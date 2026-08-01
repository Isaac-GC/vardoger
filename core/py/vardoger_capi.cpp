// vardoger_capi.cpp: a flat C ABI over the vardoger runtime, so it can be driven
// from any language with a C FFI (the Python `vardoger` package uses ctypes). One
// `VM` handle wires up the whole faithful-Android runtime (engine + memory +
// trampolines + libc/JNI stubs + scheduler + Java runtime + Android context
// graph + syscalls + ELF loader), exactly like the drivers do, and exposes it
// as load / configure / run / read-write / hook / capture primitives.
//
// Callbacks are plain C function pointers (fn, void* user); the Python side
// passes ctypes CFUNCTYPE trampolines. Everything runs on the caller's thread
// (single-threaded driving); a hook that calls back into Python re-enters with
// the GIL held, which ctypes handles.
#include <cstdint>
#include <cstring>
#include <fstream>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "vardoger/android/android_env.hpp"
#include "vardoger/android/stubs.hpp"
#include "vardoger/android/syscalls.hpp"
#include "vardoger/android/system.hpp"
#include "vardoger/art/art_bringup.hpp"
#include "vardoger/elf/elf_loader.hpp"
#include "vardoger/engine/engine.hpp"
#include "vardoger/engine/gdb_stub.hpp"
#include "vardoger/engine/memory.hpp"
#include "vardoger/engine/scheduler.hpp"
#include "vardoger/engine/trampoline.hpp"
#include "vardoger/extract/extractor.hpp"
#include "vardoger/jni/java_runtime.hpp"
#include "vardoger/jni/jni.hpp"

using namespace vardoger;

namespace {
thread_local std::string g_err;  // last error message (mv_last_error)
}

// ---- callback typedefs (must match ctypes CFUNCTYPE on the Python side)
// --------------------------
extern "C" {
typedef void (*mv_code_cb)(uint64_t pc, uint32_t size, void* user);
typedef void (*mv_write_cb)(uint64_t addr, int size, uint64_t value,
                            void* user);
typedef int (*mv_unmapped_cb)(int type, uint64_t addr,
                              void* user);  // return 1 = handled
typedef void (*mv_tramp_cb)(void* user);    // stub/capture handler
typedef int64_t (*mv_method_cb)(uint64_t self, const int64_t* args, int nargs,
                                void* user);
typedef void (*mv_dex_cb)(const uint8_t* data, uint64_t n, const char* src,
                          void* user);
typedef void (*mv_str_cb)(uint64_t addr, const char* text, const char* region,
                          void* user);
typedef void (*mv_region_cb)(uint64_t base, uint64_t size, uint32_t prot,
                             const char* label, void* user);
typedef void (*mv_native_cb)(const char* cls, const char* name, const char* sig,
                             uint64_t fn, void* user);
typedef void (*mv_prop_cb)(const char* name, const char* value, void* user);
typedef void (*mv_syscall_cb)(uint64_t nr, const char* name,
                              const uint64_t* args, uint64_t ret, void* user);
typedef void (*mv_method_obs_cb)(const char* owner, const char* name,
                                 const char* sig, const int64_t* args,
                                 int nargs, int handled, void* user);
}

// ---- the VM facade
// -------------------------------------------------------------------------------
struct VM {
  Abi abi;
  DeviceIdentity id;
  Engine e;
  Memory mem;
  uint64_t sp0 = 0;
  Trampoline tramp;
  Stubs stubs;
  Scheduler sched;
  JavaRuntime jrt;
  JniBridge jni;
  uint64_t javavm = 0;
  System sys;
  Syscalls syscalls;
  ElfLoader loader;
  std::unique_ptr<AndroidEnv> android;
  ContextGraph graph;
  std::vector<SoInfo> sos;
  std::unique_ptr<GdbStub> gdb;  // lazily created by mv_gdb_listen

  // stored Python-side callbacks (kept alive here; hooks/handlers dispatch
  // through them)
  std::function<void(uint64_t, uint32_t)> code_cb;
  std::function<bool(int, uint64_t)> unmapped_cb;
  std::vector<std::function<void(uint64_t, int, uint64_t)>> write_cbs;

  VM(Abi a, DeviceIdentity ident)
      : abi(a),
        id(std::move(ident)),
        e(a),
        mem(e),
        tramp(e, mem),
        stubs(e, mem, tramp),
        sched(e, mem),
        jrt(e, mem),
        jni(e, mem, tramp, jrt),
        sys(mem, id),
        syscalls(e, mem, sys),
        loader(e, mem) {
    sp0 = mem.setup_stack();
    mem.setup_tls();
    stubs.register_defaults();
    // __progname / getprogname: the guest process name a RASP checks against the
    // package (e.g. LIApp gates its self-decrypt on it and fails silently when it
    // mismatches). Default to the package; VARDOGER_PROGNAME / MINVM_PROGNAME
    // override for isolated loading where the real package can't be set.
    {
      std::string progname = id.package_name;
      if (const char* p = std::getenv("VARDOGER_PROGNAME"); p && *p)
        progname = p;
      else if (const char* p = std::getenv("MINVM_PROGNAME"); p && *p)
        progname = p;
      stubs.set_progname(progname);
      sys.set_progname(progname);
    }
    stubs.set_scheduler(sched);
    jrt.register_android_hierarchy();
    javavm = jni.build();
    android = std::make_unique<AndroidEnv>(jrt, id);
    graph = build_context_graph(jrt, id);
    stubs.register_system(sys);
    stubs.set_syscalls(syscalls);
    // Route packer file-writes (e.g. a decrypted DEX written to a cache path)
    // to the bytes observer, so a Python set_dex_observer / the extractor sees
    // dexes that land in the VFS, not just memory.
    sys.set_write_observer(
        [this](const std::string& path, const std::vector<uint8_t>& b) {
          jrt.notify_bytes(b, "file:" + path);
        });
    e.on_interrupt([this](Engine& en, uint32_t) {
      if (tramp.dispatch(en)) return;
      syscalls.dispatch(en);
    });
    // Import resolution, in priority order: our controlled libc/JNI stubs, then
    // a sibling library already loaded into this VM (so multi-.so targets whose
    // libs import each other link up), then a MISSING logging stub. Load
    // dependencies first — a symbol from a not-yet-loaded sibling can't resolve,
    // exactly like a real linker.
    loader.set_import_resolver([this](const std::string& n) -> uint64_t {
      if (uint64_t a = stubs.known(n)) return a;
      for (const auto& so : sos)
        if (uint64_t a = so.lookup(n)) return a;
      return stubs.resolve(n);
    });
    // dlopen()/dlsym() of a sibling lib resolves to its real exports too.
    stubs.set_lib_resolver([this](const std::string& n) -> uint64_t {
      for (const auto& so : sos)
        if (uint64_t a = so.lookup(n)) return a;
      return 0;
    });
    e.on_unmapped(
        [this](Engine& en, uc_mem_type t, uint64_t addr, int, int64_t) -> bool {
          (void)en;
          return unmapped_cb ? unmapped_cb(static_cast<int>(t), addr) : false;
        });
  }
};

// mem-write hook thunk: user = &std::function; installed via uc_hook_add
// per-hook.
static void write_thunk(uc_engine*, uc_mem_type, uint64_t addr, int size,
                        int64_t value, void* user) {
  (*reinterpret_cast<std::function<void(uint64_t, int, uint64_t)>*>(user))(
      addr, size, (uint64_t)value);
}

extern "C" {

const char* mv_last_error() { return g_err.c_str(); }

VM* mv_new(const char* abi, const char* package, int sdk) {
  try {
    DeviceIdentity id;
    if (package && *package) id.package_name = package;
    if (sdk > 0) id.sdk_int = sdk;
    const Abi a =
        (abi && std::strcmp(abi, "arm32") == 0) ? Abi::Arm32 : Abi::Arm64;
    // Build a realistic randomized /data/app install path (and lib/data dirs)
    // for this package + API level, exactly as the Android PackageManager would.
    apply_install_paths(id, a == Abi::Arm64 ? "arm64" : "arm");
    VM* vm = new VM(a, std::move(id));
    vm->sys.register_app_dirs();  // make those directories exist (access/stat)
    return vm;
  } catch (const std::exception& ex) {
    g_err = ex.what();
    return nullptr;
  }
}
void mv_free(VM* vm) { delete vm; }

// ---- load ----
int mv_load(VM* vm, const char* path) {
  try {
    SoInfo so = vm->loader.load(path);
    // Register the lib for dladdr/dl_iterate_phdr + serve its bytes at the
    // guest lib path, so a self-locating/self-decrypting packer resolves
    // correctly (matches the drivers' wiring).
    const std::string libname = [&] {
      std::string p = path;
      auto s = p.find_last_of('/');
      return s == std::string::npos ? p : p.substr(s + 1);
    }();
    const std::string lib_path = vm->id.native_lib_dir + "/" + libname;
    const uint64_t name_addr = vm->mem.mmap_alloc(
        lib_path.size() + 1, UC_PROT_READ | UC_PROT_WRITE, "soname");
    vm->e.write(name_addr, lib_path.data(), lib_path.size() + 1);
    const uint64_t phoff = vm->e.read_t<uint64_t>(so.load_bias + 32);
    const uint16_t phnum = vm->e.read_t<uint16_t>(so.load_bias + 56);
    vm->stubs.register_phdr_lib(so.load_bias, so.load_bias + phoff, phnum,
                                name_addr);
    std::ifstream f(path, std::ios::binary);
    std::string sob((std::istreambuf_iterator<char>(f)),
                    std::istreambuf_iterator<char>());
    vm->sys.add_file(lib_path, sob);
    vm->sos.push_back(std::move(so));
    return static_cast<int>(vm->sos.size() - 1);
  } catch (const std::exception& ex) {
    g_err = ex.what();
    return -1;
  }
}
// Map a real libart.so (no init) + wire dlsym/dl_iterate_phdr to it, so a
// packer that hooks or scans ART internals (Virbox: ClassLinker::DefineClass,
// DexFile::OpenMemory) resolves them.
int mv_map_art(VM* vm, const char* dir) {
  try {
    const std::string base = dir;
    auto art = std::make_shared<SoInfo>(vm->loader.load(base + "/libart.so"));
    vm->stubs.set_dlsym_provider(
        [art](const std::string& n) { return art->lookup(n); });
    std::ifstream f(base + "/libart.so", std::ios::binary);
    std::string ab((std::istreambuf_iterator<char>(f)),
                   std::istreambuf_iterator<char>());
    const std::string art_guest = "/apex/com.android.art/lib64/libart.so";
    vm->sys.add_file(art_guest, ab);
    vm->sys.add_file("/system/lib64/libart.so", ab);
    const uint64_t phoff = vm->e.read_t<uint64_t>(art->load_bias + 32);
    const uint16_t phnum = vm->e.read_t<uint16_t>(art->load_bias + 56);
    const uint64_t nm = vm->mem.mmap_alloc(
        art_guest.size() + 1, UC_PROT_READ | UC_PROT_WRITE, "artname");
    vm->e.write(nm, art_guest.data(), art_guest.size() + 1);
    vm->stubs.register_phdr_lib(art->load_bias, art->load_bias + phoff, phnum,
                                nm);
    art_init_locks(vm->e, vm->mem, art->load_bias,
                   base + "/libart.so");     // ART bring-up #1
    if (std::getenv("VARDOGER_ART_RUNTIME")) {  // ART bring-up #2/#3 (opt-in)
      art_init_runtime(vm->e, vm->mem, art->load_bias, base + "/libart.so");
      art_init_thread(vm->e, vm->mem, art->load_bias, base + "/libart.so");
    }
    return 0;
  } catch (const std::exception& ex) {
    g_err = ex.what();
    return -1;
  }
}
static SoInfo* so_at(VM* vm, int i) {
  return (i >= 0 && i < (int)vm->sos.size()) ? &vm->sos[i] : nullptr;
}
uint64_t mv_so_bias(VM* vm, int i) {
  auto* s = so_at(vm, i);
  return s ? s->load_bias : 0;
}
uint64_t mv_so_size(VM* vm, int i) {
  auto* s = so_at(vm, i);
  return s ? s->size : 0;
}
uint64_t mv_so_jni_onload(VM* vm, int i) {
  auto* s = so_at(vm, i);
  return s ? s->jni_onload : 0;
}
uint64_t mv_so_init(VM* vm, int i) {
  auto* s = so_at(vm, i);
  return s ? s->init : 0;
}
uint64_t mv_so_lookup(VM* vm, int i, const char* name) {
  auto* s = so_at(vm, i);
  return s ? s->lookup(name) : 0;
}
int mv_so_init_array(VM* vm, int i, uint64_t* out, int cap) {
  auto* s = so_at(vm, i);
  if (!s) return 0;
  const int n = std::min<int>(cap, (int)s->init_array.size());
  for (int k = 0; k < n; ++k) out[k] = s->init_array[k];
  return (int)s->init_array.size();
}

// ---- execution ----
void mv_run_init(VM* vm, int i) {
  auto* s = so_at(vm, i);
  if (s) {
    try {
      vm->loader.run_init(*s);
    } catch (const std::exception& ex) {
      g_err = ex.what();
    }
    if (vm->gdb) vm->gdb->end_run();
  }
}
// Drive a guest function through the scheduler (blocking pthreads work); sp
// reset to a clean top.
uint64_t mv_call(VM* vm, uint64_t fn, const uint64_t* args, int nargs) {
  try {
    vm->e.write_reg(Reg::Sp, vm->sp0);
    std::vector<uint64_t> a(args, args + nargs);
    // scheduler::run takes an initializer_list; marshal up to 8 args (arm64
    // x0..x7).
    uint64_t ret = 0;
    switch (nargs) {
      case 0:
        ret = vm->sched.run(fn, {});
        break;
      case 1:
        ret = vm->sched.run(fn, {a[0]});
        break;
      case 2:
        ret = vm->sched.run(fn, {a[0], a[1]});
        break;
      case 3:
        ret = vm->sched.run(fn, {a[0], a[1], a[2]});
        break;
      case 4:
        ret = vm->sched.run(fn, {a[0], a[1], a[2], a[3]});
        break;
      case 5:
        ret = vm->sched.run(fn, {a[0], a[1], a[2], a[3], a[4]});
        break;
      case 6:
        ret = vm->sched.run(fn, {a[0], a[1], a[2], a[3], a[4], a[5]});
        break;
      case 7:
        ret = vm->sched.run(fn, {a[0], a[1], a[2], a[3], a[4], a[5], a[6]});
        break;
      default:
        ret = vm->sched.run(fn,
                            {a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]});
        break;
    }
    if (vm->gdb) vm->gdb->end_run();
    return ret;
  } catch (const std::exception& ex) {
    g_err = ex.what();
    return 0;
  }
}

// ---- config / handles ----
void mv_set_property(VM* vm, const char* k, const char* v) {
  vm->sys.set_property(k, v);
}
// Set the guest process name (__progname / getprogname / /proc/self/cmdline).
// Call BEFORE loading the .so, since __progname is resolved at load time. Use
// when a RASP gates on the process name and you can't set the real package.
void mv_set_progname(VM* vm, const char* name) {
  const std::string n = name ? name : "";
  vm->stubs.set_progname(n);
  vm->sys.set_progname(n);
}
// Pin the wall-clock epoch (seconds since 1970) the guest reads via
// time()/gettimeofday/clock_gettime(CLOCK_REALTIME) — e.g. to sit inside a
// packer's license/expiry window.
void mv_set_now_unix(VM* vm, uint64_t t) { vm->sys.set_now_unix(t); }
void mv_vfs_add(VM* vm, const char* guest, const uint8_t* data, uint64_t n) {
  vm->sys.add_file(guest, std::string((const char*)data, n));
}
uint64_t mv_jni_env(VM* vm) { return vm->jni.jni_env(); }
uint64_t mv_java_vm(VM* vm) { return vm->javavm; }
uint64_t mv_app_object(VM* vm) { return vm->graph.application; }
uint64_t mv_context_object(VM* vm) { return vm->graph.context; }

// The realistic install paths generated for this package (so the caller can
// serve the APK at the right guest path and see where things live). Each copies
// up to cap-1 bytes + NUL and returns the full length.
static int copy_out(const std::string& s, char* out, int cap) {
  const int n = cap > 0 ? std::min<int>(cap - 1, (int)s.size()) : 0;
  if (cap > 0) {
    std::memcpy(out, s.data(), n);
    out[n] = 0;
  }
  return (int)s.size();
}
int mv_apk_path(VM* vm, char* out, int cap) {
  return copy_out(vm->id.apk_path, out, cap);
}
int mv_data_dir(VM* vm, char* out, int cap) {
  return copy_out(vm->id.data_dir, out, cap);
}
int mv_native_lib_dir(VM* vm, char* out, int cap) {
  return copy_out(vm->id.native_lib_dir, out, cap);
}

// ---- memory / registers ----
int mv_read(VM* vm, uint64_t addr, uint8_t* out, uint64_t n) {
  if (!vm->mem.is_mapped(addr)) return 0;
  try {
    vm->e.read(addr, out, n);
    return (int)n;
  } catch (...) {
    return 0;
  }
}
void mv_write(VM* vm, uint64_t addr, const uint8_t* data, uint64_t n) {
  try {
    vm->e.write(addr, data, n);
  } catch (...) {
  }
}
uint64_t mv_heap_alloc(VM* vm, uint64_t n) {
  return vm->mem.heap_alloc(n ? n : 8);
}
uint64_t mv_read_u64(VM* vm, uint64_t addr) {
  try {
    return vm->e.read_t<uint64_t>(addr);
  } catch (...) {
    return 0;
  }
}
void mv_write_u64(VM* vm, uint64_t addr, uint64_t v) {
  try {
    vm->e.write_t<uint64_t>(addr, v);
  } catch (...) {
  }
}
uint64_t mv_read_reg(VM* vm, int uc_reg_id) {
  return vm->e.read_uc_reg(uc_reg_id);
}
void mv_write_reg(VM* vm, int uc_reg_id, uint64_t v) {
  vm->e.write_uc_reg(uc_reg_id, v);
}
int mv_read_cstr(VM* vm, uint64_t addr, char* out, int cap) {
  std::string s = vm->e.read_cstr(addr);
  const int n = std::min<int>(cap - 1, (int)s.size());
  std::memcpy(out, s.data(), n);
  out[n] = 0;
  return (int)s.size();
}
int mv_describe(VM* vm, uint64_t addr, char* out, int cap) {
  std::string s = vm->mem.describe(addr);
  const int n = std::min<int>(cap - 1, (int)s.size());
  std::memcpy(out, s.data(), n);
  out[n] = 0;
  return (int)s.size();
}
int mv_is_mapped(VM* vm, uint64_t addr) {
  return vm->mem.is_mapped(addr) ? 1 : 0;
}
void mv_regions(VM* vm, mv_region_cb cb, void* user) {
  for (const auto& r : vm->mem.regions())
    cb(r.base, r.size, r.prot, r.label.c_str(), user);
}

// ---- hooks / trampolines ----
void mv_on_code(VM* vm, mv_code_cb cb, void* user) {
  vm->code_cb = [cb, user](uint64_t pc, uint32_t sz) { cb(pc, sz, user); };
  vm->e.on_code([vm](Engine&, uint64_t pc, uint32_t sz) {
    if (vm->code_cb) vm->code_cb(pc, sz);
  });
}
void mv_on_unmapped(VM* vm, mv_unmapped_cb cb, void* user) {
  vm->unmapped_cb = [cb, user](int t, uint64_t addr) -> bool {
    return cb(t, addr, user) != 0;
  };
}
void mv_add_mem_write_hook(VM* vm, mv_write_cb cb, void* user, uint64_t lo,
                           uint64_t hi) {
  vm->write_cbs.push_back(
      [cb, user](uint64_t a, int s, uint64_t v) { cb(a, s, v, user); });
  auto* slot = &vm->write_cbs.back();
  uc_hook h;
  uc_hook_add(vm->e.raw(), &h, UC_HOOK_MEM_WRITE,
              reinterpret_cast<void*>(&write_thunk), slot, lo,
              hi ? hi : ~uint64_t(0));
}
// Allocate a trampoline whose handler calls a Python cb, implement libc/JNI
// stubs or capture hooks entirely in Python. Inside the cb, read/modify
// regs+mem via the mv_* accessors; set the return value with mv_write_reg(uc
// x0). Returns the guest address to store/branch to.
uint64_t mv_alloc_trampoline(VM* vm, mv_tramp_cb cb, void* user,
                             const char* name) {
  return vm->tramp.alloc(name ? name : "py_stub",
                         [cb, user](Engine&) { cb(user); });
}

// ---- gdb/lldb remote debugging ----
// Open a GDB Remote Serial Protocol server on 127.0.0.1:<port> and block until
// an external debugger (lldb, gdb, Binary Ninja, IDA) attaches and issues its
// first continue/step. After this returns 1, drive JNI_OnLoad / a target
// function with mv_call (or mv_run_init) and it runs under the debugger: set
// breakpoints during the handshake, then continue. Returns 1 attached, 0 if the
// client detached during the handshake, -1 on setup error (see mv_last_error).
int mv_gdb_listen(VM* vm, int port) {
  try {
    if (!vm->gdb) vm->gdb = std::make_unique<GdbStub>(vm->e, vm->mem);
    return vm->gdb->listen(static_cast<uint16_t>(port)) ? 1 : 0;
  } catch (const std::exception& ex) {
    g_err = ex.what();
    return -1;
  }
}
int mv_gdb_attached(VM* vm) {
  return (vm->gdb && vm->gdb->attached()) ? 1 : 0;
}
void mv_gdb_detach(VM* vm) {
  if (vm->gdb) vm->gdb->detach();
}

// ---- Java helpers ----
uint64_t mv_new_string(VM* vm, const char* s) {
  return vm->jrt.new_string_utf(s);
}
uint64_t mv_new_byte_array(VM* vm, const uint8_t* data, int n) {
  return vm->jrt.new_byte_array(std::vector<uint8_t>(data, data + n));
}
uint64_t mv_find_class(VM* vm, const char* name) {
  try {
    return vm->jrt.find_class(name);
  } catch (...) {
    return 0;
  }
}
int mv_string_of(VM* vm, uint64_t handle, char* out, int cap) {
  const std::string* s = vm->jrt.string_of(handle);
  if (!s) {
    if (cap) out[0] = 0;
    return -1;
  }
  const int n = std::min<int>(cap - 1, (int)s->size());
  std::memcpy(out, s->data(), n);
  out[n] = 0;
  return (int)s->size();
}
void mv_register_method(VM* vm, const char* name, mv_method_cb cb,
                        int returns_object, void* user) {
  const bool ro = returns_object != 0;
  vm->jrt.register_method(name, [cb, user, ro](JavaRuntime&, uint64_t self,
                                               const std::vector<DvmValue>& a) {
    std::vector<int64_t> args;
    args.reserve(a.size());
    for (const auto& v : a)
      args.push_back(v.kind == DvmValue::Object ? (int64_t)v.obj : v.i);
    const int64_t r = cb(self, args.data(), (int)args.size(), user);
    return ro ? DvmValue::O((uint64_t)r) : DvmValue::I(r);
  });
}

// ---- Java object/field/array primitives (so host methods can be implemented
// in Python) ----
uint64_t mv_new_object(VM* vm, const char* cls) {
  try {
    return vm->jrt.new_object(cls);
  } catch (...) {
    return 0;
  }
}
void mv_set_field_obj(VM* vm, uint64_t obj, const char* name, uint64_t val) {
  vm->jrt.set_field(obj, name, DvmValue::O(val));
}
void mv_set_field_int(VM* vm, uint64_t obj, const char* name, int64_t val) {
  vm->jrt.set_field(obj, name, DvmValue::I(val));
}
// Returns the field value; *out_kind = 0 Void, 1 Int, 3 Object.
int64_t mv_get_field(VM* vm, uint64_t obj, const char* name, int* out_kind) {
  DvmValue v = vm->jrt.get_field(obj, name);
  if (out_kind) *out_kind = static_cast<int>(v.kind);
  return v.kind == DvmValue::Object ? (int64_t)v.obj : v.i;
}
int mv_array_length(VM* vm, uint64_t arr) {
  return (int)vm->jrt.array_length(arr);
}
// Copy a byte[]'s bytes out; returns the array length (may exceed cap).
int mv_array_read(VM* vm, uint64_t arr, uint8_t* out, int cap) {
  std::vector<uint8_t>* b = vm->jrt.bytes_ptr(arr);
  if (!b) return -1;
  const int n = std::min<int>(cap, (int)b->size());
  std::memcpy(out, b->data(), n);
  return (int)b->size();
}
// Write bytes into a byte[] at offset (grows it if needed).
void mv_array_write(VM* vm, uint64_t arr, int off, const uint8_t* data, int n) {
  std::vector<uint8_t>* b = vm->jrt.bytes_ptr(arr);
  if (!b) return;
  if ((size_t)(off + n) > b->size()) b->resize(off + n);
  std::memcpy(b->data() + off, data, n);
}
uint64_t mv_object_array_element(VM* vm, uint64_t arr, int i) {
  return vm->jrt.object_array_element(arr, i);
}

// ---- capture ----
void mv_scan_dex(VM* vm, mv_dex_cb cb, void* user) {
  Extractor ex(vm->e, vm->mem);
  for (const auto& d : ex.scan_dex())
    cb(d.bytes.data(), d.bytes.size(), "memscan", user);
}
// Search guest memory for printable strings, keeping each match's address +
// region. `needle` filters to runs containing it (empty = every run); `min_len`
// is the shortest run to report (<=0 -> 4). Fires cb(addr, text, region) per hit.
void mv_search_strings(VM* vm, const char* needle, int min_len, mv_str_cb cb,
                       void* user) {
  Extractor ex(vm->e, vm->mem);
  const size_t ml = min_len > 0 ? static_cast<size_t>(min_len) : 4;
  for (const auto& s : ex.search_strings(needle ? needle : "", ml))
    cb(s.addr, s.text.c_str(), s.region.c_str(), user);
}
void mv_set_dex_observer(VM* vm, mv_dex_cb cb, void* user) {
  vm->jrt.set_bytes_observer(
      [cb, user](const std::vector<uint8_t>& b, const std::string& src) {
        cb(b.data(), b.size(), src.c_str(), user);
      });
}
void mv_registered_natives(VM* vm, mv_native_cb cb, void* user) {
  for (const auto& n : vm->jrt.registered())
    cb(n.cls.c_str(), n.name.c_str(), n.sig.c_str(), n.fn, user);
}

// ---- monitoring: build properties + syscalls ----
// Fire cb(name, value) on every system/build property read (ro.build.*,
// ro.debuggable, ...) the guest performs. Shows exactly which device
// fingerprints a packer probes.
void mv_set_property_observer(VM* vm, mv_prop_cb cb, void* user) {
  vm->sys.set_property_observer(
      [cb, user](const std::string& name, const std::string& value) {
        cb(name.c_str(), value.c_str(), user);
      });
}
// Fire cb(nr, name, args[6], ret) on every raw syscall (SVC) the guest issues.
// `args` points to 6 uint64 (x0..x5); `name` is a short mnemonic. Traces the
// packer's direct-syscall activity (ptrace/getrandom/mprotect/openat/...).
void mv_set_syscall_observer(VM* vm, mv_syscall_cb cb, void* user) {
  vm->syscalls.set_syscall_observer(
      [cb, user](uint64_t nr, const char* name, const uint64_t args[6],
                 uint64_t ret) { cb(nr, name, args, ret, user); });
}
// Fire cb(owner, name, sig, args[nargs], handled) on EVERY Java method the guest
// calls through JNI. `handled`=1 if a host impl ran (else the call returned void
// and was logged). Each arg is an int64 (object handle for objects, else the raw
// value). Shows the full native<->Java surface without pre-registering names.
void mv_set_method_observer(VM* vm, mv_method_obs_cb cb, void* user) {
  vm->jrt.set_method_observer(
      [cb, user](const std::string& owner, const std::string& name,
                 const std::string& sig, const std::vector<DvmValue>& a,
                 bool handled) {
        std::vector<int64_t> args;
        args.reserve(a.size());
        for (const auto& v : a)
          args.push_back(v.kind == DvmValue::Object ? (int64_t)v.obj : v.i);
        cb(owner.c_str(), name.c_str(), sig.c_str(), args.data(),
           (int)args.size(), handled ? 1 : 0, user);
      });
}

}  // extern "C"
