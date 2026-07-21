#include "vardoger/jni/jni.hpp"

#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>

#include "vardoger/engine/address_space.hpp"
#include "vardoger/engine/args.hpp"
#include "vardoger/jni/jni_slots.inc"

namespace vardoger {

namespace {
constexpr uint64_t kJniVersion16 = 0x00010006;  // JNI_VERSION_1_6
constexpr size_t kEnvFnCount = sizeof(kJniEnvSlots) / sizeof(*kJniEnvSlots);
constexpr size_t kVmFnCount = sizeof(kJavaVmSlots) / sizeof(*kJavaVmSlots);

int env_index(const std::string& name) {
  for (size_t i = 0; i < kEnvFnCount; ++i)
    if (name == kJniEnvSlots[i]) return kJniEnvReserved + static_cast<int>(i);
  throw std::runtime_error("JNI: unknown JNIEnv slot '" + name + "'");
}
int vm_index(const std::string& name) {
  for (size_t i = 0; i < kVmFnCount; ++i)
    if (name == kJavaVmSlots[i]) return kJavaVmReserved + static_cast<int>(i);
  throw std::runtime_error("JNI: unknown JavaVM slot '" + name + "'");
}

// Parse a method signature's argument list into per-arg "is this an object?".
// NOTE: each arg is read as one machine word; 64-bit J/D args on arm32 (which
// span a register pair) aren't split yet, fine for the Context methods.
std::vector<bool> parse_arg_objects(const std::string& sig) {
  std::vector<bool> out;
  size_t i = sig.find('(');
  if (i == std::string::npos) return out;
  for (++i; i < sig.size() && sig[i] != ')';) {
    if (sig[i] == '[') {  // array -> object
      while (i < sig.size() && sig[i] == '[') ++i;
      if (i < sig.size() && sig[i] == 'L') {
        while (i < sig.size() && sig[i] != ';') ++i;
        if (i < sig.size()) ++i;
      } else if (i < sig.size())
        ++i;
      out.push_back(true);
    } else if (sig[i] == 'L') {  // object
      while (i < sig.size() && sig[i] != ';') ++i;
      if (i < sig.size()) ++i;
      out.push_back(true);
    } else {  // primitive (Z B C S I J F D)
      ++i;
      out.push_back(false);
    }
  }
  return out;
}
}  // namespace

JniBridge::JniBridge(Engine& engine, Memory& mem, Trampoline& tramp,
                     JavaRuntime& jrt)
    : e_(engine), mem_(mem), tramp_(tramp), jrt_(jrt) {}

void JniBridge::write_ptr(uint64_t addr, uint64_t val) {
  if (e_.pointer_size() == 8)
    e_.write_t<uint64_t>(addr, val);
  else
    e_.write_t<uint32_t>(addr, static_cast<uint32_t>(val));
}
uint64_t JniBridge::read_ptr(uint64_t addr) const {
  return e_.pointer_size() == 8 ? e_.read_t<uint64_t>(addr)
                                : e_.read_t<uint32_t>(addr);
}

uint64_t JniBridge::build() {
  build_env();
  build_vm();
  return vm_;
}

void JniBridge::build_env() {
  const int psz = e_.pointer_size();
  const size_t nslots = static_cast<size_t>(kJniEnvReserved) + kEnvFnCount;
  env_table_ = mem_.java_alloc(nslots * psz);

  for (size_t i = 0; i < nslots; ++i) {
    const std::string nm = (i < static_cast<size_t>(kJniEnvReserved))
                               ? ("reserved" + std::to_string(i))
                               : std::string(kJniEnvSlots[i - kJniEnvReserved]);
    const uint64_t stub = tramp_.alloc("JNIEnv::" + nm, [nm, i](Engine& e) {
      static const bool quiet =
          std::getenv("VARDOGER_NO_JNI_LOG") != nullptr;  // silence spam in scans
      if (!quiet)
        std::fprintf(stderr, "[jni] unimplemented JNIEnv slot %zu (%s)\n", i,
                     nm.c_str());
      e.write_reg(Reg::Ret0, 0);
    });
    write_ptr(env_table_ + i * psz, stub);
  }
  env_ = mem_.java_alloc(psz);
  write_ptr(env_, env_table_);  // JNIEnv* -> *env == function table
  install_env_handlers();
}

void JniBridge::build_vm() {
  const int psz = e_.pointer_size();
  const size_t nslots =
      static_cast<size_t>(kJavaVmReserved) + kVmFnCount;  // 3 reserved + 5
  vm_table_ = mem_.java_alloc(nslots * psz);

  for (size_t i = 0; i < nslots; ++i) {
    const std::string nm = (i < static_cast<size_t>(kJavaVmReserved))
                               ? ("reserved" + std::to_string(i))
                               : std::string(kJavaVmSlots[i - kJavaVmReserved]);
    const uint64_t stub = tramp_.alloc("JavaVM::" + nm, [nm, i](Engine& e) {
      std::fprintf(stderr, "[jni] unimplemented JavaVM slot %zu (%s)\n", i,
                   nm.c_str());
      e.write_reg(Reg::Ret0, 0);
    });
    write_ptr(vm_table_ + i * psz, stub);
  }
  vm_ = mem_.java_alloc(psz);
  write_ptr(vm_, vm_table_);
  install_vm_handlers();
}

void JniBridge::set_env(const char* name, Trampoline::Handler h) {
  const uint64_t stub =
      tramp_.alloc(std::string("JNIEnv::") + name, std::move(h));
  write_ptr(
      env_table_ + static_cast<uint64_t>(env_index(name)) * e_.pointer_size(),
      stub);
}
void JniBridge::set_vm(const char* name, Trampoline::Handler h) {
  const uint64_t stub =
      tramp_.alloc(std::string("JavaVM::") + name, std::move(h));
  write_ptr(
      vm_table_ + static_cast<uint64_t>(vm_index(name)) * e_.pointer_size(),
      stub);
}

void JniBridge::call_dispatch(Engine& e, bool is_static, char ret_kind) {
  Args a(e);
  a.next_int();                        // env
  const uint64_t recv = a.next_int();  // jobject (instance) or jclass (static)
  const uint64_t mid = a.next_int();   // jmethodID
  const std::vector<bool> obj_arg = parse_arg_objects(jrt_.method_sig(mid));

  std::vector<DvmValue> args;
  args.reserve(obj_arg.size());
  for (bool is_obj : obj_arg) {
    const uint64_t v = a.next_int();
    args.push_back(is_obj ? DvmValue::O(v)
                          : DvmValue::I(static_cast<int64_t>(v)));
  }
  const DvmValue r = jrt_.call_method(mid, is_static ? 0 : recv, args);
  if (std::getenv("VARDOGER_JNI_LOG")) {
    std::string sa;
    for (const auto& a : args)
      if (a.kind == DvmValue::Object && a.obj)
        if (const std::string* s = jrt_.string_of(a.obj))
          sa += " \"" + *s + "\"";
    std::fprintf(stderr, "[jni] Call%s %s%s%s -> %lld/obj%#llx\n",
                 is_static ? "Static" : "", jrt_.method_name(mid).c_str(),
                 jrt_.method_sig(mid).c_str(), sa.c_str(), (long long)r.i,
                 (unsigned long long)r.obj);
  }
  switch (ret_kind) {
    case 'L':
      e.write_reg(Reg::Ret0, r.obj);
      break;
    case 'I':
      e.write_reg(Reg::Ret0, static_cast<uint64_t>(r.i));
      break;
    case 'V':
      break;
  }
}

namespace {
// AArch64 va_list (AAPCS64): {void* __stack; void* __gr_top; void* __vr_top;
// int __gr_offs; int __vr_offs;}. Integer/pointer args come from x0..x7 (the GP
// save area) then the stack. Floats (vr) aren't needed for the Context methods.
struct VaList {
  uint64_t stack, gr_top, vr_top;
  int32_t gr_offs, vr_offs;
};

uint64_t valist_next_int(Engine& e, VaList& v) {
  if (e.abi() == Abi::Arm32) {  // arm32 va_list is just a char* cursor
    const uint64_t val = e.read_t<uint32_t>(v.stack);
    v.stack += 4;
    return val;
  }
  if (v.gr_offs < 0) {  // still GP registers left
    const uint64_t val = e.read_t<uint64_t>(v.gr_top + v.gr_offs);
    v.gr_offs += 8;
    return val;
  }
  const uint64_t val = e.read_t<uint64_t>(v.stack);  // spilled to the stack
  v.stack += 8;
  return val;
}
}  // namespace

void JniBridge::call_dispatch_v(Engine& e, bool is_static, char ret_kind) {
  Args a(e);
  a.next_int();  // env
  const uint64_t recv = a.next_int();
  const uint64_t mid = a.next_int();
  const uint64_t vap =
      a.next_int();  // va_list (ptr to struct on arm64; the cursor on arm32)

  VaList v{};
  if (e.abi() == Abi::Arm32) {
    v.stack = vap;
  } else {
    v.stack = e.read_t<uint64_t>(vap + 0);
    v.gr_top = e.read_t<uint64_t>(vap + 8);
    v.vr_top = e.read_t<uint64_t>(vap + 16);
    v.gr_offs = e.read_t<int32_t>(vap + 24);
    v.vr_offs = e.read_t<int32_t>(vap + 28);
  }

  std::vector<DvmValue> args;
  for (bool is_obj : parse_arg_objects(jrt_.method_sig(mid))) {
    const uint64_t val = valist_next_int(e, v);
    args.push_back(is_obj ? DvmValue::O(val)
                          : DvmValue::I(static_cast<int64_t>(val)));
  }
  const DvmValue r = jrt_.call_method(mid, is_static ? 0 : recv, args);
  if (std::getenv("VARDOGER_JNI_LOG")) {
    std::string sa;
    for (const auto& a : args)
      if (a.kind == DvmValue::Object && a.obj)
        if (const std::string* s = jrt_.string_of(a.obj))
          sa += " \"" + *s + "\"";
    std::fprintf(stderr, "[jni] Call%s %s%s%s -> %lld/obj%#llx\n",
                 is_static ? "Static" : "", jrt_.method_name(mid).c_str(),
                 jrt_.method_sig(mid).c_str(), sa.c_str(), (long long)r.i,
                 (unsigned long long)r.obj);
  }
  switch (ret_kind) {
    case 'L':
      e.write_reg(Reg::Ret0, r.obj);
      break;
    case 'I':
      e.write_reg(Reg::Ret0, static_cast<uint64_t>(r.i));
      break;
    case 'V':
      break;
  }
}

void JniBridge::install_env_handlers() {
  set_env("GetVersion", [](Engine& e) {
    Args a(e);
    a.next_int();  // env
    e.write_reg(Reg::Ret0, kJniVersion16);
  });
  set_env("GetJavaVM", [this](Engine& e) {  // (env, JavaVM** out)
    Args a(e);
    a.next_int();                  // env
    write_ptr(a.next_int(), vm_);  // *out = JavaVM*
    e.write_reg(Reg::Ret0, 0);     // JNI_OK
  });
  set_env("FindClass", [this](Engine& e) {
    Args a(e);
    a.next_int();  // env
    const std::string name = e.read_cstr(a.next_int());
    if (std::getenv("VARDOGER_JNI_LOG"))
      std::fprintf(stderr, "[jni] FindClass %s\n", name.c_str());
    // Anti-tamper evasion: packers FindClass() a tampering/instrumentation
    // tool's class and bail (exit) if it's PRESENT. We auto-create any class,
    // so these would false-positive. Return null (ClassNotFound) for known
    // hooking/repack tools so the packer sees a clean env.
    static const char* kTamperClasses[] = {
        "apksignaturekiller",
        "xposed",
        "/substrate",
        "saurik",
        "frida",
        "lsposed",
        "edxposed",
        "taichi",
        "VirtualApp",
        "sandhook",
        "SandHook",
        "/whale",
        "dexposed",
        "io/va/",
        "andhook",
        "AndHook",
        "/epic",
        "/hooka",
        "Cydia",
        "Xposed",
        "/windy/",
        "FuckSign",
        "np/manager",
        "hookzz",
        "/magisk",
        "Magisk",
        "zygisk",
        // FART/ZjDroid/MikRom-family DEX-dumping frameworks, packers
        // FindClass() these and self-destruct if present. Our auto-create would
        // false-positive them (Ijiami's OLLVM self_destruct probes
        // youlor/Unpacker, cn/mik/Fartext, mikrom, ...).
        "youlor",
        "Unpacker",
        "fupk",
        "FUPK",
        "ZjDroid",
        "zjdroid",
        "fart",
        "Fart",
        "/dumpDex",
        "cn/mik",
        "Fartext",
        "mikrom",
        "MikRom",
        "/mik/",
    };
    if (!std::getenv("VARDOGER_NO_TAMPER_EVASION"))
      for (const char* bad : kTamperClasses)
        if (name.find(bad) != std::string::npos) {
          if (std::getenv("VARDOGER_JNI_LOG"))
            std::fprintf(stderr, "[jni]   -> null (tamper-class evasion)\n");
          e.write_reg(Reg::Ret0, 0);
          return;
        }
    e.write_reg(Reg::Ret0, jrt_.find_class(name));
  });
  // DefineClass(env, name, loader, buf, bufLen) -> jclass. Packers (Jiagu
  // QHClassLoader, etc.) decrypt a class/DEX and hand the plaintext bytes here
  //, CAPTURE them (this is the deferred- decrypt capture point). Then return a
  // fresh class handle so the guest continues.
  set_env("DefineClass", [this](Engine& e) {
    Args a(e);
    a.next_int();  // env
    const uint64_t namep = a.next_int();
    a.next_int();  // name, loader
    const uint64_t buf = a.next_int();
    const int64_t len = static_cast<int64_t>(a.next_int());
    std::string name = namep ? e.read_cstr(namep) : std::string("?");
    if (buf && len > 0 && len < (64 << 20)) {
      std::vector<uint8_t> bytes(static_cast<size_t>(len));
      e.read(buf, bytes.data(), bytes.size());
      std::fprintf(
          stderr, "[jni] DefineClass \"%s\" %lld bytes%s\n", name.c_str(),
          (long long)len,
          (bytes.size() >= 4 && std::memcmp(bytes.data(), "dex\n", 4) == 0)
              ? "  <-- DEX!"
              : "");
      jrt_.notify_bytes(bytes, "DefineClass:" + name);
    } else if (std::getenv("VARDOGER_JNI_LOG")) {
      std::fprintf(stderr, "[jni] DefineClass \"%s\" (buf=%#llx len=%lld)\n",
                   name.c_str(), (unsigned long long)buf, (long long)len);
    }
    e.write_reg(Reg::Ret0, jrt_.find_class(name.empty() ? "$defined" : name));
  });
  set_env("GetMethodID", [this](Engine& e) {
    Args a(e);
    a.next_int();
    const uint64_t cls = a.next_int();
    const std::string name = e.read_cstr(a.next_int());
    const std::string sig = e.read_cstr(a.next_int());
    e.write_reg(Reg::Ret0, jrt_.get_method_id(cls, name, sig, false));
  });
  set_env("GetStaticMethodID", [this](Engine& e) {
    Args a(e);
    a.next_int();
    const uint64_t cls = a.next_int();
    const std::string name = e.read_cstr(a.next_int());
    const std::string sig = e.read_cstr(a.next_int());
    e.write_reg(Reg::Ret0, jrt_.get_method_id(cls, name, sig, true));
  });
  set_env("GetFieldID", [this](Engine& e) {
    Args a(e);
    a.next_int();
    const uint64_t cls = a.next_int();
    const std::string name = e.read_cstr(a.next_int());
    const std::string sig = e.read_cstr(a.next_int());
    if (std::getenv("VARDOGER_JNI_LOG"))
      std::fprintf(stderr, "[jni] GetFieldID %s.%s:%s\n",
                   jrt_.class_name(cls).c_str(), name.c_str(), sig.c_str());
    e.write_reg(Reg::Ret0, jrt_.get_field_id(cls, name, sig, false));
  });
  set_env("GetStaticFieldID", [this](Engine& e) {
    Args a(e);
    a.next_int();
    const uint64_t cls = a.next_int();
    const std::string name = e.read_cstr(a.next_int());
    const std::string sig = e.read_cstr(a.next_int());
    e.write_reg(Reg::Ret0, jrt_.get_field_id(cls, name, sig, true));
  });
  set_env("RegisterNatives", [this](Engine& e) {
    Args a(e);
    a.next_int();
    const uint64_t cls = a.next_int();
    const uint64_t arr = a.next_int();
    const uint64_t n = a.next_int();
    const int psz = e.pointer_size();
    for (uint64_t i = 0; i < n; ++i) {
      const uint64_t rec = arr + i * 3 * psz;  // {name*, sig*, fnPtr}
      const std::string name = e.read_cstr(read_ptr(rec));
      const std::string sig = e.read_cstr(read_ptr(rec + psz));
      const uint64_t fn = read_ptr(rec + 2 * psz);
      jrt_.register_native(cls, name, sig, fn);
      // Per-method RegisterNatives spam floods the log during materialize
      // (interface11 registers hundreds of methods). Only print it under
      // VARDOGER_VERBOSE. (getenv cached, fires per method.)
      static const bool verbose = std::getenv("VARDOGER_VERBOSE") != nullptr;
      if (verbose)
        std::fprintf(stderr, "[jni] RegisterNatives: %s.%s%s -> 0x%llx\n",
                     jrt_.class_name(cls).c_str(), name.c_str(), sig.c_str(),
                     static_cast<unsigned long long>(fn));
    }
    e.write_reg(Reg::Ret0, 0);  // JNI_OK
  });
  set_env("NewStringUTF", [this](Engine& e) {
    Args a(e);
    a.next_int();
    const uint64_t p = a.next_int();
    const std::string s = p ? e.read_cstr(p) : std::string{};
    e.write_reg(Reg::Ret0, jrt_.new_string_utf(s));
  });
  set_env("GetStringUTFChars", [this](Engine& e) {
    Args a(e);
    a.next_int();
    const uint64_t js = a.next_int();
    const uint64_t isCopy = a.next_int();
    const std::string* s = jrt_.string_of(js);
    const std::string v = s ? *s : std::string{};
    if (std::getenv("VARDOGER_STRLOG"))
      std::fprintf(
          stderr,
          "[strlog] GetStringUTFChars(js=%#llx) -> \"%s\" (len=%zu%s)\n",
          (unsigned long long)js, v.c_str(), v.size(), s ? "" : ", NON-STRING");
    const uint64_t buf = mem_.heap_alloc(v.size() + 1);
    if (!v.empty()) e.write(buf, v.data(), v.size());
    const uint8_t nul = 0;
    e.write(buf + v.size(), &nul, 1);
    if (isCopy) {
      const uint8_t one = 1;
      e.write(isCopy, &one, 1);
    }  // jboolean JNI_TRUE
    e.write_reg(Reg::Ret0, buf);
  });
  set_env("ReleaseStringUTFChars", [](Engine&) { /* bump heap: no-op */ });
  set_env("GetStringUTFLength", [this](Engine& e) {
    Args a(e);
    a.next_int();
    const std::string* s = jrt_.string_of(a.next_int());
    e.write_reg(Reg::Ret0, s ? s->size() : 0);
  });
  set_env("PushLocalFrame",
          [](Engine& e) { e.write_reg(Reg::Ret0, 0); });  // JNI_OK
  set_env("PopLocalFrame", [](Engine& e) {
    Args a(e);
    a.next_int();
    e.write_reg(Reg::Ret0, a.next_int());
  });  // pass result back
  set_env("ExceptionCheck", [this](Engine& e) {
    e.write_reg(Reg::Ret0, jrt_.pending_exception() ? 1 : 0);
  });
  set_env("ExceptionOccurred", [this](Engine& e) {
    e.write_reg(Reg::Ret0, jrt_.pending_exception());
  });
  set_env("ExceptionClear",
          [this](Engine&) { jrt_.clear_pending_exception(); });
  set_env("NewGlobalRef", [](Engine& e) {
    Args a(e);
    a.next_int();
    e.write_reg(Reg::Ret0, a.next_int());
  });
  set_env("NewLocalRef", [](Engine& e) {
    Args a(e);
    a.next_int();
    e.write_reg(Reg::Ret0, a.next_int());
  });
  set_env("DeleteGlobalRef", [](Engine&) {});
  set_env("DeleteLocalRef", [](Engine&) {});
  set_env("IsSameObject", [](Engine& e) {
    Args a(e);
    a.next_int();
    const uint64_t x = a.next_int(), y = a.next_int();
    e.write_reg(Reg::Ret0, x == y ? 1 : 0);
  });
  set_env("GetObjectClass", [this](Engine& e) {
    Args a(e);
    a.next_int();  // env
    const uint64_t obj = a.next_int();
    const uint64_t cls = jrt_.class_of(obj);
    e.write_reg(Reg::Ret0, cls ? cls : jrt_.find_class("java/lang/Object"));
  });
  set_env("IsInstanceOf", [this](Engine& e) {  // (env, obj, clazz) -> jboolean
    Args a(e);
    a.next_int();
    const uint64_t obj = a.next_int(), clazz = a.next_int();
    // JNI spec: null obj -> TRUE. vardoger has a FLAT class model (no
    // super/interface hierarchy), so we can only affirm an EXACT class match
    // (by identity or name); a cross-class relationship (e.g. StubApp is-a
    // ContextWrapper) is NOT provable here -> FALSE. Being permissive here
    // (assuming true) flips packer branches that gate on the negative and
    // breaks unpacking.
    bool result = (obj == 0);
    if (obj) {
      const uint64_t oc = jrt_.class_of(obj);
      result =
          (oc && (oc == clazz || jrt_.is_subclass(jrt_.class_name(oc),
                                                  jrt_.class_name(clazz))));
    }
    if (std::getenv("VARDOGER_JNI_LOG"))
      std::fprintf(stderr, "[jni] IsInstanceOf obj%#llx<%s> vs <%s> -> %d\n",
                   (unsigned long long)obj,
                   obj ? jrt_.class_name(jrt_.class_of(obj)).c_str() : "null",
                   jrt_.class_name(clazz).c_str(), result ? 1 : 0);
    e.write_reg(Reg::Ret0, result ? 1 : 0);
  });
  set_env("IsAssignableFrom",
          [this](Engine& e) {  // (env, clazz1, clazz2) -> clazz1 is-a clazz2
            Args a(e);
            a.next_int();
            const uint64_t c1 = a.next_int(), c2 = a.next_int();
            const bool result =
                c1 == c2 ||
                jrt_.is_subclass(jrt_.class_name(c1), jrt_.class_name(c2));
            if (std::getenv("VARDOGER_JNI_LOG"))
              std::fprintf(stderr, "[jni] IsAssignableFrom <%s> <%s> -> %d\n",
                           jrt_.class_name(c1).c_str(),
                           jrt_.class_name(c2).c_str(), result ? 1 : 0);
            e.write_reg(Reg::Ret0, result ? 1 : 0);
          });
  set_env("GetSuperclass",
          [this](Engine& e) {  // (env, clazz) -> jclass super (or null)
            Args a(e);
            a.next_int();
            const uint64_t clazz = a.next_int();
            const std::string sup = jrt_.superclass_of(jrt_.class_name(clazz));
            const uint64_t r = sup.empty() ? 0 : jrt_.find_class(sup);
            if (std::getenv("VARDOGER_JNI_LOG"))
              std::fprintf(stderr, "[jni] GetSuperclass <%s> -> %s\n",
                           jrt_.class_name(clazz).c_str(),
                           sup.empty() ? "null" : sup.c_str());
            e.write_reg(Reg::Ret0, r);
          });

  // --- ART in-memory class-load handshake (DEX-via-ByteBuffer). The packer
  // wraps decrypted DEX chunks in direct ByteBuffers and feeds them to
  // InMemoryDexClassLoader. Model the buffer as a DirectByteBuffer object
  // remembering (address, capacity) so the class-load driver can find each DEX
  // region. (Investigation: logs what dla points at.)
  set_env("NewDirectByteBuffer", [this](Engine& e) {
    Args a(e);
    a.next_int();                        // env
    const uint64_t addr = a.next_int();  // void* address
    const uint64_t cap = a.next_int();   // jlong capacity
    uint8_t magic[16] = {0};
    if (cap >= 16 && mem_.is_mapped(addr)) e.read(addr, magic, 16);
    const bool is_dex = magic[0] == 'd' && magic[1] == 'e' && magic[2] == 'x' &&
                        magic[3] == '\n';
    std::fprintf(stderr,
                 "[jni] NewDirectByteBuffer addr=%#llx cap=%#llx (%s) "
                 "magic=%02x%02x%02x%02x %s\n",
                 (unsigned long long)addr, (unsigned long long)cap,
                 mem_.describe(addr).c_str(), magic[0], magic[1], magic[2],
                 magic[3], is_dex ? "<-- DEX!" : "");
    if (is_dex && cap &&
        mem_.is_mapped(addr)) {  // capture the decrypted DEX as ART receives it
      std::vector<uint8_t> v(cap);
      e.read(addr, v.data(), cap);
      jrt_.notify_bytes(v, "DirectByteBuffer");  // extractor sink
      if (std::getenv("VARDOGER_DUMP_BB")) {
        static int n = 0;
        char path[128];
        std::snprintf(path, sizeof(path), "/tmp/ducex_dex_%d.dex", n++);
        if (FILE* f = std::fopen(path, "wb")) {
          std::fwrite(v.data(), 1, v.size(), f);
          std::fclose(f);
          std::fprintf(stderr,
                       "       -> captured decrypted DEX %s (%llu bytes)\n",
                       path, (unsigned long long)cap);
        }
      }
    }
    const uint64_t bb = jrt_.new_object("java/nio/DirectByteBuffer");
    jrt_.set_field(bb, "address", DvmValue::I(static_cast<int64_t>(addr)));
    jrt_.set_field(bb, "capacity", DvmValue::I(static_cast<int64_t>(cap)));
    e.write_reg(Reg::Ret0, bb);
  });
  set_env("GetDirectBufferAddress", [this](Engine& e) {
    Args a(e);
    a.next_int();
    const uint64_t bb = a.next_int();
    e.write_reg(Reg::Ret0,
                static_cast<uint64_t>(jrt_.get_field(bb, "address").i));
  });
  set_env("GetDirectBufferCapacity", [this](Engine& e) {
    Args a(e);
    a.next_int();
    const uint64_t bb = a.next_int();
    e.write_reg(Reg::Ret0,
                static_cast<uint64_t>(jrt_.get_field(bb, "capacity").i));
  });
  set_env(
      "NewObjectV", [this](Engine& e) {  // (env, jclass, jmethodID, va_list)
        Args a(e);
        a.next_int();
        const uint64_t cls = a.next_int();
        const std::string name = jrt_.class_name(cls);
        std::fprintf(stderr, "[jni] NewObjectV class=%s\n", name.c_str());
        e.write_reg(Reg::Ret0,
                    jrt_.new_object(name.empty() ? "java/lang/Object" : name));
      });

  // --- M4: method calls (varargs form) routed to host impls ---
  set_env("CallObjectMethod",
          [this](Engine& e) { call_dispatch(e, false, 'L'); });
  set_env("CallIntMethod", [this](Engine& e) { call_dispatch(e, false, 'I'); });
  set_env("CallBooleanMethod",
          [this](Engine& e) { call_dispatch(e, false, 'I'); });
  set_env("CallVoidMethod",
          [this](Engine& e) { call_dispatch(e, false, 'V'); });
  set_env("CallStaticObjectMethod",
          [this](Engine& e) { call_dispatch(e, true, 'L'); });
  set_env("CallStaticIntMethod",
          [this](Engine& e) { call_dispatch(e, true, 'I'); });
  set_env("CallStaticBooleanMethod",
          [this](Engine& e) { call_dispatch(e, true, 'I'); });

  // va_list variants, C++ JNI inline wrappers (env->CallX(..)) route here.
  set_env("CallObjectMethodV",
          [this](Engine& e) { call_dispatch_v(e, false, 'L'); });
  set_env("CallIntMethodV",
          [this](Engine& e) { call_dispatch_v(e, false, 'I'); });
  set_env("CallBooleanMethodV",
          [this](Engine& e) { call_dispatch_v(e, false, 'I'); });
  set_env("CallVoidMethodV",
          [this](Engine& e) { call_dispatch_v(e, false, 'V'); });
  set_env("CallStaticObjectMethodV",
          [this](Engine& e) { call_dispatch_v(e, true, 'L'); });
  set_env("CallStaticIntMethodV",
          [this](Engine& e) { call_dispatch_v(e, true, 'I'); });
  set_env("CallStaticBooleanMethodV",
          [this](Engine& e) { call_dispatch_v(e, true, 'I'); });
  set_env("CallStaticVoidMethodV",
          [this](Engine& e) { call_dispatch_v(e, true, 'V'); });

  // Long/char/short/byte returns are all a single 64-bit value in Ret0 -> reuse
  // the 'I' path.
  set_env("CallLongMethod",
          [this](Engine& e) { call_dispatch(e, false, 'I'); });
  set_env("CallLongMethodV",
          [this](Engine& e) { call_dispatch_v(e, false, 'I'); });
  set_env("CallStaticLongMethod",
          [this](Engine& e) { call_dispatch(e, true, 'I'); });
  set_env("CallStaticLongMethodV",
          [this](Engine& e) { call_dispatch_v(e, true, 'I'); });
  // CallNonvirtual*MethodV: (env, obj, jclass, methodID, va_list), one extra
  // jclass arg vs the virtual form. Drop the class and dispatch on the real
  // methodID.
  auto nonvirtual_v = [this](Engine& e, char rk) {
    Args a(e);
    a.next_int();  // env
    const uint64_t recv = a.next_int();
    a.next_int();  // jclass (ignored)
    const uint64_t mid = a.next_int(), vap = a.next_int();
    VaList v{};
    if (e_.abi() == Abi::Arm32)
      v.stack = vap;
    else {
      v.stack = e.read_t<uint64_t>(vap + 0);
      v.gr_top = e.read_t<uint64_t>(vap + 8);
      v.vr_top = e.read_t<uint64_t>(vap + 16);
      v.gr_offs = e.read_t<int32_t>(vap + 24);
      v.vr_offs = e.read_t<int32_t>(vap + 28);
    }
    std::vector<DvmValue> args;
    for (bool is_obj : parse_arg_objects(jrt_.method_sig(mid))) {
      const uint64_t val = valist_next_int(e, v);
      args.push_back(is_obj ? DvmValue::O(val)
                            : DvmValue::I(static_cast<int64_t>(val)));
    }
    const DvmValue r = jrt_.call_method(mid, recv, args);
    switch (rk) {
      case 'L':
        e.write_reg(Reg::Ret0, r.obj);
        break;
      case 'I':
        e.write_reg(Reg::Ret0, static_cast<uint64_t>(r.i));
        break;
      case 'V':
        break;
    }
  };
  set_env("CallNonvirtualObjectMethodV",
          [nonvirtual_v](Engine& e) { nonvirtual_v(e, 'L'); });
  set_env("CallNonvirtualIntMethodV",
          [nonvirtual_v](Engine& e) { nonvirtual_v(e, 'I'); });
  set_env("CallNonvirtualBooleanMethodV",
          [nonvirtual_v](Engine& e) { nonvirtual_v(e, 'I'); });
  set_env("CallNonvirtualLongMethodV",
          [nonvirtual_v](Engine& e) { nonvirtual_v(e, 'I'); });
  set_env("CallNonvirtualVoidMethodV",
          [nonvirtual_v](Engine& e) { nonvirtual_v(e, 'V'); });

  // --- M4: field access ---
  set_env("GetObjectField", [this](Engine& e) {
    Args a(e);
    a.next_int();
    const uint64_t obj = a.next_int(), fid = a.next_int();
    const uint64_t r = jrt_.get_field(obj, jrt_.field_name(fid)).obj;
    if (std::getenv("VARDOGER_JNI_LOG"))
      std::fprintf(stderr, "[jni] GetObjectField obj%#llx %s.%s -> %#llx\n",
                   (unsigned long long)obj,
                   jrt_.class_name(jrt_.class_of(obj)).c_str(),
                   jrt_.field_name(fid).c_str(), (unsigned long long)r);
    e.write_reg(Reg::Ret0, r);
  });
  set_env("GetIntField", [this](Engine& e) {
    Args a(e);
    a.next_int();
    const uint64_t obj = a.next_int(), fid = a.next_int();
    e.write_reg(Reg::Ret0, static_cast<uint64_t>(
                               jrt_.get_field(obj, jrt_.field_name(fid)).i));
  });
  set_env("SetObjectField", [this](Engine& e) {  // (env, obj, fid, value)
    Args a(e);
    a.next_int();
    const uint64_t obj = a.next_int(), fid = a.next_int(), val = a.next_int();
    jrt_.set_field(obj, jrt_.field_name(fid), DvmValue::O(val));
  });
  set_env("SetIntField", [this](Engine& e) {
    Args a(e);
    a.next_int();
    const uint64_t obj = a.next_int(), fid = a.next_int();
    jrt_.set_field(obj, jrt_.field_name(fid),
                   DvmValue::I(static_cast<int64_t>(a.next_int())));
  });
  set_env("GetStaticObjectField", [this](Engine& e) {
    Args a(e);
    a.next_int();
    a.next_int();  // env, clazz
    const uint64_t fid = a.next_int();
    const uint64_t r =
        jrt_.get_static(jrt_.field_owner(fid), jrt_.field_name(fid)).obj;
    if (std::getenv("VARDOGER_JNI_LOG"))
      std::fprintf(stderr, "[jni] GetStaticObjectField %s.%s -> %#llx\n",
                   jrt_.field_owner(fid).c_str(), jrt_.field_name(fid).c_str(),
                   (unsigned long long)r);
    e.write_reg(Reg::Ret0, r);
  });
  set_env("GetStaticIntField", [this](Engine& e) {
    Args a(e);
    a.next_int();
    a.next_int();
    const uint64_t fid = a.next_int();
    e.write_reg(
        Reg::Ret0,
        static_cast<uint64_t>(
            jrt_.get_static(jrt_.field_owner(fid), jrt_.field_name(fid)).i));
  });
  set_env("GetStaticBooleanField", [this](Engine& e) {
    Args a(e);
    a.next_int();
    a.next_int();
    const uint64_t fid = a.next_int();
    e.write_reg(
        Reg::Ret0,
        static_cast<uint64_t>(
            jrt_.get_static(jrt_.field_owner(fid), jrt_.field_name(fid)).i));
  });

  // --- M6: arrays (incl. the DEX-in-byte[] capture trigger) ---
  set_env("GetArrayLength", [this](Engine& e) {
    Args a(e);
    a.next_int();
    const uint64_t arr = a.next_int();
    if (std::getenv("VARDOGER_JNI_LOG"))
      std::fprintf(stderr, "[GetArrayLength] arr=obj%#llx -> %llu\n",
                   (unsigned long long)arr,
                   (unsigned long long)jrt_.array_length(arr));
    e.write_reg(Reg::Ret0, jrt_.array_length(arr));
  });
  set_env("NewByteArray", [this](Engine& e) {
    Args a(e);
    a.next_int();
    e.write_reg(Reg::Ret0,
                jrt_.new_byte_array(static_cast<size_t>(a.next_int())));
  });
  set_env("GetObjectArrayElement", [this](Engine& e) {
    Args a(e);
    a.next_int();
    const uint64_t arr = a.next_int(), idx = a.next_int();
    e.write_reg(Reg::Ret0,
                jrt_.object_array_element(arr, static_cast<size_t>(idx)));
  });
  set_env("NewObjectArray", [this](Engine& e) {  // (len, elementClass, initial)
    Args a(e);
    a.next_int();
    const uint64_t len = a.next_int();
    a.next_int();  // element class (ignored)
    const uint64_t init = a.next_int();
    e.write_reg(Reg::Ret0,
                jrt_.new_object_array(std::vector<uint64_t>(len, init)));
  });
  set_env("SetObjectArrayElement", [this](Engine& e) {  // (arr, idx, value)
    Args a(e);
    a.next_int();
    const uint64_t arr = a.next_int(), idx = a.next_int(), val = a.next_int();
    jrt_.set_object_array_element(arr, static_cast<size_t>(idx), val);
  });
  set_env("GetByteArrayRegion", [this](Engine& e) {  // array -> guest buffer
    Args a(e);
    a.next_int();
    const uint64_t arr = a.next_int(), start = a.next_int(), len = a.next_int(),
                   buf = a.next_int();
    const std::vector<uint8_t>* b = jrt_.bytes_view(arr);
    if (std::getenv("VARDOGER_JNI_LOG"))
      std::fprintf(stderr,
                   "[GetByteArrayRegion] arr=obj%#llx start=%llu len=%llu "
                   "bufsz=%zu %s\n",
                   (unsigned long long)arr, (unsigned long long)start,
                   (unsigned long long)len, b ? b->size() : 0,
                   (b && start + len <= b->size() && len) ? "OK" : "SKIP");
    if (b && start + len <= b->size() && len)
      e.write(buf, b->data() + start, len);
  });
  set_env("SetByteArrayRegion",
          [this](Engine& e) {  // guest buffer -> array (+ capture)
            Args a(e);
            a.next_int();
            const uint64_t arr = a.next_int(), start = a.next_int(),
                           len = a.next_int(), buf = a.next_int();
            std::vector<uint8_t>* b = jrt_.bytes_ptr(arr);
            if (b && start + len <= b->size() && len) {
              e.read(buf, b->data() + start, len);
              jrt_.notify_bytes(
                  *b, "SetByteArrayRegion");  // packer just filled a byte[]
            }
          });
  set_env("GetByteArrayElements",
          [this](Engine& e) {  // array -> heap copy (guest pointer)
            Args a(e);
            a.next_int();
            const uint64_t arr = a.next_int(), isCopy = a.next_int();
            const std::vector<uint8_t>* b = jrt_.bytes_view(arr);
            const size_t n = b ? b->size() : 0;
            if (std::getenv("VARDOGER_JNI_LOG"))
              std::fprintf(
                  stderr, "[GetByteArrayElements] arr=obj%#llx -> n=%zu %s\n",
                  (unsigned long long)arr, n, b ? "" : "NO-BYTES-VIEW");
            const uint64_t p = mem_.heap_alloc(n ? n : 1);
            if (n) e.write(p, b->data(), n);
            if (isCopy) {
              const uint8_t one = 1;
              e.write(isCopy, &one, 1);
            }
            e.write_reg(Reg::Ret0, p);
          });
  // GetLongArrayElements: long[] (byte-backed) -> heap copy (guest pointer).
  // ART DexFile.mCookie is a jlong[]{0, DexFile*}; native class-loaders read it
  // via this to reach the DexFile struct.
  set_env("GetLongArrayElements", [this](Engine& e) {
    Args a(e);
    a.next_int();
    const uint64_t arr = a.next_int(), isCopy = a.next_int();
    const std::vector<uint8_t>* b =
        jrt_.bytes_view(arr);  // backing bytes ARE the packed longs
    const size_t n = b ? b->size() : 0;
    const uint64_t p = mem_.heap_alloc(n ? n : 8);
    if (n) e.write(p, b->data(), n);
    if (isCopy) {
      const uint8_t one = 1;
      e.write(isCopy, &one, 1);
    }
    e.write_reg(Reg::Ret0, p);
  });
  set_env("ReleaseLongArrayElements", [](Engine& e) {
    Args a(e);
    a.next_int();
    e.write_reg(Reg::Ret0, 0);
  });
  set_env("ReleaseByteArrayElements",
          [this](Engine& e) {  // commit guest buffer back (+ capture)
            Args a(e);
            a.next_int();
            const uint64_t arr = a.next_int(), ptr = a.next_int(),
                           mode = a.next_int();
            std::vector<uint8_t>* b = jrt_.bytes_ptr(arr);
            if (b && mode != 2 /*JNI_ABORT*/ &&
                !b->empty()) {  // 0=commit+free, 1=commit
              e.read(ptr, b->data(), b->size());
              jrt_.notify_bytes(*b, "ReleaseByteArrayElements");
            }
          });

  // NewObject: create the instance and, for *DexClassLoader ctors, capture any
  // byte[] argument (the decrypted DEX handed to the loader).
  set_env("NewObject", [this](Engine& e) {
    Args a(e);
    a.next_int();
    const uint64_t clazz = a.next_int();
    const uint64_t mid = a.next_int();
    const std::string cls = jrt_.class_name(clazz);
    const std::vector<bool> obj_arg = parse_arg_objects(jrt_.method_sig(mid));
    const bool is_loader = cls.find("DexClassLoader") != std::string::npos;
    for (bool is_obj : obj_arg) {
      const uint64_t v = a.next_int();
      if (is_obj && is_loader)
        if (const std::vector<uint8_t>* b = jrt_.bytes_view(v))
          jrt_.notify_bytes(*b, "InMemoryDexClassLoader ctor");
    }
    e.write_reg(Reg::Ret0, jrt_.new_object(cls));
  });
}

void JniBridge::install_vm_handlers() {
  auto get_env = [this](Engine& e) {
    Args a(e);
    a.next_int();  // vm
    const uint64_t p_env = a.next_int();
    a.next_int();  // version
    write_ptr(p_env, env_);
    e.write_reg(Reg::Ret0, 0);  // JNI_OK
  };
  set_vm("GetEnv", get_env);
  set_vm("AttachCurrentThread", get_env);
  set_vm("AttachCurrentThreadAsDaemon", get_env);
  set_vm("DetachCurrentThread", [](Engine& e) { e.write_reg(Reg::Ret0, 0); });
  set_vm("DestroyJavaVM", [](Engine& e) { e.write_reg(Reg::Ret0, 0); });
}

}  // namespace vardoger
