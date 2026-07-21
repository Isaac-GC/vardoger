// vardoger: ART runtime bring-up: initialize the pieces of real libart state
// that native ART code dereferences, so a packer that CALLS into libart (not
// just hooks it) doesn't fault on uninitialized runtime globals. This is the
// incremental "make vardoger close to real ART" layer (see the task +
//. Referenced against AOSP art/ (android-15.0.0_rN):
// runtime/base/{mutex,locks}.h, runtime/jni/java_vm_ext.{h,cc}.
//
// Increment #1 (landed): art::Locks. In real ART every lock is a heap
// Mutex/ReaderWriterMutex created by Locks::Init() during Runtime startup, and
// its pointer stored in a global (art::Locks::<name>_). We map libart but never
// run its init, so those globals are null, the first native ART call that
// takes a lock (e.g. JavaVMExt::VisitRoots -> Locks::jni_globals_lock_) reads
// [null+0x14] (the Mutex's state_and_contenders_ atomic, offset 0x14) and
// faults. Fix: give each Locks global a zeroed Mutex object (unlocked; the
// uncontended fast-path CAS at +0x14 works, single-threaded so we never hit the
// vtable slow path). Discovered from libart's .symtab so it is version-agnostic
// (works whatever API level the mapped libart is).
#include "vardoger/art/art_bringup.hpp"

#include <unicorn/unicorn.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include "vardoger/engine/engine.hpp"
#include "vardoger/engine/memory.hpp"

namespace vardoger {
namespace {
// Minimal ELF64 .symtab/.dynsym walk: call `cb(name, st_value, st_size,
// st_type)` for each symbol.
template <class Cb>
void for_each_symbol(const std::string& path, Cb cb) {
  std::ifstream f(path, std::ios::binary);
  std::string d((std::istreambuf_iterator<char>(f)),
                std::istreambuf_iterator<char>());
  if (d.size() < 0x40 || std::memcmp(d.data(),
                                     "\x7f"
                                     "ELF",
                                     4) != 0)
    return;
  auto u16 = [&](size_t o) {
    uint16_t v;
    std::memcpy(&v, d.data() + o, 2);
    return v;
  };
  auto u32 = [&](size_t o) {
    uint32_t v;
    std::memcpy(&v, d.data() + o, 4);
    return v;
  };
  auto u64 = [&](size_t o) {
    uint64_t v;
    std::memcpy(&v, d.data() + o, 8);
    return v;
  };
  const uint64_t shoff = u64(0x28);
  const uint16_t shentsize = u16(0x3a), shnum = u16(0x3c);
  for (uint16_t i = 0; i < shnum; ++i) {
    const size_t sh = shoff + i * shentsize;
    if (sh + 64 > d.size()) break;
    const uint32_t type = u32(sh + 4);
    if (type != 2 && type != 11) continue;  // SYMTAB / DYNSYM
    const uint64_t off = u64(sh + 24), size = u64(sh + 32);
    const uint32_t link = u32(sh + 40);
    uint64_t ent = u64(sh + 56);
    if (!ent) ent = 24;
    const uint64_t stroff = u64(shoff + link * shentsize + 24);
    for (uint64_t k = off; k + 24 <= off + size && k + 24 <= d.size();
         k += ent) {
      const uint32_t st_name = u32(k);
      const uint8_t st_info = (uint8_t)d[k + 4];
      const uint64_t st_value = u64(k + 8), st_size = u64(k + 16);
      const size_t ns = stroff + st_name;
      if (ns >= d.size()) continue;
      const char* nm = d.data() + ns;
      cb(std::string(nm, strnlen(nm, d.size() - ns)), st_value, st_size,
         (uint8_t)(st_info & 0xf));
    }
  }
}
}  // namespace

int art_init_locks(Engine& e, Memory& mem, uint64_t art_bias,
                   const std::string& art_file_path) {
  int n = 0;
  for_each_symbol(art_file_path, [&](const std::string& name, uint64_t va,
                                     uint64_t sz, uint8_t type) {
    // art::Locks::<name>_ pointer globals (mangled "_ZN3art5Locks..."), 8-byte
    // OBJECT slots.
    if (type != 1 || sz != 8) return;  // STT_OBJECT, pointer-sized
    if (name.find("3art5Locks") == std::string::npos) return;
    const uint64_t slot = art_bias + va;
    if (e.read_t<uint64_t>(slot) != 0) return;  // already set (idempotent)
    const uint64_t mtx = mem.heap_alloc(0x60);  // zeroed Mutex (unlocked)
    e.write_t<uint64_t>(slot, mtx);
    ++n;
  });
  std::fprintf(stderr,
               "[art] init_locks: %d art::Locks globals -> Mutex objects\n", n);
  return n;
}

// Increment #2: art::Runtime singleton. `Runtime::Current()` is just `return
// instance_;` reading the
// `_ZN3art7Runtime9instance_E` global (a `Runtime*`). We never run
// Runtime::Init, so it is null and every `Runtime::Current()->...` faults at
// the null base. Point it at a large zeroed Runtime object so
// `Runtime::Current() != nullptr` guards pass and the deref lands in mapped
// (zeroed) memory, the next real dependency (class_linker_, heap_, java_vm_,
// thread_list_ …) then faults *there*, which is the fault-driven signal for the
// next increment. Version-agnostic: the global is found by symbol; we do NOT
// hardcode Runtime's internal field offsets (those differ per API level -
// filled on demand as faults surface). Returns the guest Runtime* (0 if the
// symbol is absent). Idempotent.
uint64_t art_init_runtime(Engine& e, Memory& mem, uint64_t art_bias,
                          const std::string& art_file_path) {
  uint64_t slot = 0;
  for_each_symbol(art_file_path, [&](const std::string& name, uint64_t va,
                                     uint64_t sz, uint8_t type) {
    if (type == 1 && sz == 8 && name == "_ZN3art7Runtime9instance_E")
      slot = art_bias + va;
  });
  if (!slot) {
    std::fprintf(stderr,
                 "[art] init_runtime: Runtime::instance_ symbol not found\n");
    return 0;
  }
  uint64_t rt = e.read_t<uint64_t>(slot);
  if (rt) return rt;            // already set (idempotent)
  rt = mem.heap_alloc(0x4000);  // zeroed Runtime (generous; real ~0x1e00)
  e.write_t<uint64_t>(slot, rt);
  std::fprintf(
      stderr,
      "[art] init_runtime: Runtime::instance_ @ %#llx -> Runtime obj %#llx\n",
      (unsigned long long)slot, (unsigned long long)rt);
  return rt;
}

// Increment #3: art::Thread. `Thread::Current()` is `is_started_ ?
// __get_tls[7] : nullptr`, it reads the current Thread* from TLS slot 7
// (tpidr_el0 + 0x38, TLS_SLOT_ART_THREAD_SELF) but ONLY if the global
// `art::Thread::is_started_` byte is set (else returns null). We never run
// Runtime::Init so is_started_ is 0 and slot 7 is null, and any ART code that
// does `Thread* self = Thread::Current()` gets null -> faults on `self->...`.
// Fix: set is_started_=1 and install a large zeroed Thread object in TLS
// slot 7. Version-agnostic: is_started_ found by symbol; slot 7 is the fixed
// bionic AArch64 ART self-slot. Returns the guest Thread* (0 if not arm64).
// Idempotent.
uint64_t art_init_thread(Engine& e, Memory& mem, uint64_t art_bias,
                         const std::string& art_file_path) {
  if (e.abi() != Abi::Arm64) return 0;  // slot 7 layout is the arm64 bionic TLS
  // 1) art::Thread::is_started_ = 1 (the Thread::Current() gate).
  for_each_symbol(art_file_path, [&](const std::string& name, uint64_t va,
                                     uint64_t sz, uint8_t type) {
    if (type == 1 && sz == 1 && name == "_ZN3art6Thread11is_started_E")
      e.write_t<uint8_t>(art_bias + va, 1);
  });
  // 2) install a Thread* in TLS slot 7 (tpidr_el0 + 0x38) if not already set.
  uint64_t tls = 0;
  uc_reg_read(e.raw(), UC_ARM64_REG_TPIDR_EL0, &tls);
  if (!tls) return 0;
  uint64_t thr = e.read_t<uint64_t>(tls + 0x38);
  if (thr) return thr;  // already installed (idempotent)
  thr = mem.heap_alloc(
      0x2000);  // zeroed Thread (real ~0xf00); fault-drive fields
  e.write_t<uint64_t>(tls + 0x38, thr);
  std::fprintf(stderr,
               "[art] init_thread: Thread::is_started_=1, TLS[7]=%#llx -> "
               "Thread obj %#llx\n",
               (unsigned long long)(tls + 0x38), (unsigned long long)thr);
  return thr;
}

}  // namespace vardoger
