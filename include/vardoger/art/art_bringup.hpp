// vardoger: ART runtime bring-up (make vardoger's mapped libart close to a live
// ART runtime). See core/art/art_bringup.cpp. Referenced against AOSP art/
// android-15.0.0_rN.
#pragma once

#include <cstdint>
#include <string>

namespace vardoger {

class Engine;
class Memory;

// Increment #1: give every art::Locks::<name>_ global (null because we never
// run Runtime::Init) a zeroed Mutex object, so native ART code that takes a
// lock (JavaVMExt::VisitRoots -> jni_globals_lock_, etc.) doesn't fault on
// [null+0x14]. Parses libart's symbol table so it works for any mapped libart
// version. Returns the number of locks initialized. Idempotent.
int art_init_locks(Engine& e, Memory& mem, uint64_t art_bias,
                   const std::string& art_file_path);

// Increment #2: set art::Runtime::instance_ (null because we never run
// Runtime::Init) to a large zeroed Runtime object so `Runtime::Current()`
// returns non-null and its guards pass; the next real field dependency then
// faults in mapped memory (the fault-driven signal for the next increment).
// Returns the guest Runtime* (0 if the symbol is absent). Idempotent.
// Version-agnostic (symbol-found; no hardcoded internal offsets).
uint64_t art_init_runtime(Engine& e, Memory& mem, uint64_t art_bias,
                          const std::string& art_file_path);

// Increment #3: set art::Thread::is_started_=1 and install a zeroed Thread* in
// TLS slot 7 (tpidr_el0+0x38) so `Thread::Current()` returns non-null. arm64
// only. Idempotent. Returns the guest Thread* (0 if not arm64 / no TLS). Call
// AFTER Memory::setup_tls.
uint64_t art_init_thread(Engine& e, Memory& mem, uint64_t art_bias,
                         const std::string& art_file_path);

}  // namespace vardoger
