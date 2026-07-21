// vardoger: raw syscall dispatcher.
//
// When the interrupt hook decides a trap is a real syscall (PC not on the
// trampoline page), it routes here. Handles the curated set a packer issues
// directly to bypass libc hooks: a controlled clock, pid/uid, mmap/mprotect
// (-> Memory), /proc reads (-> System), exit, getrandom, ptrace. Two number
// tables (arm64 + arm32).
#pragma once

#include <cstdint>
#include <functional>
#include <unordered_map>

#include "vardoger/android/system.hpp"
#include "vardoger/engine/engine.hpp"
#include "vardoger/engine/memory.hpp"

namespace vardoger {

class Syscalls {
 public:
  Syscalls(Engine& engine, Memory& mem, System& sys)
      : e_(engine), mem_(mem), sys_(sys) {}

  // Read the syscall number, run the handler, set the return register.
  void dispatch(Engine& e);

  // Cooperative-yield hook. nanosleep/sched_yield call this to give the CPU to
  // another thread, a real sleeping thread yields the scheduler. Without it, a
  // packer's watchdog thread (sleep -> poll -> maybe self-destruct) never lets
  // the main thread run, so it always sees "no progress" and self-destructs.
  // The hook should perform a scheduler yield (returning to the caller next
  // time) and return true; if no scheduler is active it returns false and the
  // caller just returns 0 (old behavior).
  void set_yield(std::function<bool()> y) { yield_ = std::move(y); }

 private:
  Engine& e_;
  Memory& mem_;
  System& sys_;  // single fd table lives here (shared with libc stubs)
  std::function<bool()> yield_;
};

}  // namespace vardoger
