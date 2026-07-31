// vardoger: libc / liblog / libdl stubs.
//
// Registers host C++ handlers for the imported functions a packed .so calls,
// each backed by a trampoline. resolve() is wired into the ELF loader's import
// resolver: known names get their handler's stub; unknown names get a
// lazily-made logging stub so a missing import becomes a named log line, not a
// crash.
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "vardoger/engine/engine.hpp"
#include "vardoger/engine/memory.hpp"
#include "vardoger/engine/trampoline.hpp"

namespace vardoger {

class System;     // anti-analysis facade (properties + /proc + clock)
class Scheduler;  // cooperative green-thread scheduler (pthreads)
class Syscalls;   // raw syscall dispatcher (libc syscall() routes here)

class Stubs {
 public:
  Stubs(Engine& engine, Memory& mem, Trampoline& tramp);

  void
  register_defaults();  // the realistic starter set (mem/str/malloc/log/cxa)
  void register_system(System& sys);  // ptrace / properties / /proc via stdio
  // Route pthread/blocking stubs through a scheduler. When set and active,
  // threads are real cooperative contexts; otherwise the eager fallback runs
  // workers inline.
  void set_scheduler(Scheduler& s) { sched_ = &s; }

  // Route the libc syscall(nr, ...) wrapper to the raw syscall dispatcher.
  // Without this syscall() falls back to the "unimplemented -> 0" stub, which
  // breaks anything that reads a real return, notably syscall(gettid) inside
  // __cxa_guard/pthread_once static-init guards (tid==0 corrupts ownership
  // checks and SKIPS guarded initializers, e.g. a native self-decrypt
  // constructor). Reusable across packers.
  void set_syscalls(Syscalls& s) { syscalls_ = &s; }

  // Loader import resolver: returns a stub address for `name`, creating a
  // logging "unimplemented" stub on first sight of an unknown name.
  uint64_t resolve(const std::string& name);

  // Address of an ALREADY-known stub for `name` (a registered libc/JNI stub or a
  // previously-resolved import), or 0 — WITHOUT creating a MISSING stub. Lets the
  // loader try our controlled stubs first, then sibling-library exports, then
  // fall back to resolve() for a MISSING stub.
  uint64_t known(const std::string& name) const;

  // Resolve a symbol against sibling libraries loaded into the same VM (the
  // C-API wires this to search every SoInfo's exports). Consulted by dlsym after
  // the dlsym provider, so a packer that dlopen()+dlsym()s a lib it (or we)
  // loaded lands on the real function.
  void set_lib_resolver(std::function<uint64_t(const std::string&)> f) {
    lib_resolver_ = std::move(f);
  }

  // Set the process name the guest reads via the bionic globals __progname /
  // program_invocation_short_name / program_invocation_name (DATA symbols) and
  // getprogname(). Defaults to the package name; some RASP (LIApp) gate their
  // self-decrypt on __progname matching the package and fail SILENTLY otherwise,
  // which is why isolated loading never decrypts. Call before loading the .so
  // (imports resolve at load time); idempotent (safe to update).
  void set_progname(const std::string& name);

  // dlsym provider: a driver can supply REAL symbol addresses (e.g. from a
  // libart.so it loaded into the guest) so dlsym() returns the actual function,
  // not a stub. Tried before the stub fallback; return 0 to defer.
  void set_dlsym_provider(std::function<uint64_t(const std::string&)> p) {
    dlsym_provider_ = std::move(p);
  }

  // Register a loaded library so dl_iterate_phdr() reports it to the guest
  // callback with a real dl_phdr_info (load base, name, program headers).
  // Packers parse this to find their own load base; without it they compute
  // base=0 and mis-relocate function pointers.
  struct PhdrLib {
    uint64_t dlpi_addr;
    uint64_t phdr_addr;
    uint16_t phnum;
    uint64_t name_addr;
  };
  void register_phdr_lib(uint64_t dlpi_addr, uint64_t phdr_addr, uint16_t phnum,
                         uint64_t name_addr) {
    phdr_libs_.push_back({dlpi_addr, phdr_addr, phnum, name_addr});
  }

 private:
  void add(const std::string& name, Trampoline::Handler h);
  void register_pthreads();  // pthread_*/sleep, scheduler-routed (called by
                             // defaults)
  void register_zlib();      // inflate/inflateInit*/inflateEnd over host zlib
  void dl_iter_step();       // drive the dl_iterate_phdr guest-callback loop

  Engine& engine_;
  Memory& mem_;
  Trampoline& tramp_;
  Scheduler* sched_ = nullptr;    // set => cooperative pthreads
  Syscalls* syscalls_ = nullptr;  // set => libc syscall() routes to it
  uint64_t progname_cell_ = 0;    // char* cell __progname resolves to (stable)
  uint64_t progname_str_ = 0;     // the name string getprogname() returns
  bool progname_fn_ = false;      // getprogname() stub registered
  std::function<uint64_t(const std::string&)>
      dlsym_provider_;  // real symbols (e.g. libart)
  std::function<uint64_t(const std::string&)>
      lib_resolver_;  // sibling-library exports (dlsym cross-lib)
  // dl_iterate_phdr: loaded-lib registry + in-flight iteration state
  // (host-side, persists across the guest-callback redirects).
  std::vector<PhdrLib> phdr_libs_;
  uint64_t dl_cb_ = 0, dl_data_ = 0, dl_ret_lr_ = 0, dl_info_buf_ = 0,
           dl_return_stub_ = 0;
  size_t dl_idx_ = 0;
  std::map<std::string, uint64_t> by_name_;
  // pthread thread-specific storage (single host thread): key -> value.
  std::map<uint64_t, uint64_t> tls_values_;
  uint64_t next_pthread_key_ = 1;
  uint64_t errno_slot_ = 0;
  uint64_t tm_buf_ =
      0;  // static struct tm for gmtime()   // guest errno (lazy)
  // File fds live in System (shared with the raw-syscall layer).
  // Guest z_stream addr -> host z_streamp (void* avoids leaking <zlib.h> into
  // the header).
  std::map<uint64_t, void*> zstreams_;

  // --- synchronous worker-thread emulation (arm64) ---
  // pthread_create records (start_routine, arg); the worker runs LAZILY at the
  // pthread_join that waits on it, by then the creator has set up the shared
  // state a thread-pool worker expects (running eagerly at create
  // deadlocks/null- derefs such workers). The run happens inside the current
  // emulation via PC redirection (no nested uc_emu_start): snapshot the
  // joiner's callee-saved regs/ SP/LR, switch to a private stack, set
  // LR=thread_return_stub_, redirect into the routine. On return that stub
  // stores the result, writes the join's retval-out, and resumes the joiner.
  // Nesting -> a stack of contexts; stacks pooled by depth.
  struct Pending {
    uint64_t routine;
    uint64_t arg;
  };
  struct ThreadCtx {
    uint64_t tid;
    uint64_t ret_lr;
    uint64_t sp;
    uint64_t retval_out;
    uint64_t saved[12];
  };
  uint64_t thread_return_stub_ = 0;
  uint64_t next_tid_ = 0x1000;
  std::map<uint64_t, Pending>
      pending_threads_;                // tid -> (routine, arg), not yet run
  std::vector<ThreadCtx> thread_ctx_;  // joins currently running a worker
  std::map<uint64_t, uint64_t> thread_results_;  // tid -> start_routine return
  std::vector<uint64_t> worker_stacks_;          // stack base per nesting depth
};

}  // namespace vardoger
