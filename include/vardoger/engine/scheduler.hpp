// vardoger: cooperative green-thread scheduler.
//
// Unicorn cannot nest uc_emu_start, but it CAN run one context at a time and
// switch between them across sequential slices. This scheduler models pthreads
// that way: each guest "thread" is a saved CPU context (X0..X30, SP, PC, NZCV,
// TPIDR_EL0, V0..V31). A top-level loop runs the current thread via
// uc_emu_start until it reaches a yield point, a blocking stub
// (sleep/join/cond_wait/contended mutex) that records why and calls uc_emu_stop
//, then picks another runnable thread. This makes thread-pool /
// producer-consumer packers (e.g. Ducex's dla) work, where the main thread
// enqueues work and worker threads poll for it. Single host thread, so locks
// never truly contend, they only model ordering. arm64 only.
// (execution core).
#pragma once

#include <cstdint>
#include <initializer_list>
#include <map>
#include <vector>

#include "vardoger/engine/engine.hpp"
#include "vardoger/engine/memory.hpp"

namespace vardoger {

class Scheduler {
 public:
  Scheduler(Engine& engine, Memory& mem);

  // Run fn(args...) as the main thread (tid 0), scheduling every thread it
  // spawns, until the main thread returns. Returns the main thread's X0.
  // Re-usable across top-level calls (e.g. init() then dla());
  // spawned-but-finished threads are reaped.
  uint64_t run(uint64_t fn, std::initializer_list<uint64_t> args);

  bool active() const { return running_; }  // true while inside run()

  // Hybrid (default): a spawned worker runs FIRST until it blocks/exits, so
  // run-to-completion workers (e.g. Ducex init's per-module decrypt) have their
  // results ready when pthread_create returns. Deferred (false): a spawned
  // worker does NOT run until the creator blocks (join/sleep), needed when the
  // creator sets up the worker's input AFTER pthread_create (e.g. Ducex dla's
  // pool).
  void set_hybrid(bool h) { hybrid_ = h; }

  // Override the per-slice timeout at runtime (µs). Lets a caller bound a
  // fragile/garbage-looping drive (e.g. the Jiagu decode scans) to fail fast,
  // without touching the process-wide default. VARDOGER_SLICE_US, if set, still
  // wins (the driver only lowers this when the env is absent).
  void set_slice_us(uint64_t us) { slice_us_ = us; }
  uint64_t slice_us() const { return slice_us_; }

  // ---- called by the pthread stubs, from inside the running thread ----
  // Create a worker and run it FIRST (until it blocks/yields/exits) before the
  // creator resumes: run-to-completion workers get eager semantics (their
  // results are ready when pthread_create returns), pool workers yield back at
  // their wait.
  void spawn(Engine& e, uint64_t out_ptr, uint64_t routine, uint64_t arg);
  // Raw clone/fork path: fork the CURRENT thread's whole CPU context into a new
  // green-thread that resumes at the same (post-SVC) PC but with X0=0 (the
  // child's syscall return), an optional new stack (child_sp; 0 = share the
  // parent's, fork/COW-style) and TLS (tls; 0 = inherit). Writes the child tid
  // to the CLONE_*_SETTID pointers (shared address space) and sets the parent's
  // return register to the child tid. Returns the child tid, or 0 if it can't
  // schedule one (scheduler not running, or not arm64) so the caller can fall
  // back. Used by the clone/clone3/fork/vfork syscalls (see Syscalls::set_clone).
  uint64_t spawn_clone(Engine& e, uint64_t child_sp, uint64_t tls,
                       uint64_t flags, uint64_t ptid, uint64_t ctid);
  // The exit/exit_group syscall from inside a scheduled thread: reap the CURRENT
  // thread (a raw-clone child terminates this way rather than by returning to
  // the sentinel) and switch to another runnable thread; the main thread ending
  // still ends run(). Returns true if it consumed the exit (scheduler active),
  // false otherwise so the caller stops the VM the old way. status = exit code.
  bool thread_exit(Engine& e, uint64_t status);
  void do_join(Engine& e, uint64_t tid,
               uint64_t retval_out);  // block until tid exits
  void do_yield(Engine& e);  // sleep/sched_yield: stay runnable, switch
  void mutex_lock(Engine& e, uint64_t m);
  void mutex_unlock(uint64_t m);
  void cond_wait(Engine& e, uint64_t cond, uint64_t mutex);
  void cond_wake(uint64_t cond, bool all);
  uint64_t self_tid() const { return cur_; }

 private:
  enum class State { Runnable, Blocked, Finished };
  enum class Block { None, Join, Mutex, Cond };
  enum class Stop { None, Exit, Block, Yield };  // why a slice ended

  struct Thread {
    uint64_t tid = 0;
    State state = State::Runnable;
    Block block = Block::None;
    uint64_t block_obj = 0;  // join: target tid; mutex/cond: object address
    uint64_t join_out = 0;   // join: where to write the target's retval
    uint64_t retval = 0;     // start_routine's return value (for joiners)
    bool started = false;    // false until first scheduled (entry regs pending)
    uint64_t entry_arg = 0;
    uint64_t stack_top = 0;
    uint64_t tls_base = 0;
    // saved CPU context (valid when not currently running)
    uint64_t x[31]{}, sp = 0, pc = 0, nzcv = 0, tpidr = 0;
    uint8_t v[32][16]{};
    bool ctx_valid = false;
  };

  Thread* pick_next();
  void load_ctx(const Thread& t);
  void save_ctx(Thread& t);
  void wake_joiners(uint64_t tid);

  Engine& engine_;
  Memory& mem_;
  std::map<uint64_t, Thread> threads_;
  std::map<uint64_t, uint64_t>
      mutex_owner_;  // mutex addr -> owning tid (0 = free)
  uint64_t cur_ = 0;
  uint64_t next_tid_ = 1;  // 0 reserved for the main thread
  uint64_t rr_ = 0;        // round-robin cursor
  uint64_t prefer_ = 0;  // run this tid next (a just-spawned worker), 0 = none
  uint64_t slice_us_ =
      0;  // per-slice timeout (set from VARDOGER_SLICE_US in the ctor; 0 before)
  bool hybrid_ = true;  // run a just-spawned worker first (vs defer to join)
  bool running_ = false;
  Stop stop_ = Stop::None;
  uint64_t exit_retval_ = 0;
};

}  // namespace vardoger
