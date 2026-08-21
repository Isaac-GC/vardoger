#include "vardoger/engine/scheduler.hpp"

#include <unicorn/unicorn.h>

#include <cstdio>
#include <cstdlib>
#include <stdexcept>

#include "vardoger/engine/address_space.hpp"

namespace vardoger {

static const bool kSchedDbg = std::getenv("VARDOGER_SCHED_DEBUG") != nullptr;
static const bool kNoVregs =
    std::getenv("VARDOGER_NO_VREGS") != nullptr;  // diagnostic
// Preemptive quantum (instructions/slice). 0 = cooperative (run until
// block/exit). A nonzero quantum interleaves threads finely, approximating real
// preemptive pthreads.
static const uint64_t kQuantum = [] {
  const char* q = std::getenv("VARDOGER_SCHED_QUANTUM");
  return q ? std::strtoull(q, nullptr, 0) : 0ull;
}();

namespace {
constexpr size_t kWorkerStack = 0x100000;  // 1 MiB per worker thread
static const uint64_t kSliceTimeoutUs =
    [] {  // VARDOGER_SLICE_US overrides (scans want a short per-call bound)
      const char* s = std::getenv("VARDOGER_SLICE_US");
      return s ? std::strtoull(s, nullptr, 0) : 30'000'000ull;
    }();

// The 31 general regs X0..X30 in order (X29=FP, X30=LR live outside the X0..X28
// run).
const int kXReg[31] = {
    UC_ARM64_REG_X0,  UC_ARM64_REG_X1,  UC_ARM64_REG_X2,  UC_ARM64_REG_X3,
    UC_ARM64_REG_X4,  UC_ARM64_REG_X5,  UC_ARM64_REG_X6,  UC_ARM64_REG_X7,
    UC_ARM64_REG_X8,  UC_ARM64_REG_X9,  UC_ARM64_REG_X10, UC_ARM64_REG_X11,
    UC_ARM64_REG_X12, UC_ARM64_REG_X13, UC_ARM64_REG_X14, UC_ARM64_REG_X15,
    UC_ARM64_REG_X16, UC_ARM64_REG_X17, UC_ARM64_REG_X18, UC_ARM64_REG_X19,
    UC_ARM64_REG_X20, UC_ARM64_REG_X21, UC_ARM64_REG_X22, UC_ARM64_REG_X23,
    UC_ARM64_REG_X24, UC_ARM64_REG_X25, UC_ARM64_REG_X26, UC_ARM64_REG_X27,
    UC_ARM64_REG_X28, UC_ARM64_REG_X29, UC_ARM64_REG_X30,
};
}  // namespace

Scheduler::Scheduler(Engine& engine, Memory& mem) : engine_(engine), mem_(mem) {
  slice_us_ = kSliceTimeoutUs;
  // VARDOGER_HYBRID=0 defers spawned workers until the creator blocks (join/
  // sleep), instead of running them eagerly. Needed when a packer spawns
  // infinite-loop anti-tamper monitor threads that would otherwise starve the
  // MAIN thread's real work (e.g. a packer's DEX decrypt on the main thread).
  if (const char* h = std::getenv("VARDOGER_HYBRID"); h && h[0] == '0')
    hybrid_ = false;
}

void Scheduler::load_ctx(const Thread& t) {
  uc_engine* uc = engine_.raw();
  for (int i = 0; i < 31; ++i) uc_reg_write(uc, kXReg[i], &t.x[i]);
  uc_reg_write(uc, UC_ARM64_REG_SP, &t.sp);
  uc_reg_write(uc, UC_ARM64_REG_NZCV, &t.nzcv);
  uc_reg_write(uc, UC_ARM64_REG_TPIDR_EL0, &t.tpidr);
  if (!kNoVregs)
    for (int i = 0; i < 32; ++i) uc_reg_write(uc, UC_ARM64_REG_V0 + i, t.v[i]);
}

void Scheduler::save_ctx(Thread& t) {
  uc_engine* uc = engine_.raw();
  for (int i = 0; i < 31; ++i) uc_reg_read(uc, kXReg[i], &t.x[i]);
  uc_reg_read(uc, UC_ARM64_REG_SP, &t.sp);
  uc_reg_read(uc, UC_ARM64_REG_PC, &t.pc);
  uc_reg_read(uc, UC_ARM64_REG_NZCV, &t.nzcv);
  uc_reg_read(uc, UC_ARM64_REG_TPIDR_EL0, &t.tpidr);
  if (!kNoVregs)
    for (int i = 0; i < 32; ++i) uc_reg_read(uc, UC_ARM64_REG_V0 + i, t.v[i]);
}

Scheduler::Thread* Scheduler::pick_next() {
  if (prefer_) {  // a just-spawned worker runs first
    const uint64_t p = prefer_;
    prefer_ = 0;
    auto it = threads_.find(p);
    if (it != threads_.end() && it->second.state == State::Runnable)
      return &it->second;
  }
  // round-robin over runnable threads so pollers and producers all make
  // progress.
  if (threads_.empty()) return nullptr;
  const size_t n = threads_.size();
  std::vector<uint64_t> ids;
  ids.reserve(n);
  for (auto& kv : threads_) ids.push_back(kv.first);
  for (size_t k = 0; k < n; ++k) {
    const uint64_t id = ids[(rr_ + k) % n];
    Thread& t = threads_.at(id);
    if (t.state == State::Runnable) {
      rr_ = (rr_ + k + 1) % n;
      return &t;
    }
  }
  return nullptr;
}

void Scheduler::wake_joiners(uint64_t tid) {
  const uint64_t rv = threads_.at(tid).retval;
  for (auto& kv : threads_) {
    Thread& t = kv.second;
    if (t.state == State::Blocked && t.block == Block::Join &&
        t.block_obj == tid) {
      if (t.join_out) engine_.write_t<uint64_t>(t.join_out, rv);
      t.block = Block::None;
      t.state = State::Runnable;
    }
  }
}

uint64_t Scheduler::run(uint64_t fn, std::initializer_list<uint64_t> args) {
  uc_engine* uc = engine_.raw();
  threads_.clear();
  mutex_owner_.clear();
  cur_ = 0;
  rr_ = 0;
  next_tid_ = 1;
  running_ = true;

  // Main thread (tid 0) runs on the current stack/state; we just point it at
  // fn.
  Thread main{};
  main.tid = 0;
  save_ctx(main);  // snapshot current registers
  int i = 0;
  for (uint64_t a : args) {
    if (i < 31) main.x[i] = a;
    ++i;
  }
  main.x[30] = kFiniPage;  // LR: return sentinel
  main.pc = fn;
  main.ctx_valid = true;
  main.state = State::Runnable;
  threads_[0] = main;

  uint64_t result = 0;
  // Anti-spin: a native garbage loop inside a callee (e.g. a decode-scan drive
  // fed huge seed values used as a loop count) never returns or faults, so it
  // is re-run every quantum forever. VARDOGER_MAX_PREEMPT bounds the number of
  // quantum preemptions per run(); on exceed we throw (the decode-scan drive
  // catches it and moves to the next method). 0 = unbounded (default; only
  // decode scans set it).
  static const uint64_t kMaxPreempt = [] {
    const char* s = std::getenv("VARDOGER_MAX_PREEMPT");
    return s ? std::strtoull(s, nullptr, 0) : 0ull;
  }();
  uint64_t preempts = 0;
  for (;;) {
    Thread* t = pick_next();
    if (!t)
      throw std::runtime_error("scheduler: no runnable thread (deadlock)");
    cur_ = t->tid;
    load_ctx(*t);
    const uint64_t slice_pc = t->pc;
    stop_ = Stop::None;
    try {
      engine_.run(t->pc, kFiniPage, slice_us_,
                  kQuantum);  // slice (block/exit/quantum)
    } catch (...) {
      if (kSchedDbg) {
        uint64_t x21 = 0, ga8 = 0;
        uc_reg_read(uc, UC_ARM64_REG_X21, &x21);
        uc_mem_read(uc, 0x120eb800, &ga8, 8);  // g+0xa8 (load_bias 0x12000000)
        std::fprintf(stderr,
                     "[sched] t%llu FAULTED slice_pc=%#llx lr=%#llx sp=%#llx "
                     "x21=%#llx [g+0xa8]=%#llx\n",
                     (unsigned long long)cur_, (unsigned long long)slice_pc,
                     (unsigned long long)t->x[30], (unsigned long long)t->sp,
                     (unsigned long long)x21, (unsigned long long)ga8);
      }
      // VARDOGER_TOLERATE_WORKER_FAULT: a crashing WORKER thread (cur_!=0), e.g.
      // an anti-tamper watchdog that faults inside vardoger: must not kill the
      // whole run. Retire it and keep scheduling so the MAIN thread finishes
      // its work (the DEX decrypt). The main thread (tid 0) still propagates.
      if (cur_ != 0 && std::getenv("VARDOGER_TOLERATE_WORKER_FAULT")) {
        Thread& f = threads_.at(cur_);
        f.state = State::Finished;
        wake_joiners(cur_);
        std::fprintf(stderr,
                     "[sched] worker t%llu faulted @ %#llx -> retired "
                     "(tolerate), continuing\n",
                     (unsigned long long)cur_, (unsigned long long)slice_pc);
        continue;
      }
      throw;
    }

    uint64_t pc_now = 0;
    uc_reg_read(uc, UC_ARM64_REG_PC, &pc_now);
    Thread& ran = threads_.at(cur_);
    const char* why = "?";
    if (stop_ == Stop::Block) {
      save_ctx(ran);  // stub already set state/PC=LR
      why = ran.block == Block::Join    ? "block:join"
            : ran.block == Block::Mutex ? "block:mutex"
                                        : "block:cond";
    } else if (stop_ == Stop::Yield) {
      save_ctx(ran);
      ran.state = State::Runnable;
      why = "yield";
    } else if (pc_now == kFiniPage) {  // thread returned
      uc_reg_read(uc, UC_ARM64_REG_X0, &ran.retval);
      ran.state = State::Finished;
      wake_joiners(cur_);
      why = "exit";
      if (kSchedDbg)
        std::fprintf(stderr,
                     "[sched] t%llu ran [%#llx..] -> exit (ret=%#llx)\n",
                     (unsigned long long)cur_, (unsigned long long)slice_pc,
                     (unsigned long long)ran.retval);
      if (cur_ == 0) {
        result = ran.retval;
        break;
      }
      continue;
    } else if (kQuantum &&
               pc_now !=
                   kFiniPage) {  // quantum expired: preempt, stay runnable
      save_ctx(ran);
      ran.state = State::Runnable;
      why = "preempt";
      if (kMaxPreempt &&
          ++preempts > kMaxPreempt) {  // spinning callee -> bail this run()
        running_ = false;
        throw std::runtime_error("scheduler: preempt cap exceeded (anti-spin)");
      }
    } else {
      char msg[128];
      std::snprintf(msg, sizeof(msg),
                    "scheduler: slice ended unexpectedly at pc=%#llx "
                    "(slice_pc=%#llx lr=%#llx)",
                    (unsigned long long)pc_now, (unsigned long long)slice_pc,
                    (unsigned long long)ran.x[30]);
      throw std::runtime_error(msg);
    }
    if (kSchedDbg)
      std::fprintf(stderr, "[sched] t%llu ran [%#llx..] -> %s\n",
                   (unsigned long long)cur_, (unsigned long long)slice_pc, why);
  }
  running_ = false;
  return result;
}

void Scheduler::spawn(Engine& e, uint64_t out_ptr, uint64_t routine,
                      uint64_t arg) {
  const uint64_t tid = next_tid_++;
  Thread t{};
  t.tid = tid;
  t.stack_top = (mem_.mmap_alloc(kWorkerStack, UC_PROT_READ | UC_PROT_WRITE,
                                 "thread stack") +
                 kWorkerStack) &
                ~uint64_t(15);
  // Initial context: start_routine(arg) on its own stack, returning to the
  // sentinel.
  t.x[0] = arg;
  t.x[30] = kFiniPage;
  t.sp = t.stack_top;
  t.pc = routine;
  uc_reg_read(engine_.raw(), UC_ARM64_REG_TPIDR_EL0,
              &t.tpidr);  // share the main TLS
  t.ctx_valid = true;
  t.state = State::Runnable;
  threads_[tid] = t;

  if (out_ptr) e.write_t<uint64_t>(out_ptr, tid);
  e.write_reg(Reg::Ret0, 0);
  if (!hybrid_)
    return;  // deferred: creator continues; worker
             // runs at the next join/sleep (data ready)
  // Hybrid: YIELD so the new worker runs first (its result is ready at create).
  e.write_reg(Reg::Pc,
              e.read_reg(Reg::Lr));  // creator resumes after pthread_create
  threads_.at(cur_).state = State::Runnable;
  prefer_ = tid;  // ...but the worker is scheduled next
  stop_ = Stop::Yield;
  e.stop();
}

uint64_t Scheduler::spawn_clone(Engine& e, uint64_t child_sp, uint64_t tls,
                                uint64_t /*flags*/, uint64_t ptid,
                                uint64_t ctid) {
  // Only meaningful under an active arm64 schedule (the context model is
  // arm64-only); otherwise report failure so the syscall falls back to -ENOSYS.
  if (!running_ || e.abi() != Abi::Arm64) return 0;
  const uint64_t tid = next_tid_++;
  Thread t{};
  t.tid = tid;
  save_ctx(t);      // child inherits the FULL parent context (x1..x30, v, nzcv,
  t.x[0] = 0;       // tpidr) and the live post-SVC PC, but returns 0 as the child
  if (child_sp) {   // pthread/clone: run on the caller-provided stack...
    t.sp = child_sp & ~uint64_t(15);  // (fork, child_sp==0: keep the shared sp)
    t.x[30] = kFiniPage;  // ...and reap it if the child routine ever returns
  }
  if (tls) t.tpidr = tls;             // CLONE_SETTLS
  t.state = State::Runnable;
  t.ctx_valid = true;
  threads_[tid] = t;

  // Shared address space, so the SETTID writes land where the child would put
  // them. (glibc/bionic pthread reads *ctid to learn its own tid.)
  if (ptid) e.write_t<uint32_t>(ptid, static_cast<uint32_t>(tid));
  if (ctid) e.write_t<uint32_t>(ctid, static_cast<uint32_t>(tid));

  e.write_reg(Reg::Ret0, tid);  // parent's clone() returns the child tid
  if (!hybrid_) return tid;     // deferred: parent runs on; child runs at its
                                // next block/yield/quantum
  // Hybrid: let the child run first (its side effects are visible when the
  // parent's clone() returns), then the parent resumes at the post-SVC PC.
  threads_.at(cur_).state = State::Runnable;
  prefer_ = tid;
  stop_ = Stop::Yield;
  e.stop();
  return tid;
}

bool Scheduler::thread_exit(Engine& e, uint64_t status) {
  if (!running_) return false;  // no schedule -> caller stops the VM directly
  // Reuse the "thread returned to the sentinel" reap path: point PC at kFiniPage
  // and end the slice. The run loop then records X0 as the retval, marks this
  // thread Finished, wakes its joiners, and (if it was the main thread) returns.
  e.write_reg(Reg::Ret0, status);  // becomes the thread's retval (join result)
  e.write_reg(Reg::Pc, kFiniPage);
  e.stop();
  return true;
}

// ---- blocking primitives: set the thread's resume state, then stop the slice
// ----

void Scheduler::do_join(Engine& e, uint64_t tid, uint64_t retval_out) {
  auto it = threads_.find(tid);
  if (it == threads_.end() ||
      it->second.state == State::Finished) {  // already done
    if (retval_out)
      e.write_t<uint64_t>(retval_out,
                          it == threads_.end() ? 0 : it->second.retval);
    e.write_reg(Reg::Ret0, 0);
    return;  // no block: caller continues
  }
  Thread& self = threads_.at(cur_);
  self.state = State::Blocked;
  self.block = Block::Join;
  self.block_obj = tid;
  self.join_out = retval_out;
  e.write_reg(Reg::Ret0, 0);                  // join returns 0 when woken
  e.write_reg(Reg::Pc, e.read_reg(Reg::Lr));  // resume at the caller
  stop_ = Stop::Block;
  e.stop();
}

void Scheduler::do_yield(Engine& e) {  // sleep / sched_yield
  e.write_reg(Reg::Ret0, 0);
  e.write_reg(Reg::Pc, e.read_reg(Reg::Lr));  // return to caller next time
  stop_ = Stop::Yield;
  e.stop();
}

void Scheduler::mutex_lock(Engine& e, uint64_t m) {
  auto it = mutex_owner_.find(m);
  if (it == mutex_owner_.end() ||
      it->second == 0) {  // free -> acquire, continue
    mutex_owner_[m] = cur_;
    e.write_reg(Reg::Ret0, 0);
    return;
  }
  Thread& self = threads_.at(cur_);  // contended -> block
  self.state = State::Blocked;
  self.block = Block::Mutex;
  self.block_obj = m;
  e.write_reg(Reg::Ret0, 0);
  e.write_reg(Reg::Pc, e.read_reg(Reg::Lr));
  stop_ = Stop::Block;
  e.stop();
}

void Scheduler::mutex_unlock(uint64_t m) {
  mutex_owner_[m] = 0;
  for (auto& kv : threads_) {  // hand off to one waiter
    Thread& t = kv.second;
    if (t.state == State::Blocked && t.block == Block::Mutex &&
        t.block_obj == m) {
      mutex_owner_[m] = t.tid;
      t.block = Block::None;
      t.state = State::Runnable;
      break;
    }
  }
}

void Scheduler::cond_wait(Engine& e, uint64_t cond, uint64_t mutex) {
  mutex_unlock(mutex);  // release while waiting
  Thread& self = threads_.at(cur_);
  self.state = State::Blocked;
  self.block = Block::Cond;
  self.block_obj = cond;
  e.write_reg(Reg::Ret0, 0);
  e.write_reg(Reg::Pc, e.read_reg(Reg::Lr));
  stop_ = Stop::Block;
  e.stop();
}

void Scheduler::cond_wake(uint64_t cond, bool all) {
  for (auto& kv : threads_) {
    Thread& t = kv.second;
    if (t.state == State::Blocked && t.block == Block::Cond &&
        t.block_obj == cond) {
      t.block = Block::None;
      t.state = State::Runnable;  // re-acquire is modelled loosely
      if (!all) break;
    }
  }
}

}  // namespace vardoger
