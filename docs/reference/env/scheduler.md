# Scheduler & Execution

These variables control how guest threads are scheduled and how long each call is
allowed to run before being interrupted.

---

## VARDOGER_HYBRID

**Type:** boolean  
**Default:** enabled (1)

Scheduler mode for spawned threads.

- **Unset / `1`** — new threads run immediately when spawned (parallel execution).
- **`0`** — new threads are deferred until the spawning thread blocks (e.g. on a join,
  mutex, or sleep). Use this when a packer spawns a watchdog that must NOT run during
  unpack but the main flow never voluntarily blocks.

```bash
export VARDOGER_HYBRID=0    # deferred scheduler
```

---

## VARDOGER_SCHED_QUANTUM

**Type:** uint64 (instruction count)  
**Default:** `0` (cooperative)

Preemptive scheduling quantum in instructions. When set to a nonzero value, a running
thread is preempted and the next thread is scheduled every `N` instructions. Zero means
cooperative — a thread runs until it blocks or exits.

```bash
export VARDOGER_SCHED_QUANTUM=10000
```

!!! note
    Fine-grained preemption is expensive. Prefer `0` unless you are trying to reproduce
    a race condition or get a packer's watchdog to coexist with the main thread.

---

## VARDOGER_SLICE_US

**Type:** uint64 (microseconds)  
**Default:** `30000000` (30 seconds)

Per-call wall-clock timeout. If a single `vm.call()` or `vm.run_init()` takes longer
than this many microseconds, the scheduler interrupts it. Prevents infinite loops from
hanging indefinitely.

```bash
export VARDOGER_SLICE_US=60000000   # 60 seconds
export VARDOGER_SLICE_US=5000000    # 5 seconds (aggressive)
```

---

## VARDOGER_MAX_PREEMPT

**Type:** uint64  
**Default:** unlimited

Caps the total number of times any single thread can be re-scheduled (rescheduled after
being preempted). Useful as a circuit-breaker when `VARDOGER_SCHED_QUANTUM` is set and
a thread is stuck in a tight loop.

---

## VARDOGER_NO_SLEEP_YIELD

**Type:** boolean  
**Default:** disabled (sleep yields by default)

When a guest thread calls `sleep()` or `nanosleep()`, the scheduler normally yields to
other threads. Set this to skip that yield and return immediately instead.

```bash
export VARDOGER_NO_SLEEP_YIELD=1
```

---

## VARDOGER_TOLERATE_WORKER_FAULT

**Type:** boolean  
**Default:** disabled

If a spawned (non-main) thread crashes (illegal instruction, unmapped access), continue
execution of the remaining threads rather than aborting the whole session.

```bash
export VARDOGER_TOLERATE_WORKER_FAULT=1
```

Useful when a packer spawns a watchdog that performs integrity checks and deliberately
aborts on tamper — tolerating the fault lets the main unpack thread continue.
