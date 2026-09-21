# Environment Variables — Overview

vardoger is configured primarily through environment variables. Every option has a
sensible default; set only the ones you need for your specific packer.

## Conventions

- **Boolean flags** — presence of the variable enables the feature; the value is ignored
  (any non-empty string works). Unset = disabled.
- **Integer values** — parsed via `strtoull` (decimal or hex with `0x` prefix).
- **String values** — passed as-is; see per-variable docs for format.
- **Path values** — absolute path to a file or directory.

## Quick reference

| Category | Variables |
|---|---|
| [Scheduler & Execution](scheduler.md) | `VARDOGER_HYBRID`, `VARDOGER_SCHED_QUANTUM`, `VARDOGER_SLICE_US`, `VARDOGER_MAX_PREEMPT`, `VARDOGER_NO_SLEEP_YIELD`, `VARDOGER_TOLERATE_WORKER_FAULT` |
| [Memory & Mapping](memory.md) | `VARDOGER_TCG_BUFFER_MB`, `VARDOGER_AUTOMAP`, `VARDOGER_LOW_LIB_BASE`, `VARDOGER_HEAP_TIGHT`, `VARDOGER_NO_MAPFIXED`, `VARDOGER_WX` |
| [ART / DEX Runtime](art.md) | `VARDOGER_ART`, `VARDOGER_ART_RUNTIME`, `VARDOGER_ART_CLASSLINKER`, `VARDOGER_ART_HOOKABLE` |
| [Anti-Tamper Evasion](evasion.md) | `VARDOGER_EXIT_NOOP`, `VARDOGER_ABORT_NOOP`, `VARDOGER_SLEEP_NOOP`, `VARDOGER_KILL_ESRCH`, `VARDOGER_NO_TAMPER_EVASION`, `VARDOGER_PROC_HIDE` |
| [System Environment](system.md) | `VARDOGER_PROGNAME`, `MINVM_PROGNAME`, `VARDOGER_PROPS`, `VARDOGER_ENTRY_CLASS`, `VARDOGER_NO_MMAINTHREAD`, `VARDOGER_NO_FIELD_DEFAULTS` |
| [Dalvik & JNI](dalvik.md) | `VARDOGER_NO_DALVIK`, `VARDOGER_FAKE_DALVIK`, `VARDOGER_JNI_LOG`, `VARDOGER_VERBOSE`, `VARDOGER_DUMP_BB`, `VARDOGER_LIFECYCLE_TRACE`, `VARDOGER_STRLOG` |
| [Tracing & Instrumentation](tracing.md) | `VARDOGER_ITRACE`, `VARDOGER_PCTRACE`, `VARDOGER_TRACEPC`, `VARDOGER_BT`, `VARDOGER_XWATCH`, `VARDOGER_MEMREAD`, `VARDOGER_MEMWRITE_TGT`, `VARDOGER_DEXWRITE`, `VARDOGER_ADDRWATCH`, `VARDOGER_EWRITE_WATCH` |
| [Crypto Extraction](crypto.md) | `VARDOGER_KSA_DUMP`, `VARDOGER_RC4_FAST`, `VARDOGER_RC4_LOG`, `VARDOGER_RC4_DUMP` |
| [I/O Logging](io.md) | `VARDOGER_OPEN_LOG`, `VARDOGER_READ_LOG`, `VARDOGER_LSEEK_LOG`, `VARDOGER_DL_LOG`, `VARDOGER_DLOPEN_FAIL`, `VARDOGER_MMAP_LOG`, `VARDOGER_PROP_LOG`, `VARDOGER_ZLIB_LOG`, `VARDOGER_ZLIB_DUMP`, `VARDOGER_INFLATE_DUMP`, `VARDOGER_STR_LOG` |
| [Miscellaneous](misc.md) | `VARDOGER_SCHED_DEBUG`, `VARDOGER_CALL_LOG`, `VARDOGER_LEGACY_SYSCALLS`, `VARDOGER_LEGACY_MALLOC`, `VARDOGER_CAPI` |
