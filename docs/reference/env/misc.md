# Miscellaneous

---

## VARDOGER_CAPI

**Type:** string (file path)  
**Default:** auto-detected

Absolute path to `libvardoger_capi.so` (Linux) or `libvardoger_capi.dylib` (macOS).
Set this to override the automatic search when the library is in a non-standard location.

```bash
export VARDOGER_CAPI=/opt/vardoger/lib/libvardoger_capi.so
```

Search order when this is not set:
1. Next to `__init__.py` (installed wheel)
2. `<repo>/build/`
3. `<repo>/build/linux/`, `<repo>/build/mac/`, `<repo>/build/pylib/`

---

## VARDOGER_SCHED_DEBUG

**Type:** boolean  
**Default:** disabled

Enable scheduler debug output: thread creation, yield, block, unblock, and preemption
events. Very verbose — only useful when diagnosing deadlocks or scheduling anomalies.

```bash
export VARDOGER_SCHED_DEBUG=1
```

---

## VARDOGER_CALL_LOG

**Type:** boolean  
**Default:** disabled

Log every call and return trampoline hit (functions that go through the trampoline
table, including registered Python stubs). Shows the full dispatch sequence for
trampoline-based stubs.

---

## VARDOGER_LEGACY_SYSCALLS

**Type:** boolean  
**Default:** disabled

Force the legacy syscall handling path. A/B toggle used during development to compare
old and new syscall dispatch behavior.

---

## VARDOGER_LEGACY_MALLOC

**Type:** boolean  
**Default:** disabled

Force the legacy malloc expansion set. A/B toggle for heap allocator strategy
comparison.

---

## VARDOGER_AASSET_FAKEMISS

**Type:** boolean  
**Default:** disabled

Force every `AAssetManager_open()` call to return `NULL`, even when the requested
asset exists in the VFS. Use to test packer fallback paths when assets are absent.

---

## VARDOGER_MEMCPY_WATCH

**Type:** string  
**Default:** none

Log `memcpy` operations matching a watch condition. Used to observe large copies that
could be decryption outputs. The value format is packer-specific.

---

## VARDOGER_FNMATCH_LOG

**Type:** boolean  
**Default:** disabled

Log every `fnmatch()` call: pattern, string, and result. Packers sometimes use
`fnmatch` to check file paths or package names.

---

## VARDOGER_HEAP_LOG

**Type:** boolean  
**Default:** disabled

Log guest heap allocation and free operations: size, returned address, and call site.

---

## VARDOGER_NO_VREGS

**Type:** boolean (negated)  
**Default:** disabled (virtual registers active)

Diagnostic: disable virtual register optimization. Set only when debugging a
suspected register-mapping bug in the engine.
