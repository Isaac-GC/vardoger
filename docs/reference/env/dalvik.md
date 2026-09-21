# Dalvik & JNI

---

## VARDOGER_NO_DALVIK

**Type:** boolean  
**Default:** disabled (Dalvik available)

Disable the built-in Dalvik DEX interpreter. When set, `vm.run_lifecycle()` will not
function. Use to force the ART-only path on packers that should not reach the Dalvik
layer.

---

## VARDOGER_FAKE_DALVIK

**Type:** boolean  
**Default:** disabled

In ART mode, restore the old Dalvik `JavaVM*` handle in `dlopen("")` results. Provides
backwards compatibility for packers that check for the Dalvik VM by inspecting the
handle returned by `dlopen(nullptr)`.

---

## VARDOGER_JNI_LOG

**Type:** boolean  
**Default:** disabled

Log every JNI call (method name, class, and arguments) as it enters the JNI dispatch
layer. Very verbose; use `VARDOGER_VERBOSE` for per-method detail instead.

```bash
export VARDOGER_JNI_LOG=1
```

---

## VARDOGER_VERBOSE

**Type:** boolean  
**Default:** disabled

Enable verbose per-method output in the JNI handler. Prints method owner, name,
signature, and argument values on every dispatch. Pairs with `VARDOGER_JNI_LOG`.

```bash
export VARDOGER_VERBOSE=1
```

---

## VARDOGER_DUMP_BB

**Type:** boolean  
**Default:** disabled

Dump basic blocks during JNI execution. Logs the entry address and instruction count
of every translated basic block. Use for coarse tracing without a full `VARDOGER_ITRACE`.

---

## VARDOGER_LIFECYCLE_TRACE

**Type:** boolean  
**Default:** disabled

Enable trace output during `vm.run_lifecycle()` — logs each lifecycle phase
(`attachBaseContext` / `onCreate`), the class being driven, and the interpreter
dispatch. Useful for diagnosing stalls in the stub's Java bytecode.

```bash
export VARDOGER_LIFECYCLE_TRACE=1
```

---

## VARDOGER_STRLOG

**Type:** boolean  
**Default:** disabled

Log string-related JNI operations (NewStringUTF, GetStringUTFChars, etc.) within the
JNI dispatch layer. Complements `VARDOGER_STR_LOG` (which logs libc string ops) to
show the full Java/native string-passing surface.
