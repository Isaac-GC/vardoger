# VM

The central class. Create one per analysis session; it maps to a single guest address space.

```python
from vardoger import VM

vm = VM(package="com.example.app", sdk=31)
```

`VM` is a context manager:

```python
with VM(package="com.example.app") as vm:
    ...
```

---

## Constructor

```python
VM(*, abi: str = "arm64", package: str | None = None, sdk: int = 31)
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `abi` | `str` | `"arm64"` | Target ABI. Currently only `"arm64"` is supported. |
| `package` | `str \| None` | `None` | Android package name (e.g. `"com.example.app"`). Sets `__progname`, data-dir path, and APK path. |
| `sdk` | `int` | `31` | Android API level. Affects path layout and default system properties. |

Raises `VardogerError` if the underlying runtime cannot be allocated.

---

## Lifecycle

### `load(path) → Module`

```python
so = vm.load("lib/arm64-v8a/libpacker.so")
```

Load an ELF `.so`: run relocations and resolve imports against the stub libc/JNI layer.
Does **not** run DT_INIT or `.init_array`.

Returns a [`Module`](#module).

---

### `run_init(mod)`

```python
vm.run_init(so)
```

Run `DT_INIT` then every `.init_array` entry of `mod` in order.
Self-decryption and anti-tamper checks typically happen here.

---

### `call(fn, args=()) → int`

```python
ret = vm.call(so.jni_onload, [vm.java_vm, 0])
```

Call guest function at `fn` through the scheduler. Blocking pthreads (futex, nanosleep)
are supported — spawned threads run cooperatively. Up to 8 args go in x0–x7.
Returns x0 (the integer/pointer result).

---

### `map_art(art_dir)`

Map a real `libart.so` from `art_dir` without running its init, and wire `dlsym` /
`dl_iterate_phdr` to it. Required for ART-substrate packers (DefineClass driver).
Requires `VARDOGER_ART_CLASSLINKER`.

---

### `art_bringup() → dict`

Return the Strategy-A ART bring-up pointers populated by `map_art`:

```python
ptrs = vm.art_bringup()
# {"art_bias", "runtime", "thread", "class_linker", "heap",
#  "linear_alloc", "intern_table", "class_linker_off"}
```

All values are 0 if `VARDOGER_ART_CLASSLINKER` was not set.

---

### `art_register_dex(dex, location="base.apk") → int`

Make `dex` resident in guest memory as a real `art::DexFile` and return its Java
`DexFile` handle. Used with class-load-decrypt packers that follow the cookie to the
trailing encrypted payload. Requires `VARDOGER_ART`.

---

### `run_lifecycle(dex, class_desc, app=0, ctx=0)`

Run the packer stub's Java lifecycle through the Dalvik interpreter:
`attachBaseContext` → `onCreate`. The stub's OWN bytecode drives the natives, so
class-load decrypt fires in the correct order.

| Parameter | Description |
|---|---|
| `dex` | The app's `classes.dex` (stub with encrypted payload appended). |
| `class_desc` | DEX descriptor of the stub app class, e.g. `"Lcom/stub/StubApp;"`. |
| `app` | Optional Application object handle (0 = use built-in). |
| `ctx` | Optional Context handle (0 = use built-in). |

Raises `VardogerError` on interpreter error.

---

### `close()`

Free the guest address space. Called automatically by `__del__` and `__exit__`.

---

## Environment

### `serve_apk(host_path, guest_path=None) → bytes`

Serve an APK from disk at the guest APK path (defaults to `vm.apk_path`). Also
unpacks every `assets/*` entry into the VFS so the NDK `AAsset` API resolves them.
Returns the raw APK bytes.

---

### `vfs_add(guest_path, data)`

Serve arbitrary `data` at a guest path. The guest's `open()` / `read()` will find it.

---

### `set_property(key, value)`

Override a system property the guest reads via `__system_property_get`.

---

### `set_progname(name)`

Set the guest process name (`__progname` / `getprogname()` / `/proc/self/cmdline`).
Some RASP (LIApp) gate self-decrypt on this matching the package — call **before**
`load()` since the name is resolved at relocation time.

Equivalent to `VARDOGER_PROGNAME`.

---

### `set_signing_cert(der)`

Set the app's signing certificate DER (what `Signature.toByteArray()` returns).
Most Chinese packers and RASP derive keys from it or validate it.
Call before driving any code that reads the signature.

---

### `set_now_unix(t)`

Pin the wall-clock time the guest reads via `time()` / `gettimeofday` /
`clock_gettime(CLOCK_REALTIME)` — e.g. to sit inside a packer's license window.

---

## Properties (read-only)

| Property | Type | Description |
|---|---|---|
| `apk_path` | `str` | Realistic randomized guest APK path used by `serve_apk` and returned by `getPackageCodePath()`. |
| `data_dir` | `str` | App data dir (`/data/user/0/<pkg>/files`). |
| `native_lib_dir` | `str` | Native library dir (`.../<pkg>-<rand>/lib/arm64`). |
| `jni_env` | `int` | Guest `JNIEnv*` pointer. |
| `java_vm` | `int` | Guest `JavaVM*` pointer. Pass as first arg to `JNI_OnLoad`. |
| `application` | `int` | Guest `Application` object handle. |
| `context` | `int` | Guest `Context` object handle. |

---

## Memory

### `read(addr, n) → bytes`

Read `n` bytes from guest address `addr`.

### `write(addr, data)`

Write `data` bytes to guest address `addr`.

### `read_u64(addr) → int`

Read a little-endian 64-bit value.

### `write_u64(addr, v)`

Write a little-endian 64-bit value.

### `read_cstr(addr, cap=4096) → str`

Read a null-terminated C string from guest memory.

### `heap_alloc(n) → int`

Allocate `n` bytes of guest heap; return the guest address.

### `is_mapped(addr) → bool`

True if `addr` falls in a mapped region.

### `describe(addr) → str`

Human-readable description of the region containing `addr` (SO name + offset, or "heap", etc.).

### `regions() → list[Region]`

All currently mapped guest regions.

---

## Registers

```python
from vardoger import Reg

x0 = vm.reg(Reg.X0)
vm.set_reg(Reg.X0, 0x1234)
```

### `reg(uc_reg_id) → int`

Read a register by Unicorn register id. Use `Reg.*` constants.

### `set_reg(uc_reg_id, v)`

Write a register.

---

## Strings & search

### `search_strings(needle="", min_len=4) → list[FoundString]`

Scan guest heap/mmap/lib regions for printable-ASCII runs of at least `min_len` bytes.
If `needle` is non-empty, only runs containing it are returned.

---

## Module

```python
@dataclass
class Module:
    index:      int   # internal library index
    path:       str   # host path passed to load()
    bias:       int   # load bias; add to file vaddr to get guest address
    size:       int   # mapped span in bytes
    jni_onload: int   # guest address of JNI_OnLoad, or 0
    init:       int   # guest address of DT_INIT, or 0
```

### `Module.lookup(symbol) → int`

Return the guest address of an exported symbol, or 0.

### `Module.init_array → list[int]`

Guest addresses of every `.init_array` entry.
