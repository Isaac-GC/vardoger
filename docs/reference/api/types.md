# Data Types

## Reg

ARM64 register id constants (Unicorn `UC_ARM64_REG_*` values).

```python
from vardoger import Reg

vm.reg(Reg.X0)      # read
vm.set_reg(Reg.X1, 42)  # write
```

| Constant | Description |
|---|---|
| `Reg.X[0]`–`Reg.X[28]` | General-purpose registers X0–X28 (tuple indexed). |
| `Reg.X0`–`Reg.X8` | Individual aliases X0–X8. |
| `Reg.X19`–`Reg.X28` | Callee-saved aliases. |
| `Reg.FP` / `Reg.X29` | Frame pointer. |
| `Reg.LR` / `Reg.X30` | Link register (return address). |
| `Reg.SP` | Stack pointer. |
| `Reg.PC` | Program counter. |

---

## Module

Returned by `VM.load()`.

```python
@dataclass
class Module:
    index:      int   # internal library index
    path:       str   # host-side path passed to load()
    bias:       int   # load bias (add to file VA to get guest VA)
    size:       int   # total mapped span in bytes
    jni_onload: int   # guest address of JNI_OnLoad, or 0
    init:       int   # guest address of DT_INIT, or 0
```

**Methods:**

- `lookup(symbol) → int` — Guest address of an exported symbol (0 if not found).
- `init_array → list[int]` — Guest addresses of every `.init_array` entry.

---

## Region

Returned by `VM.regions()`.

```python
@dataclass
class Region:
    base:  int   # guest start address
    size:  int   # byte length
    prot:  int   # UC_PROT_* bitmask: 1=READ 2=WRITE 4=EXEC
    label: str   # human-readable (SO filename, "heap", "mmap", ...)
```

---

## Native

Returned by `VM.registered_natives()`.

```python
@dataclass
class Native:
    cls:  str   # "com/example/Stub"
    name: str   # "decrypt"
    sig:  str   # "(Ljava/lang/String;)[B"
    fn:   int   # guest address of the native implementation
```

---

## FoundString

Returned by `VM.search_strings()`.

```python
@dataclass
class FoundString:
    addr:   int   # guest address of the first byte
    text:   str   # printable-ASCII run
    region: str   # mapping label the string lives in
```

---

## VardogerError

```python
class VardogerError(RuntimeError): ...
```

Raised by any `VM` method when the underlying C runtime returns an error.
The message comes from `mv_last_error()` and describes what failed.
