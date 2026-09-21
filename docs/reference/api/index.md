# Python API — Overview

The Python API is a thin ctypes wrapper around `libvardoger_capi`. Every call goes to the
C ABI shared library; no C++ headers or pybind11 are involved.

```python
from vardoger import VM, Reg, Module, Region, Native, FoundString, VardogerError
```

## Class hierarchy

| Class | Purpose |
|---|---|
| [`VM`](vm.md) | Main runtime handle. Create one per session. |
| [`Module`](vm.md#module) | A loaded `.so` — bias, size, JNI_OnLoad address, symbol lookup. |
| [`Region`](types.md) | A mapped guest memory region (base, size, prot, label). |
| [`Native`](types.md) | A `RegisterNatives` entry (class, name, sig, fn address). |
| [`FoundString`](types.md) | A string found by `search_strings` (addr, text, region). |
| [`Reg`](types.md) | ARM64 register id constants (X0–X28, FP, LR, SP, PC). |
| `VardogerError` | Exception raised on any VM error. |

## Typical call order

```
VM()                  # allocate runtime
  serve_apk()         # populate VFS
  set_signing_cert()  # RASP cert check
  set_progname()      # RASP name check
  load()              # ELF load + relocations
    register_method() # stub missing Java methods
    set_dex_observer()# wire up capture
  run_init()          # DT_INIT + .init_array
  call(jni_onload)    # drive initialization
  scan_dex()          # harvest captures
  close()             # free runtime
```
