# vardoger: drive the vardoger Android runtime from Python

A generic Python (3.10+) interface to **vardoger**. Load a packer or native `.so` into the emulated
Android runtime and drive it yourself: configure the environment, run init / JNI_OnLoad / arbitrary
functions, read and write memory and registers, hook code and memory, allocate trampolines (so you
can implement libc/JNI stubs and capture hooks *in Python*), register Java methods, and capture DEX.
It is packer-agnostic and exposes the same primitives the C++ core uses, for scripting.

The backend is the C-ABI shared library `libvardoger_capi.so`, driven through `ctypes`, so there is no
pybind11 or `Python.h` to build against.

## Build

```bash
cmake -S . -B build -G Ninja       # once
cmake --build build                # builds build/libvardoger_capi.so
```

The package finds the library automatically next to the installed module or in a local `build/`
tree. You can also point `$VARDOGER_CAPI` straight at it.

## Use

```bash
pip install .                      # or: PYTHONPATH=python python3 -c "from vardoger import VM"
```

```python
from vardoger import VM, Reg

vm = VM(package="com.foo.bar", sdk=31)
vm.serve_apk("base.apk")                      # Serve the APK where the loader looks for it.

so = vm.load("lib.so")                        # -> Module(bias, jni_onload, size, init_array, lookup)
vm.run_init(so)                               # DT_INIT + .init_array, where a packer self-decrypts.
ver = vm.call(so.jni_onload, [vm.java_vm, 0]) # Returns 0x10006 on success.

# Inspect.
for n in vm.registered_natives(): print(n.cls, n.name, hex(n.fn))
for r in vm.regions(): print(hex(r.base), r.label)
for dex in vm.scan_dex(): ...                 # DEX blobs pulled from memory.

# Read and write.
data = vm.read(addr, 0x100); vm.write(addr, b"...")
vm.write_u64(slot, value); x0 = vm.reg(Reg.X0); vm.set_reg(Reg.X0, 0)

# Hooks.
@vm.on_code
def trace(pc, size): ...
vm.add_mem_write_hook(lambda a, s, v: ..., lo=0x1000, hi=0x2000)

# Implement a stub or capture hook in Python.
def my_stub():
    base, n = vm.reg(Reg.X0), vm.reg(Reg.X1)
    open("out.bin", "wb").write(vm.read(base, n))
    vm.set_reg(Reg.X0, vm.heap_alloc(0x10))   # Return a fake non-null pointer.
tramp = vm.alloc_trampoline(my_stub)
vm.write_u64(some_fnptr_slot, tramp)          # The guest now calls your Python code.

# Implement a Java method in Python.
def get_entry(self_h, args):
    ze = vm.new_object("java/util/zip/ZipEntry")
    vm.set_field(ze, "__name", args[0])
    return ze
vm.register_method("getEntry", get_entry, returns_object=True)

# Map a real libart so a packer that hooks or scans ART internals resolves them.
vm.map_art("/path/to/libart_api31")
```

## API surface (`VM`)

| Area | methods |
|---|---|
| lifecycle | `load`, `map_art`, `run_init`, `call`, `close` (context manager) |
| environment | `set_property`, `vfs_add`, `serve_apk`, `jni_env`, `java_vm`, `application`, `context` |
| memory/regs | `read`, `write`, `read_u64`, `write_u64`, `reg`, `set_reg`, `read_cstr`, `describe`, `is_mapped`, `regions`, `heap_alloc` |
| hooks | `on_code`, `on_unmapped`, `add_mem_write_hook`, `alloc_trampoline` |
| Java | `new_string`, `find_class`, `string_of`, `new_object`, `get_field`, `set_field`, `array_length`, `array_read`, `array_write`, `object_array_element`, `register_method` |
| capture | `scan_dex`, `set_dex_observer`, `registered_natives` |

Some libc-stub behaviors are read from the environment at call time, so they work through the
bindings too. For example, `VARDOGER_EXIT_NOOP=1` and `VARDOGER_ABORT_NOOP=1` neutralise a packer's
anti-debug `exit(88)` / `abort()`, and `VARDOGER_QUIET=1` silences logging.

## Examples

- `examples/drive_jni.py`: load a `.so`, run init and JNI_OnLoad, then list the registered natives,
  memory regions, and any DEX found in memory.
- `examples/art_bringup_probe.py`: map a real `libart.so` and probe the ART bring-up path, checking
  that `Thread::Current()` resolves the way it does on a device.

```bash
python3 python/vardoger/examples/drive_jni.py path/to/lib.so
```

Subnote: Yes, this python stubs/integration with vardoger vm/engine was generated with LLM
