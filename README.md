# vardøger

vardøger (amed from Norse mythology of what is basically a phantom double)  is a faithful-enough Android runtime for ARM64, built on the Unicorn emulator, runs native `.so`
code the way it would run on a device but with no device in the loop. It loads an ELF, resolves its
relocations, runs `DT_INIT` and `.init_array`, and drives `JNI_OnLoad` and individual functions
through a cooperative scheduler. Around the CPU it provides the pieces guest code expects: a memory
manager with a fixed address-space layout, libc and syscall stubs, a JNI 1.6 bridge with an Android
context graph, a small DEX parser and Dalvik interpreter, and hooks that let you observe execution and actually be able
perform some action like DEX dumping. 

The engine is written in C++ with a flat C ABI (`libvardoger_capi.so`) that exposes it, and the `vardoger` Python package
that drives that ABI through `ctypes`, so you can script the whole runtime from Python without building
against `Python.h`.

This was used privately for a while, but is part of publically releasing code to better aid in Android reversing.
See https://github.com/Isaac-GC/project-platypus for the DEX/Smali and UI tools 

(DO NOT use this for Flutter, Unity, Cocos, or whatever else. It may work, but there are too many intracices in those
complex frameworks to sanely implement here)

## What it is for

To emulate an Android system without actually being an Android device
or stupidly large (multiple GB) analysis system. Sometimes you just need a harness and
to analyze things in a simple way. It is deliberately general (load, drive, hook, read/write, capture), so the same interface serves a range
of tasks rather than any one target.

## Build

You need CMake (3.24+), a C++20 compiler, and the development packages for Unicorn, Capstone, and
zlib.

```bash
# Debian/Ubuntu:  sudo apt-get install libunicorn-dev libcapstone-dev zlib1g-dev
# macOS:          brew install unicorn capstone zlib
cmake -S . -B build -G Ninja
cmake --build build            # -> build/libvardoger_capi.so
```

## Usage

### Python
```bash
pip install .                  # builds the native library and installs the vardoger package
```

```python
from vardoger import VM, Reg

vm = VM(package="com.foo.bar", sdk=31)
vm.serve_apk("base.apk")
so = vm.load("lib.so")
vm.run_init(so)                                # DT_INIT + .init_array
vm.call(so.jni_onload, [vm.java_vm, 0])        # -> 0x10006 on success
for dex in vm.scan_dex(): ...                  # DEX pulled from memory
```

See [python/vardoger/README.md](python/vardoger/README.md) for the full Python API and more examples.

### Debugging with lldb / gdb (and Binary Ninja / IDA)

The runtime hosts a GDB Remote Serial Protocol server, so any RSP client — lldb (the
macOS-native debugger), gdb-multiarch, or the debuggers built into Binary Ninja and IDA — can
attach to the emulated ARM64 CPU and set breakpoints, single-step, and read/write registers and
guest memory, while vardoger keeps providing the Android surface underneath.

```python
vm = VM(package="com.foo.bar", sdk=31)
vm.serve_apk("base.apk")
so = vm.load("lib.so")
vm.run_init(so)
vm.gdb_listen(1234)                              # blocks until a debugger attaches + continues
vm.call(so.jni_onload, [vm.java_vm, 0])          # now runs under the debugger
```

```bash
# in another terminal — lldb:
lldb -o "gdb-remote 127.0.0.1:1234"
# or gdb:  (gdb) target remote :1234
```

The full ARM64 register file is exposed — `x0`–`x30`, `sp`, `pc`, `cpsr`, the 128-bit SIMD/FP
registers `v0`–`v31`, and `fpsr`/`fpcr` — so `register read` and vector inspection work. Breakpoints
are tracked host-side (no `BRK` patched into guest memory), so stepping works even on freshly
self-decrypted / execute-only pages. The listener binds `127.0.0.1` only.

### Monitoring build properties and syscalls

Observe exactly which device fingerprints a packer probes and which raw syscalls it issues to
bypass libc hooks:

```python
vm.set_property_observer(lambda name, value: print(f"prop {name} -> {value!r}"))
vm.set_syscall_observer(lambda nr, name, args, ret: print(f"svc {name}({args[0]:#x}) = {ret}"))
```

`set_property_observer` fires on every `__system_property_get` (`ro.build.*`, `ro.debuggable`,
`ro.product.model`, …); `set_syscall_observer` fires on every `SVC` with the mnemonic, the six
argument registers, and the return value (ptrace anti-debug probes, `getrandom`, `mprotect` W^X
flips, `openat` of `/proc`, …).

### Install paths

Each VM gets a realistic randomized install path, exactly as the Android `PackageManager` lays one
out for the package + API level — `/data/app/~~<base64url>/<pkg>-<base64url>/base.apk` on API 30+,
the `<pkg>-<base64url>` suffix on API 26–29, `<pkg>-1` below that. The `~~`/suffix tokens are stable
per package (so runs are reproducible) but look like real device tokens. The code, `lib/`, and
`/data/user/0/<pkg>` directories are registered so a packer that `access()`/`stat()`s them finds
them present, and `serve_apk()` serves the APK at that real path (what `getPackageCodePath()`
returns).

```python
vm = VM(package="com.foo.bar", sdk=31)
vm.apk_path          # /data/app/~~5xSo81c4QwL3j0Vw9wMz2w/com.foo.bar-89Cv5G39stefHG-UWUETNQ/base.apk
vm.native_lib_dir    # .../com.foo.bar-89Cv5G39stefHG-UWUETNQ/lib/arm64
vm.serve_apk("base.apk")   # served at vm.apk_path
```

## Layout

```
core/          
  engine/      CPU, memory, scheduling, trampolines, tracing
  elf/         elf loader
  android/     libc stubs, syscalls, the VFS, system properties, the context graph, and whatever else android
  jni/         the JNI bridge and Java runtime
  dex/         DEX parser, mini-Dalvik interpreter, lifecycle
  art/         the ART class-resolution substrate and bring-up
  extract/     payload capture and debug hooks
  py/          the flat C ABI (vardoger_capi)
include/vardoger/  public headers, mirroring core/
python/vardoger/    the ctypes package and examples
```

## License

GNU Lesser General Public License v3.0. The LGPL terms are in
[COPYING.LESSER](COPYING.LESSER), which builds on the GPL terms in [COPYING](COPYING).
