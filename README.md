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
