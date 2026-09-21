# vardoger

**vardoger** is a faithful Android ARM64 emulation runtime for unpacking and analyzing
protected APKs on macOS and Linux — no Android device or emulator needed.

It loads native `.so` files into a self-contained emulated environment that replicates
the ART/Dalvik layer, Android system properties, the VFS, JNI, and libc, running all
packer initialization code natively against the ARM64 JIT (via Unicorn) so decryption
happens exactly as it would on a real device.

---

## What it does

| Capability | Details |
|---|---|
| **ELF loading** | Relocations, GOT patching, DT_INIT / .init_array, registered natives |
| **JNI surface** | Faithful JNI env, FindClass, RegisterNatives, reflection hooks |
| **ART integration** | Optional real libart.so mapping, DefineClass driver, DEX observer |
| **Dalvik interpreter** | Run stub Application lifecycle bytecode to trigger class-load decrypt |
| **VFS** | Serve APK, assets, and arbitrary guest paths from Python |
| **DEX capture** | Memory scan + ART open hook + byte[] observer |
| **Python scripting** | Full memory/register read-write, hooks, trampolines, method registration |
| **GDB server** | RSP server on any port; attach lldb / gdb-multiarch / IDA |

---

## Packages

```
pip install vardoger-vm      # PyPI distribution name
import vardoger              # import name
```

The package requires Python ≥ 3.10 and ships a pre-built `libvardoger_capi` for
Linux x86-64 and macOS (arm64 / x86-64).

---

## License

LGPL-3.0-only.
