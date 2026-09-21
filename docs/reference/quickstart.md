# Quick Start

## Minimal example — run JNI_OnLoad and capture DEX

```python
from vardoger import VM, Reg

# 1. Create the runtime.
vm = VM(package="com.example.app", sdk=31)

# 2. Serve the APK so the packer can open its own file.
vm.serve_apk("base.apk")

# 3. Load the packer's native library (relocations run, no init yet).
so = vm.load("lib/arm64-v8a/libpacker.so")

# 4. Run DT_INIT + .init_array (self-decryption of .text happens here).
vm.run_init(so)

# 5. Call JNI_OnLoad through the scheduler (blocking threads OK).
vm.call(so.jni_onload, [vm.java_vm, 0])

# 6. Scan memory for any DEX that appeared.
for dex in vm.scan_dex():
    print(f"found {len(dex):,} byte DEX with magic {dex[:8]}")
    open("recovered.dex", "wb").write(dex)
```

---

## Trace every instruction

```python
@vm.on_code
def _(pc, size):
    print(f"{pc:#x}")
```

---

## Implement a missing Java method in Python

```python
# The packer calls Context.getPackageName() — implement it.
def get_package_name(self_h, args):
    return vm.new_string("com.example.app")

vm.register_method("android/content/Context#getPackageName",
                   get_package_name, returns_object=True)
```

---

## Capture from a write-back slot (trampoline)

```python
slot_addr = so.bias + 0x1234  # fn-ptr the packer writes decrypted DEX into

def capture():
    base = vm.reg(Reg.X0)
    size = vm.reg(Reg.X1)
    open("out.dex", "wb").write(vm.read(base, size))

vm.write_u64(slot_addr, vm.alloc_trampoline(capture, "dex_callback"))
vm.call(so.jni_onload, [vm.java_vm, 0])
```

---

## ART-mode class-load decrypt (DEX observer)

Some packers (dpt-shell, some Jiagu variants) decrypt each class at load time via
`DefineClass`. Enable the ART substrate:

```bash
export VARDOGER_ART=1
export VARDOGER_ART_CLASSLINKER=1
```

```python
vm = VM(package="com.example.app")

collected = []

def on_dex(dex_bytes, source):
    print(f"[dex] {len(dex_bytes):,} bytes from {source}")
    collected.append(dex_bytes)

vm.set_dex_observer(on_dex)
vm.map_art("/path/to/libart-arm64.so")
vm.serve_apk("base.apk")
so = vm.load("libstub.so")
vm.run_init(so)
vm.call(so.jni_onload, [vm.java_vm, 0])
```

---

## Dalvik lifecycle decrypt

For packers whose stub is implemented as a Java `Application` subclass:

```python
vm = VM(package="com.example.app")
vm.set_signing_cert(open("META-INF/CERT.RSA", "rb").read())
vm.serve_apk("base.apk")
so = vm.load("libstub.so")
vm.run_init(so)
vm.call(so.jni_onload, [vm.java_vm, 0])

# classes.dex is the stub APK's classes.dex with the encrypted payload appended.
dex = open("classes.dex", "rb").read()
vm.run_lifecycle(dex, "Lcom/example/StubApp;")

for dex in vm.scan_dex():
    open("recovered.dex", "wb").write(dex)
```

---

## Attach a debugger

```python
so = vm.load("lib.so")
vm.run_init(so)

vm.gdb_listen(1234)   # blocks until client connects and continues

vm.call(so.jni_onload, [vm.java_vm, 0])
```

In another terminal:

```
lldb -o "gdb-remote 1234"
# or: gdb-multiarch -ex "target remote :1234"
```
