# GDB / LLDB Debugging

vardoger exposes a GDB Remote Serial Protocol server so you can attach any RSP-capable
client and debug the emulated ARM64 core interactively.

---

## Starting the server

```python
so = vm.load("lib.so")
vm.run_init(so)

vm.gdb_listen(1234)   # blocks until client attaches and continues
vm.call(so.jni_onload, [vm.java_vm, 0])
```

### `gdb_listen(port=1234) → bool`

Open a GDB RSP server on `127.0.0.1:<port>` and block until an external debugger
attaches and issues `continue`. Returns `True` once resumed, `False` if the client
disconnected during the handshake. Raises `VardogerError` on socket failure.

---

## Connecting clients

=== "lldb"
    ```
    lldb
    (lldb) gdb-remote 1234
    (lldb) b *0x700012a4          # breakpoint at bias-relative address
    (lldb) c
    ```

=== "gdb-multiarch"
    ```
    gdb-multiarch
    (gdb) set architecture aarch64
    (gdb) target remote :1234
    (gdb) break *0x700012a4
    (gdb) continue
    ```

=== "IDA / Binary Ninja"
    Use the built-in GDB remote target, host `127.0.0.1`, port `1234`.

---

## Status & disconnect

### `gdb_attached → bool`

`True` if a debugger is currently connected.

### `gdb_detach()`

Close the debugger connection and remove the per-instruction hook (restores normal speed).

---

## Workflow example

Set a breakpoint just before the decryption loop, inspect registers, then let it run
to completion and harvest the DEX:

```python
vm.serve_apk("base.apk")
so = vm.load("libpacker.so")
vm.run_init(so)

# Pause here — let the analyst set breakpoints in lldb before initialization runs.
print(f"Attach lldb: gdb-remote 1234  (bias={so.bias:#x})")
vm.gdb_listen(1234)

vm.call(so.jni_onload, [vm.java_vm, 0])

for dex in vm.scan_dex():
    open("recovered.dex", "wb").write(dex)
```
