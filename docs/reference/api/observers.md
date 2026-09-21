# Observers

Observers are callbacks fired by the runtime on specific events. They complement
hooks (which are low-level instruction / memory triggers) with higher-level signals.

---

## Property observer

```python
def on_prop(name: str, value: str):
    print(f"getprop({name!r}) -> {value!r}")

vm.set_property_observer(on_prop)
```

### `set_property_observer(fn)`

Called on every `__system_property_get` call the guest makes.
Shows which build properties / device fingerprints a packer probes and the value it
received. Common targets:

| Property | Typical use |
|---|---|
| `ro.debuggable` | Anti-debug gate |
| `ro.build.fingerprint` | Device/emulator check |
| `ro.build.version.sdk` | API-level branching |
| `ro.product.model` | Emulator detection |
| `ro.product.manufacturer` | Emulator detection |

---

## Syscall observer

```python
def on_syscall(nr: int, name: str, args: list[int], ret: int):
    print(f"  SVC {name}({', '.join(hex(a) for a in args)}) = {ret:#x}")

vm.set_syscall_observer(on_syscall)
```

### `set_syscall_observer(fn)`

Called on every raw `SVC` the guest issues. `fn(nr, name, args, ret)`:

- `nr` — syscall number.
- `name` — human-readable name (e.g. `"openat"`).
- `args` — x0–x5 on syscall entry.
- `ret` — x0 after the handler.

Traces direct-syscall activity that bypasses libc hooks: ptrace anti-debug, `getrandom`,
`mprotect` W^X flips, `openat(/proc/...)`, `futex`, etc.

---

## Method observer

```python
def on_method(owner: str, name: str, sig: str,
              args: list[int], handled: bool):
    print(f"  JNI -> {owner}#{name}{sig}  handled={handled}")

vm.set_method_observer(on_method)
```

### `set_method_observer(fn)`

Called on every Java method the guest invokes via JNI. `fn(owner, name, sig, args, handled)`:

- `owner` — slash-form class, e.g. `"java/lang/Class"`.
- `name` — method name.
- `sig` — JNI descriptor, e.g. `"(Ljava/lang/String;)Ljava/lang/Class;"`.
- `args` — argument values (object handles for reference types, raw ints for primitives).
- `handled` — `True` if a `register_method` impl ran; `False` if it fell through.

Pair with `register_method`: observe to discover which methods matter, then implement the
ones you need.
