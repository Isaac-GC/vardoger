# Hooks & Trampolines

## Code hook

```python
@vm.on_code
def trace(pc: int, size: int):
    print(f"{pc:#x}  ({size} bytes)")
```

### `on_code(fn)` → decorator / direct call

Register a per-instruction hook. `fn(pc, size)` fires before every ARM64 instruction
that executes. Usable as a decorator or called directly:

```python
vm.on_code(lambda pc, sz: ...)
```

!!! warning "Performance"
    Per-instruction hooks are slow. For targeted tracing use `VARDOGER_ITRACE` or
    `VARDOGER_TRACEPC` instead.

---

## Unmapped-access hook

```python
@vm.on_unmapped
def handle(access_type: int, addr: int) -> bool:
    # Map the page and return True to retry, or return False to abort.
    vm.write(addr & ~0xFFF, b"\x00" * 0x1000)
    return True
```

### `on_unmapped(fn)` → decorator

`fn(access_type, addr) -> bool`. Return `True` to retry the faulting instruction,
`False` to propagate the fault. Used to lazily map pages a packer expects.

---

## Memory write hook

```python
vm.add_mem_write_hook(
    lambda addr, size, value: print(f"WRITE {addr:#x} {size}B = {value:#x}"),
    lo=so.bias,
    hi=so.bias + so.size,
)
```

### `add_mem_write_hook(fn, lo=1, hi=0)`

Call `fn(addr, size, value)` on every guest memory write in `[lo, hi]`.
`hi=0` means all addresses.

---

## Memory read hook

```python
vm.add_mem_read_hook(
    lambda addr, size, _: print(f"READ {addr:#x}"),
    lo=target_base,
    hi=target_base + target_size,
)
```

### `add_mem_read_hook(fn, lo=1, hi=0)`

Call `fn(addr, size, value)` on every guest memory read in `[lo, hi]`.
The `value` parameter is not the loaded data — use `vm.read_u64(addr)` inside
the hook to sample it.

---

## Trampolines

A trampoline is a small guest stub whose body jumps to a Python callable. Use them to
implement missing libc functions, capture callbacks, or intercept fn-pointer tables.

```python
def my_stub():
    # read args
    x0 = vm.reg(Reg.X0)
    x1 = vm.reg(Reg.X1)
    # write return value
    vm.set_reg(Reg.X0, 0)

addr = vm.alloc_trampoline(my_stub, name="my_stub")
```

### `alloc_trampoline(fn, name="py_stub") → int`

Allocate a guest stub whose body calls `fn()` (no arguments — read / write via
`vm.reg` / `vm.set_reg` / `vm.read` / `vm.write`). Returns the guest address.

Store it in any fn-pointer slot the packer will call:

```python
vm.write_u64(slot_va, vm.alloc_trampoline(capture))
```

!!! tip "Lifetime"
    The Python callback is kept alive for the lifetime of the VM. You do not need to
    hold a reference yourself.
