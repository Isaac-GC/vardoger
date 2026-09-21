# Memory & Mapping

---

## VARDOGER_TCG_BUFFER_MB

**Type:** uint32 (megabytes)  
**Default:** `256`

Size of the Unicorn TCG translation buffer in megabytes. Larger values allow more
compiled blocks to be cached in memory before eviction; smaller values save RAM.
Set to `0` to keep Unicorn's built-in default.

```bash
export VARDOGER_TCG_BUFFER_MB=512
```

---

## VARDOGER_AUTOMAP

**Type:** boolean  
**Default:** disabled

Automatically map unmapped pages (R/W, 4 KiB) on write or execute faults.
Prevents hard crashes when a packer computes and jumps to a page it forgot to
`mmap` first, or writes into a garbage pointer. The created pages are zeroed.

```bash
export VARDOGER_AUTOMAP=1
```

!!! warning
    This can mask bugs in your environment setup. Use `vm.on_unmapped` for finer
    control if you need to distinguish legitimate faults from configuration gaps.

---

## VARDOGER_LOW_LIB_BASE

**Type:** boolean  
**Default:** disabled

Force the compact low-address band for library mappings even on 64-bit (addresses
below `~0x100000000`). By default the emulator places libraries in a high address
band on ARM64. Enable this when the packer assumes 32-bit-range pointers or encodes
bias offsets in a 32-bit field.

```bash
export VARDOGER_LOW_LIB_BASE=1
```

---

## VARDOGER_HEAP_TIGHT

**Type:** boolean  
**Default:** disabled

Switch the heap allocator to a tight packing strategy. Normally the bump heap grows
conservatively; this toggle enables a denser layout. Useful for packers that measure
heap fragmentation or perform pointer arithmetic on heap addresses.

---

## VARDOGER_NO_MAPFIXED

**Type:** boolean (negated — setting this DISABLES the behavior)  
**Default:** disabled (honors `MAP_FIXED` by default)

When set, the `mmap` stub ignores the `MAP_FIXED` flag and treats all mappings as
non-fixed. Use when a packer requests a fixed mapping at an address that conflicts
with the emulator's internal layout.

```bash
export VARDOGER_NO_MAPFIXED=1
```

---

## VARDOGER_WX

**Type:** boolean  
**Default:** disabled

W^X mode: memory buffers are mapped non-executable by default. Self-decrypting code
that writes to a page and then jumps to it will fault on the execute attempt. This is
used with DT_INIT loaders that decrypt `.text` on non-exec pages — the fault is caught,
the page is made executable, and the payload is extracted before re-running.

```bash
export VARDOGER_WX=1
```
