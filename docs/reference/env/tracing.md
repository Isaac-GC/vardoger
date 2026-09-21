# Tracing & Instrumentation

These variables enable targeted low-level tracing without writing Python hooks.
All addresses are **SO-relative** (offset from the library base) unless noted.

---

## VARDOGER_ITRACE

**Type:** string `"lo:hi"` (hex offsets)  
**Default:** none

Single-step every instruction whose SO-relative PC is in `[lo, hi)` and log
register state. Produces a dense trace — use a tight range.

```bash
export VARDOGER_ITRACE=0x1000:0x2000
```

Output format per instruction:
```
[itrace] 0x7000001234  x0=0xdeadbeef  x1=0x0  ...
```

### VARDOGER_ITRACE_BITPOS

**Type:** boolean  
**Default:** disabled

Append the Dalvik classic-VM decode bit-position to each ITRACE line. Useful when
tracing a Dalvik VMP opcode dispatch to understand the bit-field decode.

### VARDOGER_ITRACE_XWIDE

**Type:** boolean  
**Default:** disabled

In ITRACE output, also dump callee-saved registers (x19–x28) and the dispatch
registers used by the Dalvik interpreter (x25 = dex-pc, etc.).

---

## VARDOGER_PCTRACE

**Type:** string (file path)  
**Default:** none

Write a fast binary PC trace to the given file. Each entry is a SO-relative `u32 LE`.
Much faster than `VARDOGER_ITRACE` — captures every PC without full register dump.

```bash
export VARDOGER_PCTRACE=/tmp/trace.bin
export VARDOGER_PCTRACE_HI=0x80000    # optional upper bound (default 0x60000)
```

### VARDOGER_PCTRACE_HI

**Type:** uint64 (hex)  
**Default:** `0x60000`

Upper bound (SO-relative) for `VARDOGER_PCTRACE`. PCs above this limit are not recorded.

---

## VARDOGER_TRACEPC

**Type:** string `"lo:hi"` or `"addr"` (hex)  
**Default:** none

Log a single line whenever execution reaches an SO-relative address (or range).
Lighter than ITRACE — fires once per entry, not per instruction.

```bash
export VARDOGER_TRACEPC=0x12a4
export VARDOGER_TRACEPC=0x1000:0x1200
```

### VARDOGER_TRACEPC_STACK

**Type:** boolean  
**Default:** disabled

With `VARDOGER_TRACEPC`, also dump `x30` (LR), `sp`, and `[sp+0x38]` (typical saved-LR
slot in the frame). Useful for understanding the call chain at a traced address.

---

## VARDOGER_BT

**Type:** string (hex SO-relative PC)  
**Default:** none

When execution reaches the given SO-relative PC, walk the `x29` frame chain and print
a SO-relative backtrace. Use to understand the call stack at a specific point without
running under a debugger.

```bash
export VARDOGER_BT=0x5678
```

---

## VARDOGER_XWATCH

**Type:** string (comma-separated hex absolute addresses)  
**Default:** none

Log a hit line whenever execution reaches any of the listed **absolute** guest addresses.
Unlike `VARDOGER_TRACEPC` (SO-relative), this works across modules.

```bash
export VARDOGER_XWATCH=0x7000012a4,0x700001300
```

---

## VARDOGER_MEMREAD

**Type:** string `"lo:hi"` (hex SO-relative)  
**Default:** none

Log every memory READ whose PC is in `[so+lo, so+hi)`. Shows what addresses the
code at that PC range is reading from.

```bash
export VARDOGER_MEMREAD=0x1000:0x2000
```

### VARDOGER_MEMREAD_TGT

**Type:** string `"addr:addr"` (hex)  
**Default:** none

Filter `VARDOGER_MEMREAD` output to only reads whose target address is in the given
range. Combined with `VARDOGER_MEMREAD` to see only reads of a specific buffer.

---

## VARDOGER_MEMWRITE_TGT

**Type:** string `"lo:hi"` (hex guest addresses)  
**Default:** none

Capture every write to guest addresses in `[lo, hi)` and log the writing PC, size,
and value. Use to watch a buffer being decrypted in-place.

```bash
export VARDOGER_MEMWRITE_TGT=0x700080000:0x700090000
```

---

## VARDOGER_DEXWRITE

**Type:** boolean  
**Default:** disabled

Hook ALL memory writes and log whenever the DEX magic bytes (`dex\n`) are written.
Fires at the exact moment a DEX header lands in memory — useful for packers that
write the DEX directly rather than handing it to `openInMemoryDexFile`.

```bash
export VARDOGER_DEXWRITE=1
```

---

## VARDOGER_ADDRWATCH

**Type:** string (hex guest address)  
**Default:** none

Log every write landing in `[addr, addr+8)` along with the PC, x0–x5 at the time
of the write. Good for watching a specific slot being overwritten (fn-ptr, key, etc.).

```bash
export VARDOGER_ADDRWATCH=0x700080100
```

---

## VARDOGER_EWRITE_WATCH

**Type:** uint64 (hex guest address)  
**Default:** none

Similar to `VARDOGER_ADDRWATCH` but cached at the engine level for lower overhead.
Fires on the first write to the target address each call.

---

## VARDOGER_WRITEFAULT_SRC

**Type:** boolean  
**Default:** disabled

When a guest write faults (destination is unmapped), peek the SOURCE bytes being
written instead of just logging the fault. Useful for packers that `memcpy` decrypted
payload to an un-mmap'd destination — the source bytes contain the plaintext.

```bash
export VARDOGER_WRITEFAULT_SRC=1
```
