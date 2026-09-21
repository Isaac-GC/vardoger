# Capture

## scan_dex() → list[bytes]

```python
for dex in vm.scan_dex():
    print(f"{len(dex):,} bytes, {dex[:8]}")
```

Scan every mapped guest region for DEX magic (`dex\n`) and return each candidate as
bytes. Runs synchronously after any guest execution.

!!! tip
    For packers that decrypt inline and never leave a coherent DEX in memory for long,
    prefer `set_dex_observer` (fired at the byte[]/ClassLoader boundary) or
    `VARDOGER_ART` (hooked at `openInMemoryDexFile`).

---

## set_dex_observer(fn)

```python
def on_dex(dex_bytes: bytes, source: str):
    print(f"[dex] {len(dex_bytes):,}B from {source}")
    open("out.dex", "wb").write(dex_bytes)

vm.set_dex_observer(on_dex)
```

Register `fn(dex_bytes, source)` to be called whenever DEX-looking bytes cross the
`byte[]` / `ClassLoader` JNI boundary. Fires at the earliest point the runtime sees
a complete DEX buffer.

`source` is a human-readable label (method name or ART hook point).

Requires `VARDOGER_ART` to capture via the `openInMemoryDexFile` / `DefineClass` path.

---

## registered_natives() → list[Native]

```python
for n in vm.registered_natives():
    print(f"{n.cls}.{n.name}{n.sig}  @{n.fn:#x}")
```

Return every method registered via `RegisterNatives`. Each entry is a `Native`:

```python
@dataclass
class Native:
    cls:  str   # "com/example/Stub"
    name: str   # "decrypt"
    sig:  str   # "(Ljava/lang/String;)[B"
    fn:   int   # guest address
```

---

## search_strings(needle="", min_len=4) → list[FoundString]

```python
hits = vm.search_strings("amazonaws.com", min_len=8)
for h in hits:
    print(f"{h.addr:#x}  [{h.region}]  {h.text!r}")
```

Scan heap/mmap/lib regions for printable-ASCII runs. If `needle` is non-empty, only
runs containing it are returned. Useful for hunting decrypted URLs, class names, or
license strings.

```python
@dataclass
class FoundString:
    addr:   int   # guest address
    text:   str   # printable run
    region: str   # mapping label (heap, mmap, SO name, ...)
```
