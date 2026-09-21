# virbox_recover

Single-pass DEX recovery for Virbox Protector APKs.

```
python3 scripts/virbox_recover.py <sample.apk|.zip|.xapk> [-o outdir] [-v]
```

---

## What it does

Combines the unpack and splice pipelines into one VM run:

| Path | Trigger | Pipeline |
|---|---|---|
| **DEX-VMP** | VBPD magic found in `classes.dex` | Runtime ZSTD frame capture → SENS key derivation → chunk_00 splice into stub DEX |
| **Standard** | No VBPD magic | ART `DexFile::OpenMemory` cache-slot trampoline + heap memscan |

Both pipelines run in a single VM instance; output is deduplicated by SHA-1.

---

## Options

| Flag | Default | Description |
|---|---|---|
| `sample` | (required) | APK, ZIP, or XAPK to recover. |
| `-o, --out OUT` | `./out_vbrecover` | Output directory for recovered DEX files. |
| `-v, --verbose` | off | Print per-stage detail (frame sizes, splice counts, validation scores). |
| `--rounds N` | `4` | Number of JNI drive rounds after `JNI_OnLoad`. More rounds capture methods that decrypt lazily. |
| `--static-only` | off | Skip the runtime VM entirely; try static VBPD decrypt only (fast, low coverage). |

---

## Output naming

```
<stem>.<i>.<N>cls.dex
```

- `<stem>` — APK basename.
- `<i>` — output index (0 = largest class count).
- `<N>cls` — number of class definitions.

---

## Variant details

### Standard variant

1. Loads `lib/arm64-v8a/libvirdoger_a64.so` (or similar).
2. Installs ART `DexFile::OpenMemory` cache-slot trampolines.
3. Drives `JNI_OnLoad` + `--rounds` rounds of registered native calls.
4. Scans heap/mmap for DEX magic after each round.

### DEX-VMP variant

1. Reads VBPD container from `classes.dex` (magic `"VBPD"` at known offset).
2. Parses SENS container from assets (`kqkticwjgzy.dat` or similar) → RC4 key.
3. Attempts static decrypt of VBPD sections (ZSTD decompression).
4. If static decrypt fails, drives `JNI_OnLoad` with fork-watchdog model
   (`fork`/`waitpid`/`kill`/`prctl` GOT slots patched).
5. Scans VM memory for ZSTD frames; decompresses captured frames.
6. Identifies:
   - Section 2 (s2): the 707-class stub DEX.
   - Section 1 (s1): `chunk_00` — the code_item table for VMP'd methods.
7. Splices `chunk_00` into the stub DEX:
   - Appends real code_items (from `chunk_00`) to the DEX.
   - Rebuilds affected `class_data_items` with correct ULEB128 `code_item_off` values.
   - Updates SHA-1 / Adler32 / `file_size` / `data_size` header fields.

---

## Examples

```bash
# Basic recovery
python3 scripts/virbox_recover.py apks/target.apk -o out/

# Verbose mode (shows frame sizes, chunk_00 entries, splice stats)
python3 scripts/virbox_recover.py apks/target.apk -o out/ -v

# More rounds for lazy-decrypt methods
python3 scripts/virbox_recover.py apks/target.apk --rounds 8

# Static only (no VM — fast scan for samples with unencrypted VBPD)
python3 scripts/virbox_recover.py apks/target.apk --static-only
```
