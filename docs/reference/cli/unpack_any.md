# unpack_any

One command to identify, route, and unpack any supported packer family.

```
python3 scripts/unpack_any.py <apk|dir> [options]
```

---

## What it does

`unpack_any.py` is a thin, honest router:

1. **Identify** — classify the packer by ZIP contents (never by directory name).
2. **Route** — dispatch to the family-specific driver if one exists.
3. **Fallback** — run the generic drive-and-capture path if no driver matches.
4. **Validate** — apply strict DEX validation to every emitted file.
5. **Report** — write a CSV with per-sample results.

---

## Options

| Flag | Default | Description |
|---|---|---|
| `targets` | (required) | APK files or directories to process. |
| `-o, --out OUT` | `./out` | Output directory for recovered DEX files. |
| `--family FAMILY` | auto | Force a specific family; skip auto-detection. |
| `--generic-only` | off | Skip family drivers; use the generic drive-and-capture path for all samples. |
| `--identify-only` | off | Classify only — do not unpack, write, or emit CSV. |
| `--jobs N` | `1` | Parallel worker processes. |
| `--report FILE` | none | Write per-sample results to a CSV. |
| `--timeout S` | `420` | Seconds allowed per driver invocation before kill. |
| `--rounds N` | `1` | JNI drive rounds for generic / Virbox paths. |
| `--slice US` | `60000000` | `VARDOGER_SLICE_US` for emulated paths (microseconds). |
| `--generic-loaders N` | `2` | Number of candidate loader `.so` files to try during generic drive. |
| `--devirt` | off | Run method-VMP devirtualization (requires a per-build profile). |
| `--max N` | `0` (all) | Maximum samples to process (0 = all). |
| `--keep-intermediate` | off | Keep merged split bundles in the output tree. |

---

## Supported families

| Family | Decisive marker | Driver |
|---|---|---|
| `ducex:mx` | `assets/mx/mx.data` (magic `mx\x01\x02`) \| `libducex.so` | Generic (init/dl/dla/runOn) |
| `ducex:classic` | `ran\0rcfn\0` in oversized `classes.dex` | Generic + `ducex_decode_bodies --splice` |
| `virbox` | `assets/l<hex>_a64.so` | `virbox_capture_vardoger.py` |
| `jiagu:sdk` | `lib/*/libjiagu_sdk_<tok>Protected.so` | `jiagu_sdk_standalone.py` |
| `jiagu:classic` | `libjiagu*.so` / `assets/libjiagu*` | `jiagu_classic.py` |
| `ijiami:classic` | `assets/ijiami.dat` | `ijiami_classic.py` (static) |
| `ijiami:abcd` | `libabcd.so` / `sp\0\1` container | `ijiami_makekey` + `abcd_static` |
| `dpt/acf` | `libdpt*` / `DexHelper` / `DPT_KEY_DATA` | Generic (skeleton DEX only) |
| `legu` | `lib/*/libshell*.so`, `libtxshell` | Generic |
| `bangcle` | `libSecShell` / `libsecexe` / `libsecmain` | Generic |
| Other | any above not listed | Generic |

---

## Validation rule

A DEX is accepted only if **all** of the following hold:

- `class_defs > 3`
- Zero-byte % in class_def table < 80%
- Zero-byte % in data section < 80%
- ≥ 50% of class names parse as valid `L...;` MUTF-8 descriptors
- Not byte-identical to any DEX already in the APK

`file_size` / `adler32` / `SHA-1` header fields are reported but never used to reject.

---

## Examples

```bash
# Unpack a single APK
python3 scripts/unpack_any.py target.apk -o out/

# Batch with 4 workers and a CSV report
python3 scripts/unpack_any.py apks/ -o out/ --jobs 4 --report results.csv

# Force generic path, 3 rounds
python3 scripts/unpack_any.py target.apk --generic-only --rounds 3

# Just identify, no unpacking
python3 scripts/unpack_any.py apks/ --identify-only
```
