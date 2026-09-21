# Script Index

All scripts live in `scripts/`. Fully documented scripts have their own page;
the rest are listed here with a one-line description.

## Fully documented

| Script | Description |
|---|---|
| [`unpack_any.py`](unpack_any.md) | Universal router: identify, route, unpack, validate. |
| [`virbox_recover.py`](virbox_recover.md) | Single-pass Virbox DEX recovery (standard + DEX-VMP). |

---

## Virbox

| Script | Description |
|---|---|
| `virbox_capture_vardoger.py` | Low-level Virbox capture (used by unpack_any). |
| `virbox_env.py` | Android runtime fidelity surface for Virbox loaders (reflection, ZipFile, File). |
| `virbox_fork.py` | Fork-watchdog model — patches GOT slots for `fork`/`waitpid`/`kill`/`prctl`. |
| `virbox_splice.py` | Standalone VBPD/SENS/ZSTD capture + code_item splice. |
| `virbox_unpack.py` | Standalone standard-variant Virbox unpack (ART trampoline + memscan). |
| `virbox_batch.py` | Batch runner for Virbox corpus. |
| `virbox_diag.py` | Diagnostic capture with verbose output. |
| `virbox_triage.py` | Fast corpus triage — identify and filter. |
| `virbox_prune.py` | Prune old output files on a schedule. |
| `virbox_report.py` | Summarize batch results. |
| `virbox_body_check.py` | Validate code_item bodies in recovered DEX. |
| `virbox_verify_dex.py` | Structural DEX verification. |

---

## Jiagu (NetEase)

| Script | Description |
|---|---|
| `jiagu_classic.py` | Classic Jiagu unpack driver. |
| `jiagu_sdk_standalone.py` | Jiagu SDK (token-protected) unpack driver. |
| `jiagu_vardoger.py` | Jiagu vardoger harness. |
| `jiagu_dump_keys.py` | Extract Jiagu class encryption keys. |
| `jiagu_vm_semprobe.py` | Semantic probe for Jiagu VMP opcode shapes. |
| `jiagu_vm_solve.py` | Solve Jiagu VMP dispatch from probed semantics. |
| `jiagu_devirt_emit.py` | Emit devirtualized DEX from solved VMP. |
| `jiagu_block_analyze.py` | Basic-block analysis for Jiagu VMP. |
| `jiagu_k1.py` | K1 region extraction for Jiagu. |
| `jiagu_key_recover.py` | Key recovery pass. |
| `jiagu_cake_recon.py` | Cake obfuscation reconnaissance. |

---

## Ijiami

| Script | Description |
|---|---|
| `ijiami_classic.py` | Classic Ijiami (static unpack). |
| `ijiami_abcd.py` | ABCD-variant unpack. |
| `ijiami_abcd_static.py` | ABCD static decryption. |
| `ijiami_makekey.py` | Key derivation for ABCD. |
| `ijiami_unpack.py` | Generic Ijiami unpack harness. |
| `ijiami_vardoger.py` | vardoger-driven Ijiami path. |
| `ijiami_sp_container.py` | SP container parser. |
| `ijiami_rc4.py` | RC4 operations for Ijiami. |
| `ijiami_generic.py` | Generic (loader-encrypted) Ijiami path. |

---

## DuCEx (NetEase)

| Script | Description |
|---|---|
| `ducex_unpack.py` | DuCEx unpack driver. |
| `ducex_recover.py` | DuCEx recovery (MX + classic). |
| `ducex_decode_bodies.py` | Decode obfuscated method bodies. |
| `ducex_splice.py` | Splice decoded bodies into stub DEX. |
| `ducex_env.py` | DuCEx environment surface. |
| `ducex_harness.py` | Test harness. |
| `ducex_natural_load.py` | Natural load-order driver. |
| `ducex_call_handler.py` | Call handler for DuCEx JNI surface. |
| `ducex_trace_handler.py` | Trace handler. |
| `ducex_trace_installer.py` | Install trace hooks. |
| `ducex_real_hook.py` | Real (non-trampoline) hook setup. |
| `ducex_force_art.py` | Force ART mode for DuCEx. |
| `ducex_fart_dump.py` | FART-style class dump. |
| `ducex_form.py` | Form (format) parsing. |
| `ducex_mxdata.py` | MX data parser. |
| `ducex_ctx_build.py` | Context builder. |
| `ducex_ctx_probe.py` | Context probe. |
| `ducex_module0_index.py` | Module-0 index analysis. |
| `ducex_watch_globals.py` | Watch global variable writes. |
| `ducex_find_glob_writers.py` | Find global-writing instructions. |
| `ducex_verify_hook.py` | Verify hook correctness. |
| `ducex_text_image.py` | Text-section image dump. |

---

## DPT / ACF

| Script | Description |
|---|---|
| `dpt_unpack.py` | DPT unpack driver. |
| `dpt_dex.py` | DPT DEX extraction. |
| `dpt_validate.py` | Validate DPT output. |

---

## Utilities

| Script | Description |
|---|---|
| `unpack_any.py` | Universal router (see [dedicated page](unpack_any.md)). |
| `dump_dex.py` | Dump DEX from a running process (Frida-based). |
| `dump_abcd_keystream.py` | Dump ABCD keystream. |
| `deflate_oracle.py` | Deflate oracle for compressed payload analysis. |
| `dalvik_dis.py` | Minimal Dalvik disassembler. |
| `art_graph.py` | ART pointer graph visualizer. |
| `gen_syscall_table.py` | Generate syscall number table for a given Android version. |
| `openmemory_capture.py` | Standalone `openInMemoryDexFile` hook capture. |
| `manticore_fetch_apks.py` | Fetch APKs from MobSF/Manticore. |
| `manticore_stream_triage.py` | Stream triage results. |
