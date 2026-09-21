# Crypto Extraction

These variables target RC4 operations specifically — a common cipher in Android packers.

---

## VARDOGER_KSA_DUMP

**Type:** string (`"auto"` or hex SO-relative PC)  
**Default:** none

At the RC4 KSA (Key Scheduling Algorithm) entry, dump the key argument:
`x0` = key pointer, `x1` = key length, followed by the key bytes in hex.

```bash
export VARDOGER_KSA_DUMP=auto     # auto-detect KSA by pattern
export VARDOGER_KSA_DUMP=0x12a40  # explicit SO-relative PC of KSA entry
```

`auto` scans for a KSA-shaped loop in the loaded SO automatically.

---

## VARDOGER_RC4_FAST

**Type:** boolean  
**Default:** disabled

Intercept emulated RC4 KSA and PRGA with native equivalents. When the guest's
RC4 implementation is identified (requires `VARDOGER_KSA_DUMP` to locate the PCs),
replace the emulated execution with a host-side RC4 call. Dramatically speeds up
decryption-heavy packers that run millions of RC4 rounds in emulation.

```bash
export VARDOGER_KSA_DUMP=auto
export VARDOGER_RC4_FAST=1
```

---

## VARDOGER_RC4_LOG

**Type:** boolean  
**Default:** disabled

Log each RC4 KSA key schedule setup and PRGA output-generation call.
Shows key material and output-stream offsets without dumping to files.

```bash
export VARDOGER_RC4_LOG=1
```

---

## VARDOGER_RC4_DUMP

**Type:** string (directory path)  
**Default:** none

Dump each RC4 PRGA output stream to a file `<dir>/prga_NN.bin`. The index `NN`
increments per PRGA call. Use to capture every keystream a packer generates.

```bash
export VARDOGER_RC4_DUMP=/tmp/rc4_streams
mkdir -p /tmp/rc4_streams
```
