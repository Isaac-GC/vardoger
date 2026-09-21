# I/O Logging

These variables enable logging of filesystem, dynamic-linker, and compression
operations without needing Python hooks.

---

## VARDOGER_OPEN_LOG

**Type:** boolean  
**Default:** disabled

Log every `open()` / `openat()` call the guest makes, including the path and flags.

```bash
export VARDOGER_OPEN_LOG=1
```

---

## VARDOGER_OPEN_LR

**Type:** boolean  
**Default:** disabled

Log `open("")` (empty-path) calls and the calling LR. Used to identify code that
opens its own `.so` by looking it up via the empty-path resolver trick.

---

## VARDOGER_READ_LOG

**Type:** boolean  
**Default:** disabled

Log every `read()` syscall: fd, count, and return value.

```bash
export VARDOGER_READ_LOG=1
```

---

## VARDOGER_LSEEK_LOG

**Type:** boolean  
**Default:** disabled

Log every `lseek()` syscall: fd, offset, whence, and return value.

---

## VARDOGER_LSEEK0

**Type:** boolean  
**Default:** disabled

Force `lseek()` to return position 0 on certain paths. Used when a packer seeks to
the file end to measure its size but the emulated size diverges from what it expects.

---

## VARDOGER_DL_LOG

**Type:** boolean  
**Default:** disabled

Log every `dlopen()`, `dlmopen()`, and `dlsym()` call with the requested name /
symbol and the returned handle or address.

```bash
export VARDOGER_DL_LOG=1
```

---

## VARDOGER_DLOPEN_FAIL

**Type:** string (comma-separated substrings)  
**Default:** none

Force `dlopen(name)` to return `NULL` for any library whose name contains one of the
listed substrings. Useful for selectively blocking libraries the packer loads as part
of its integrity check (e.g. block Frida's `frida-agent.so`).

```bash
export VARDOGER_DLOPEN_FAIL=frida,xposed
```

---

## VARDOGER_MMAP_LOG

**Type:** boolean  
**Default:** disabled

Log every `mmap()` call: address hint, length, prot flags, map flags, fd, offset,
and the returned address.

```bash
export VARDOGER_MMAP_LOG=1
```

---

## VARDOGER_PROP_LOG

**Type:** boolean  
**Default:** disabled

Log every system property access (`__system_property_get`): key and the value
returned. See also `vm.set_property_observer()` for the Python equivalent.

---

## VARDOGER_TIME_LOG

**Type:** boolean  
**Default:** disabled

Log every `clock_gettime()` syscall — clock id, returned seconds and nanoseconds.

---

## VARDOGER_ZLIB_LOG

**Type:** boolean  
**Default:** disabled

Log every `inflateInit` / `inflate` / `inflateEnd` call sequence: input length,
output length, and return code.

---

## VARDOGER_ZLIB_DUMP

**Type:** string (directory path)  
**Default:** none

Dump the output of every successful `inflate()` call to `<dir>/inflate_NN.bin`.

```bash
export VARDOGER_ZLIB_DUMP=/tmp/zlib_out
```

---

## VARDOGER_INFLATE_DUMP

**Type:** string (file path)  
**Default:** none

Append the inflate **INPUT** (post-cipher, pre-decompression) to the given file.
Use when the packer decrypts data then immediately feeds it to `inflate` — this
captures the ciphertext stream for offline analysis.

```bash
export VARDOGER_INFLATE_DUMP=/tmp/inflate_input.bin
```

---

## VARDOGER_STR_LOG

**Type:** boolean  
**Default:** disabled

Log libc string operations (`strlen`, `strcmp`, `strncmp`, etc.) for strings of
4 bytes or more. Shows every string comparison the native code makes — useful for
finding where the packer checks a key, cert hash, or package name.

```bash
export VARDOGER_STR_LOG=1
```
