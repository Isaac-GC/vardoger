#!/usr/bin/env python3
"""Search guest memory for strings after running a packer's self-decrypt.

Loads a native .so, runs its init + JNI_OnLoad (where a packer typically decrypts
its payload into fresh memory), then greps that memory for a marker string and
prints each hit with its guest address and the region it lives in. Handy for
locating a decrypted class name, C2 URL, or license blob the moment it appears.

Usage:  python3 python/vardoger/examples/search_strings.py <lib.so> [needle]

  # every printable string >= 6 bytes:
  python3 .../search_strings.py libfoo.so
  # only strings containing "http":
  python3 .../search_strings.py libfoo.so http
"""

import sys
from vardoger import VM

so_path = sys.argv[1]
needle = sys.argv[2] if len(sys.argv) > 2 else ""

vm = VM(package="com.victim.app", sdk=31)
so = vm.load(so_path)
vm.run_init(so)  # DT_INIT + .init_array (self-decrypt happens here)
if so.jni_onload:
    vm.call(so.jni_onload, [vm.java_vm, 0])

hits = vm.search_strings(needle=needle, min_len=6)
label = f'containing "{needle}"' if needle else "(all)"
print(f"{len(hits)} strings {label} in guest memory:")
for s in hits[:200]:
    print(f"  {s.addr:#012x}  [{s.region}]  {s.text!r}")
if len(hits) > 200:
    print(f"  ... and {len(hits) - 200} more")
