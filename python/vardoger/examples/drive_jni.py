#!/usr/bin/env python3
"""Minimal example: load a native .so, run its lifecycle, list what it registered.

Usage:  python3 python/vardoger/examples/drive_jni.py <lib.so> [base.apk] [package]
"""

import sys
from vardoger import VM, Reg

so_path = sys.argv[1]
apk = sys.argv[2] if len(sys.argv) > 2 else None
pkg = sys.argv[3] if len(sys.argv) > 3 else "com.victim.app"

vm = VM(package=pkg, sdk=31)
if apk:
    vm.vfs_add(f"/data/app/~~pk==/{pkg}-1/base.apk", open(apk, "rb").read())

so = vm.load(so_path)
print(
    f"loaded {so_path}: bias={so.bias:#x} size={so.size:#x} jni_onload={so.jni_onload:#x}"
)
print(f"init_array: {[hex(x) for x in so.init_array]}")

vm.run_init(so)  # DT_INIT + .init_array (self-decrypt happens here)
if so.jni_onload:
    print(f"JNI_OnLoad -> {vm.call(so.jni_onload, [vm.java_vm, 0]):#x}")

print("\nRegisterNatives'd methods:")
for n in vm.registered_natives():
    print(f"  {n.cls}.{n.name}{n.sig} -> {n.fn:#x}")

print("\nmemory regions:")
for r in vm.regions():
    print(f"  {r.base:#014x}-{r.base + r.size:#014x} prot={r.prot} {r.label}")

dexes = vm.scan_dex()
print(f"\nDEX blobs in memory: {len(dexes)} ({[len(d) for d in dexes]} bytes)")
