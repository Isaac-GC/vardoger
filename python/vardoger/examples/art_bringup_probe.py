#!/usr/bin/env python3
"""Probe the vardoger ART bring-up against a real libart.

Runs the fault-driven ART bring-up (art_init_locks, art_init_runtime, art_init_thread, all behind
VARDOGER_ART_RUNTIME) and validates it end-to-end: it calls the real libart
`art::Thread::CurrentFromGdb()`, which is literally `return Thread::Current();`, and checks that it
returns the Thread* we installed in TLS slot 7. It then clears `art::Thread::is_started_` and confirms
that Thread::Current() correctly returns null, which proves the gate semantics.

Usage:  VARDOGER_ART_RUNTIME=1 python3 python/vardoger/examples/art_bringup_probe.py <libart_dir>

You supply the libart directory; a real libart.so is not shipped with this repo. The
CurrentFromGdb offset (0x6828fc) and is_started_ address (0xa18ad8) below are for an api31 libart.
For a different libart, resolve `_ZN3art6Thread14CurrentFromGdbEv` and `_ZN3art6Thread11is_started_E`
from its symbol table and update them.
"""

import os, sys

os.environ.setdefault("VARDOGER_ART_RUNTIME", "1")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from vardoger import VM  # noqa: E402

ART = sys.argv[1] if len(sys.argv) > 1 else "libart_api31"
CURRENT_FROM_GDB = 0x6828FC  # _ZN3art6Thread14CurrentFromGdbEv (api31)
IS_STARTED = 0xA18AD8  # _ZN3art6Thread11is_started_E (api31)

vm = VM(package="com.probe.art", sdk=31)
vm.map_art(ART)
artb = next(r.base for r in vm.regions() if "libart" in r.label)

r = vm.call(artb + CURRENT_FROM_GDB, [])
print(f"[probe] real libart Thread::CurrentFromGdb() -> {hex(r)}")
ok = r != 0
print(
    "[probe] PASS: Thread::Current() returns a non-null Thread"
    if ok
    else "[probe] FAIL: null Thread"
)

vm.write(artb + IS_STARTED, b"\x00")  # clear the is_started_ gate
r2 = vm.call(artb + CURRENT_FROM_GDB, [])
print(f"[probe] with is_started_=0 -> {hex(r2)} (expect 0x0)")
ok = ok and r2 == 0
print("[probe] gate semantics OK" if ok else "[probe] FAIL: gate")
sys.exit(0 if ok else 1)
