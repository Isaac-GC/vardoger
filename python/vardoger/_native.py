"""ctypes binding layer for libvardoger_capi.so, the flat C ABI over vardoger.

This module only declares the raw C prototypes and callback types and locates the shared library.
The Pythonic API lives in ``vardoger/__init__.py``.
"""

from __future__ import annotations

import ctypes as C
import os
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parent.parent  # python/vardoger -> repo root.
# Try the host's native extension FIRST, so a stale cross-built artifact left in
# build/ (e.g. a Linux .so lingering in a macOS checkout) can't shadow the real
# one and fail to dlopen.
if sys.platform == "darwin":
    _NAMES = ("libvardoger_capi.dylib", "libvardoger_capi.so")
elif sys.platform == "win32":
    _NAMES = ("vardoger_capi.dll", "libvardoger_capi.dll")
else:
    _NAMES = ("libvardoger_capi.so", "libvardoger_capi.dylib")


def _find_lib() -> str:
    # $VARDOGER_CAPI wins, then the copy an installed wheel puts next to this file, then a local build
    # tree for people running straight from a checkout.
    if env := os.environ.get("VARDOGER_CAPI"):
        return env
    roots = (
        _HERE,
        _REPO / "build",
        _REPO / "build" / "linux",
        _REPO / "build" / "mac",
        _REPO / "build" / "pylib",
    )
    for root in roots:
        for name in _NAMES:
            cand = root / name
            if cand.exists():
                return str(cand)
    raise FileNotFoundError(
        "libvardoger_capi.so not found. Build it with `cmake -B build && cmake --build build`, "
        "or point $VARDOGER_CAPI at the shared library."
    )


lib = C.CDLL(_find_lib())

# ---- Callback function types. These must match the typedefs in core/py/vardoger_capi.cpp. ----------
CODE_CB = C.CFUNCTYPE(
    None, C.c_uint64, C.c_uint32, C.c_void_p
)  # (pc, size, user)
WRITE_CB = C.CFUNCTYPE(
    None, C.c_uint64, C.c_int, C.c_uint64, C.c_void_p
)  # (addr, size, value, user)
UNMAPPED_CB = C.CFUNCTYPE(
    C.c_int, C.c_int, C.c_uint64, C.c_void_p
)  # (type, addr, user) -> handled
TRAMP_CB = C.CFUNCTYPE(None, C.c_void_p)  # (user)
METHOD_CB = C.CFUNCTYPE(
    C.c_int64, C.c_uint64, C.POINTER(C.c_int64), C.c_int, C.c_void_p
)  # (self, args, nargs, user)
DEX_CB = C.CFUNCTYPE(
    None, C.POINTER(C.c_uint8), C.c_uint64, C.c_char_p, C.c_void_p
)  # (data, n, src, user)
REGION_CB = C.CFUNCTYPE(
    None, C.c_uint64, C.c_uint64, C.c_uint32, C.c_char_p, C.c_void_p
)  # (base, size, prot, label, user)
NATIVE_CB = C.CFUNCTYPE(
    None, C.c_char_p, C.c_char_p, C.c_char_p, C.c_uint64, C.c_void_p
)  # (cls, name, sig, fn, user)
PROP_CB = C.CFUNCTYPE(
    None, C.c_char_p, C.c_char_p, C.c_void_p
)  # (name, value, user)
SYSCALL_CB = C.CFUNCTYPE(
    None, C.c_uint64, C.c_char_p, C.POINTER(C.c_uint64), C.c_uint64, C.c_void_p
)  # (nr, name, args[6], ret, user)

VMP = C.c_void_p  # Opaque VM*.

_P = C.POINTER
_u8p = _P(C.c_uint8)
_u64p = _P(C.c_uint64)
_i64p = _P(C.c_int64)


def _sig(name, restype, *argtypes):
    fn = getattr(lib, name)
    fn.restype = restype
    fn.argtypes = list(argtypes)
    return fn


mv_last_error = _sig("mv_last_error", C.c_char_p)
mv_new = _sig("mv_new", VMP, C.c_char_p, C.c_char_p, C.c_int)
mv_free = _sig("mv_free", None, VMP)

mv_load = _sig("mv_load", C.c_int, VMP, C.c_char_p)
mv_map_art = _sig("mv_map_art", C.c_int, VMP, C.c_char_p)
mv_so_bias = _sig("mv_so_bias", C.c_uint64, VMP, C.c_int)
mv_so_size = _sig("mv_so_size", C.c_uint64, VMP, C.c_int)
mv_so_jni_onload = _sig("mv_so_jni_onload", C.c_uint64, VMP, C.c_int)
mv_so_init = _sig("mv_so_init", C.c_uint64, VMP, C.c_int)
mv_so_lookup = _sig("mv_so_lookup", C.c_uint64, VMP, C.c_int, C.c_char_p)
mv_so_init_array = _sig(
    "mv_so_init_array", C.c_int, VMP, C.c_int, _u64p, C.c_int
)

mv_run_init = _sig("mv_run_init", None, VMP, C.c_int)
mv_call = _sig("mv_call", C.c_uint64, VMP, C.c_uint64, _u64p, C.c_int)

mv_set_property = _sig("mv_set_property", None, VMP, C.c_char_p, C.c_char_p)
mv_vfs_add = _sig("mv_vfs_add", None, VMP, C.c_char_p, _u8p, C.c_uint64)
mv_apk_path = _sig("mv_apk_path", C.c_int, VMP, C.c_char_p, C.c_int)
mv_data_dir = _sig("mv_data_dir", C.c_int, VMP, C.c_char_p, C.c_int)
mv_native_lib_dir = _sig("mv_native_lib_dir", C.c_int, VMP, C.c_char_p, C.c_int)
mv_jni_env = _sig("mv_jni_env", C.c_uint64, VMP)
mv_java_vm = _sig("mv_java_vm", C.c_uint64, VMP)
mv_app_object = _sig("mv_app_object", C.c_uint64, VMP)
mv_context_object = _sig("mv_context_object", C.c_uint64, VMP)

mv_read = _sig("mv_read", C.c_int, VMP, C.c_uint64, _u8p, C.c_uint64)
mv_write = _sig("mv_write", None, VMP, C.c_uint64, _u8p, C.c_uint64)
mv_heap_alloc = _sig("mv_heap_alloc", C.c_uint64, VMP, C.c_uint64)
mv_read_u64 = _sig("mv_read_u64", C.c_uint64, VMP, C.c_uint64)
mv_write_u64 = _sig("mv_write_u64", None, VMP, C.c_uint64, C.c_uint64)
mv_read_reg = _sig("mv_read_reg", C.c_uint64, VMP, C.c_int)
mv_write_reg = _sig("mv_write_reg", None, VMP, C.c_int, C.c_uint64)
mv_read_cstr = _sig(
    "mv_read_cstr", C.c_int, VMP, C.c_uint64, C.c_char_p, C.c_int
)
mv_describe = _sig("mv_describe", C.c_int, VMP, C.c_uint64, C.c_char_p, C.c_int)
mv_is_mapped = _sig("mv_is_mapped", C.c_int, VMP, C.c_uint64)
mv_regions = _sig("mv_regions", None, VMP, REGION_CB, C.c_void_p)

mv_on_code = _sig("mv_on_code", None, VMP, CODE_CB, C.c_void_p)
mv_on_unmapped = _sig("mv_on_unmapped", None, VMP, UNMAPPED_CB, C.c_void_p)
mv_add_mem_write_hook = _sig(
    "mv_add_mem_write_hook",
    None,
    VMP,
    WRITE_CB,
    C.c_void_p,
    C.c_uint64,
    C.c_uint64,
)
mv_alloc_trampoline = _sig(
    "mv_alloc_trampoline", C.c_uint64, VMP, TRAMP_CB, C.c_void_p, C.c_char_p
)

mv_new_string = _sig("mv_new_string", C.c_uint64, VMP, C.c_char_p)
mv_new_byte_array = _sig("mv_new_byte_array", C.c_uint64, VMP, _u8p, C.c_int)
mv_find_class = _sig("mv_find_class", C.c_uint64, VMP, C.c_char_p)
mv_string_of = _sig(
    "mv_string_of", C.c_int, VMP, C.c_uint64, C.c_char_p, C.c_int
)
mv_register_method = _sig(
    "mv_register_method", None, VMP, C.c_char_p, METHOD_CB, C.c_int, C.c_void_p
)

mv_new_object = _sig("mv_new_object", C.c_uint64, VMP, C.c_char_p)
mv_set_field_obj = _sig(
    "mv_set_field_obj", None, VMP, C.c_uint64, C.c_char_p, C.c_uint64
)
mv_set_field_int = _sig(
    "mv_set_field_int", None, VMP, C.c_uint64, C.c_char_p, C.c_int64
)
mv_get_field = _sig(
    "mv_get_field", C.c_int64, VMP, C.c_uint64, C.c_char_p, _P(C.c_int)
)
mv_array_length = _sig("mv_array_length", C.c_int, VMP, C.c_uint64)
mv_array_read = _sig("mv_array_read", C.c_int, VMP, C.c_uint64, _u8p, C.c_int)
mv_array_write = _sig(
    "mv_array_write", None, VMP, C.c_uint64, C.c_int, _u8p, C.c_int
)
mv_object_array_element = _sig(
    "mv_object_array_element", C.c_uint64, VMP, C.c_uint64, C.c_int
)

mv_gdb_listen = _sig("mv_gdb_listen", C.c_int, VMP, C.c_int)
mv_gdb_attached = _sig("mv_gdb_attached", C.c_int, VMP)
mv_gdb_detach = _sig("mv_gdb_detach", None, VMP)

mv_scan_dex = _sig("mv_scan_dex", None, VMP, DEX_CB, C.c_void_p)
mv_set_dex_observer = _sig("mv_set_dex_observer", None, VMP, DEX_CB, C.c_void_p)
mv_registered_natives = _sig(
    "mv_registered_natives", None, VMP, NATIVE_CB, C.c_void_p
)
mv_set_property_observer = _sig(
    "mv_set_property_observer", None, VMP, PROP_CB, C.c_void_p
)
mv_set_syscall_observer = _sig(
    "mv_set_syscall_observer", None, VMP, SYSCALL_CB, C.c_void_p
)
