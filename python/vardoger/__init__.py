"""Drive the vardoger faithful-Android runtime from Python.

This is a generic Python interface to vardoger's capabilities: load a packer/native .so into the
emulated Android runtime, configure the environment, run init / JNI_OnLoad / arbitrary functions,
read and write memory and registers, hook code and memory, allocate trampolines (so libc/JNI stubs
and capture hooks can be implemented in Python), register Java methods, and capture DEX. It is
packer-agnostic and exposes the same primitives the C++ drivers use, for scripting.

The backend is the C-ABI shared library libvardoger_capi.so, driven through ctypes with no pybind11 or
Python.h needed. Requires Python 3.10+.

Example
-------
    from vardoger import VM, Reg

    vm = VM(package="com.foo.bar", sdk=31)
    vm.serve_apk("base.apk")                       # Serve the APK where the loader expects it.
    so = vm.load("lib.so")                          # -> Module(bias, jni_onload, size, ...)
    vm.run_init(so)                                 # DT_INIT + .init_array
    ver = vm.call(so.jni_onload, [vm.java_vm, 0])   # Returns 0x10006 on success.

    @vm.on_code                                     # Trace every instruction.
    def _(pc, size): ...

    slot = ...                                       # A .data fn-ptr slot in the SO.
    def capture():                                   # A Python stub the guest will call.
        base, size = vm.reg(Reg.X0), vm.reg(Reg.X1)
        open("out.dex","wb").write(vm.read(base, size))
    vm.write_u64(slot, vm.alloc_trampoline(capture)) # Seed the slot to capture in Python.

    for n in vm.registered_natives(): print(n.cls, n.name, hex(n.fn))
    for dex in vm.scan_dex(): ...
"""

from __future__ import annotations

import ctypes as C
from dataclasses import dataclass
from typing import Callable

from . import _native as _n

__all__ = ["VM", "Module", "Reg", "Region", "Native", "VardogerError"]


class VardogerError(RuntimeError):
    pass


class Reg:
    """ARM64 register ids (unicorn UC_ARM64_REG_*) for :meth:`VM.reg` / :meth:`VM.set_reg`."""

    # X0..X28 are contiguous (X0 == 199), whereas X29/X30/SP/PC are special.
    X = tuple(199 + i for i in range(29))  # Reg.X[0] .. Reg.X[28]
    X0, X1, X2, X3, X4, X5, X6, X7, X8 = (199 + i for i in range(9))
    X19, X20, X21, X22, X23, X24, X25, X26, X27, X28 = (
        199 + i for i in range(19, 29)
    )
    FP = X29 = 1
    LR = X30 = 2
    SP = 4
    PC = 260


@dataclass(slots=True)
class Module:
    """A loaded ELF `.so` inside the VM."""

    index: int
    path: str
    bias: int  # Load bias; add to a file vaddr to get the guest address.
    size: int  # Mapped span.
    jni_onload: int  # Guest address of JNI_OnLoad, or 0.
    init: int  # Guest address of DT_INIT, or 0.
    _vm: "VM"

    def lookup(self, symbol: str) -> int:
        """Guest address of an exported symbol, or 0."""
        return _n.mv_so_lookup(self._vm._h, self.index, symbol.encode())

    @property
    def init_array(self) -> list[int]:
        buf = (C.c_uint64 * 64)()
        n = _n.mv_so_init_array(self._vm._h, self.index, buf, 64)
        return [buf[i] for i in range(min(n, 64))]


@dataclass(slots=True)
class Region:
    base: int
    size: int
    prot: int  # UC_PROT_* bitmask (1=READ, 2=WRITE, 4=EXEC).
    label: str


@dataclass(slots=True)
class Native:
    cls: str
    name: str
    sig: str
    fn: int  # Guest address of the native impl.


@dataclass(slots=True)
class FoundString:
    addr: int  # Guest address of the string's first byte.
    text: str  # The printable-ASCII run.
    region: str  # The mapping it lives in (heap/mmap/lib label).


class VM:
    """A configured vardoger Android runtime you drive from Python."""

    def __init__(
        self, *, abi: str = "arm64", package: str | None = None, sdk: int = 31
    ):
        self._h = _n.mv_new(abi.encode(), (package or "").encode() or None, sdk)
        if not self._h:
            raise VardogerError(_n.mv_last_error().decode())
        self._keep: list = []  # Keep ctypes callbacks alive to prevent GC.
        self._mods: list[Module] = []

    # ---- lifecycle --------------------------------------------------------------------------
    def close(self) -> None:
        if getattr(self, "_h", None):
            _n.mv_free(self._h)
            self._h = None

    def __del__(self):  # Best-effort cleanup.
        self.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def load(self, path: str) -> Module:
        """Load an ELF `.so` (runs relocations + import resolution, not init). Returns a Module."""
        i = _n.mv_load(self._h, str(path).encode())
        if i < 0:
            raise VardogerError(_n.mv_last_error().decode())
        m = Module(
            index=i,
            path=str(path),
            bias=_n.mv_so_bias(self._h, i),
            size=_n.mv_so_size(self._h, i),
            jni_onload=_n.mv_so_jni_onload(self._h, i),
            init=_n.mv_so_init(self._h, i),
            _vm=self,
        )
        self._mods.append(m)
        return m

    def map_art(self, art_dir: str) -> None:
        """Map a real libart.so from `art_dir` without init, and wire dlsym/dl_iterate_phdr to it,
        so a packer that hooks or scans ART internals (e.g. ClassLinker::DefineClass) resolves them.
        """
        if _n.mv_map_art(self._h, str(art_dir).encode()) != 0:
            raise VardogerError(_n.mv_last_error().decode())

    def run_init(self, mod: Module) -> None:
        """Run DT_INIT then every .init_array entry (packer self-decrypt happens here)."""
        _n.mv_run_init(self._h, mod.index)

    def call(self, fn: int, args: list[int] | tuple[int, ...] = ()) -> int:
        """Drive a guest function through the scheduler (blocking pthreads OK); returns x0.

        The stack is reset to a clean top first. Args go in x0..x7 (max 8)."""
        arr = (C.c_uint64 * len(args))(*[a & 0xFFFFFFFFFFFFFFFF for a in args])
        return int(_n.mv_call(self._h, fn, arr, len(args)))

    # ---- environment ------------------------------------------------------------------------
    def set_property(self, key: str, value: str) -> None:
        _n.mv_set_property(self._h, key.encode(), value.encode())

    def vfs_add(self, guest_path: str, data: bytes) -> None:
        """Serve `data` at a guest path (the packer's open()/read() see it)."""
        buf = (C.c_uint8 * len(data)).from_buffer_copy(data)
        _n.mv_vfs_add(self._h, guest_path.encode(), buf, len(data))

    def serve_apk(self, host_path: str, guest_path: str | None = None) -> bytes:
        """Serve an APK from disk at the guest APK path. Returns its bytes.

        Defaults to the realistic randomized :attr:`apk_path` (what ``getPackageCodePath()`` /
        ``sourceDir`` return), so a packer that opens its own code path finds the APK. Pass
        `guest_path` to override.
        """
        data = open(host_path, "rb").read()
        self.vfs_add(guest_path or self.apk_path, data)
        return data

    def _path(self, fn) -> str:
        buf = C.create_string_buffer(1024)
        fn(self._h, buf, 1024)
        return buf.value.decode()

    @property
    def apk_path(self) -> str:
        """The realistic randomized guest APK path (e.g. ``/data/app/~~<rand>/<pkg>-<rand>/base.apk``)
        that ``getPackageCodePath()`` returns and where :meth:`serve_apk` serves the APK."""
        return self._path(_n.mv_apk_path)

    @property
    def data_dir(self) -> str:
        """The app data dir (``/data/user/0/<pkg>/files``)."""
        return self._path(_n.mv_data_dir)

    @property
    def native_lib_dir(self) -> str:
        """The native library dir (``.../<pkg>-<rand>/lib/arm64``)."""
        return self._path(_n.mv_native_lib_dir)

    @property
    def jni_env(self) -> int:
        return int(_n.mv_jni_env(self._h))

    @property
    def java_vm(self) -> int:
        return int(_n.mv_java_vm(self._h))

    @property
    def application(self) -> int:
        return int(_n.mv_app_object(self._h))

    @property
    def context(self) -> int:
        return int(_n.mv_context_object(self._h))

    # ---- memory / registers -----------------------------------------------------------------
    def read(self, addr: int, n: int) -> bytes:
        buf = (C.c_uint8 * n)()
        got = _n.mv_read(self._h, addr, buf, n)
        return bytes(buf[:got]) if got else b""

    def write(self, addr: int, data: bytes) -> None:
        buf = (C.c_uint8 * len(data)).from_buffer_copy(data)
        _n.mv_write(self._h, addr, buf, len(data))

    def heap_alloc(self, n: int) -> int:
        """Allocate `n` bytes of guest heap; returns the guest address (e.g. to return from a stub)."""
        return int(_n.mv_heap_alloc(self._h, n))

    def read_u64(self, addr: int) -> int:
        return int(_n.mv_read_u64(self._h, addr))

    def write_u64(self, addr: int, v: int) -> None:
        _n.mv_write_u64(self._h, addr, v & 0xFFFFFFFFFFFFFFFF)

    def reg(self, uc_reg_id: int) -> int:
        return int(_n.mv_read_reg(self._h, uc_reg_id))

    def set_reg(self, uc_reg_id: int, v: int) -> None:
        _n.mv_write_reg(self._h, uc_reg_id, v & 0xFFFFFFFFFFFFFFFF)

    def is_mapped(self, addr: int) -> bool:
        return bool(_n.mv_is_mapped(self._h, addr))

    def read_cstr(self, addr: int, cap: int = 4096) -> str:
        buf = C.create_string_buffer(cap)
        _n.mv_read_cstr(self._h, addr, buf, cap)
        return buf.value.decode("latin1", "replace")

    def describe(self, addr: int) -> str:
        buf = C.create_string_buffer(256)
        _n.mv_describe(self._h, addr, buf, 256)
        return buf.value.decode("latin1", "replace")

    def regions(self) -> list[Region]:
        out: list[Region] = []

        @_n.REGION_CB
        def cb(base, size, prot, label, _u):
            out.append(
                Region(
                    base,
                    size,
                    prot,
                    label.decode("latin1", "replace") if label else "",
                )
            )

        _n.mv_regions(self._h, cb, None)
        return out

    # ---- hooks / trampolines ----------------------------------------------------------------
    def on_code(self, fn: Callable[[int, int], None]) -> Callable:
        """Register a per-instruction trace hook `fn(pc, size)`. Usable as a decorator."""

        @_n.CODE_CB
        def cb(pc, size, _u):
            fn(pc, size)

        self._keep.append(cb)
        _n.mv_on_code(self._h, cb, None)
        return fn

    def on_unmapped(self, fn: Callable[[int, int], bool]) -> Callable:
        """Register `fn(access_type, addr) -> handled` for unmapped accesses. Usable as a decorator."""

        @_n.UNMAPPED_CB
        def cb(t, addr, _u):
            return 1 if fn(t, addr) else 0

        self._keep.append(cb)
        _n.mv_on_unmapped(self._h, cb, None)
        return fn

    def add_mem_write_hook(
        self, fn: Callable[[int, int, int], None], lo: int = 1, hi: int = 0
    ) -> None:
        """Call `fn(addr, size, value)` on guest memory writes in [lo, hi] (hi=0 means all)."""

        @_n.WRITE_CB
        def cb(addr, size, value, _u):
            fn(addr, size, value)

        self._keep.append(cb)
        _n.mv_add_mem_write_hook(self._h, cb, None, lo, hi)

    def alloc_trampoline(
        self, fn: Callable[[], None], name: str = "py_stub"
    ) -> int:
        """Allocate a guest stub whose handler is a Python callable, so libc/JNI stubs or capture
        hooks can be implemented in Python. Inside `fn`, read and modify regs and mem, and set the
        return via `set_reg(Reg.X0, ...)`. Returns the guest address to store into a table or branch to.
        """

        @_n.TRAMP_CB
        def cb(_u):
            fn()

        self._keep.append(cb)
        return int(_n.mv_alloc_trampoline(self._h, cb, None, name.encode()))

    # ---- debugging (gdb/lldb) ---------------------------------------------------------------
    def gdb_listen(self, port: int = 1234) -> bool:
        """Open a GDB Remote Serial Protocol server on 127.0.0.1:`port` and block until an
        external debugger attaches and continues, then return so you can drive the target.

        lldb, gdb-multiarch, and the RSP clients in Binary Ninja / IDA all speak this protocol.
        The typical flow::

            vm.load("lib.so"); vm.run_init(so)
            vm.gdb_listen(1234)             # blocks; in another terminal:
            #   lldb -o "gdb-remote 1234"   (or, in gdb:  target remote :1234)
            #   set breakpoints, then `continue`
            vm.call(so.jni_onload, [vm.java_vm, 0])   # runs under the debugger

        Breakpoints, single-stepping, register and memory access all work against the emulated
        ARM64 CPU. Returns True once attached and the client has resumed; False if the debugger
        detached during the handshake.
        """
        r = _n.mv_gdb_listen(self._h, int(port))
        if r < 0:
            raise VardogerError(_n.mv_last_error().decode())
        return r == 1

    @property
    def gdb_attached(self) -> bool:
        return _n.mv_gdb_attached(self._h) == 1

    def gdb_detach(self) -> None:
        """Close the debugger connection and remove the instruction hook."""
        _n.mv_gdb_detach(self._h)

    # ---- Java -------------------------------------------------------------------------------
    def new_string(self, s: str) -> int:
        return int(_n.mv_new_string(self._h, s.encode()))

    def new_byte_array(self, data: bytes) -> int:
        buf = (C.c_uint8 * len(data)).from_buffer_copy(data)
        return int(_n.mv_new_byte_array(self._h, buf, len(data)))

    def find_class(self, name: str) -> int:
        return int(_n.mv_find_class(self._h, name.encode()))

    def new_object(self, cls: str) -> int:
        """Create a guest Java object of class `cls`; returns its handle."""
        return int(_n.mv_new_object(self._h, cls.encode()))

    def set_field(
        self, obj: int, name: str, value: int, *, is_object: bool = True
    ) -> None:
        """Set a field on `obj`. `value` is an object handle (is_object=True) or an int."""
        if is_object:
            _n.mv_set_field_obj(self._h, obj, name.encode(), value)
        else:
            _n.mv_set_field_int(self._h, obj, name.encode(), value)

    def get_field(self, obj: int, name: str) -> tuple[int, str]:
        """Get a field -> (value, kind) where kind is 'void'|'int'|'object'."""
        kind = C.c_int(0)
        v = int(_n.mv_get_field(self._h, obj, name.encode(), C.byref(kind)))
        return v, {0: "void", 1: "int", 3: "object"}.get(kind.value, "?")

    def array_length(self, arr: int) -> int:
        return int(_n.mv_array_length(self._h, arr))

    def object_array_element(self, arr: int, i: int) -> int:
        return int(_n.mv_object_array_element(self._h, arr, i))

    def array_read(self, arr: int) -> bytes:
        """Read a byte[]'s contents."""
        n = _n.mv_array_length(self._h, arr)
        if n <= 0:
            return b""
        buf = (C.c_uint8 * n)()
        got = _n.mv_array_read(self._h, arr, buf, n)
        return bytes(buf[:got]) if got >= 0 else b""

    def array_write(self, arr: int, data: bytes, off: int = 0) -> None:
        """Write bytes into a byte[] at offset (grows it if needed)."""
        buf = (C.c_uint8 * len(data)).from_buffer_copy(data)
        _n.mv_array_write(self._h, arr, off, buf, len(data))

    def string_of(self, handle: int, cap: int = 65536) -> str | None:
        buf = C.create_string_buffer(cap)
        n = _n.mv_string_of(self._h, handle, buf, cap)
        return None if n < 0 else buf.value.decode("latin1", "replace")

    def register_method(
        self,
        name: str,
        fn: Callable[[int, list[int]], int],
        returns_object: bool = True,
    ) -> None:
        """Implement a Java method in Python as `fn(self_handle, args) -> int`.

        `args` are int64 (object handles for objects, raw value for ints/longs). Return an object
        handle (returns_object=True) or an int. Use `string_of`/`new_string` to marshal strings.
        """

        @_n.METHOD_CB
        def cb(self_h, args_ptr, nargs, _u):
            args = [int(args_ptr[i]) for i in range(nargs)]
            return int(fn(self_h, args))

        self._keep.append(cb)
        _n.mv_register_method(
            self._h, name.encode(), cb, 1 if returns_object else 0, None
        )

    # ---- capture ----------------------------------------------------------------------------
    def scan_dex(self) -> list[bytes]:
        """Scan guest memory for DEX files; return each as bytes."""
        out: list[bytes] = []

        @_n.DEX_CB
        def cb(data, n, src, _u):
            out.append(C.string_at(data, n))

        _n.mv_scan_dex(self._h, cb, None)
        return out

    def search_strings(
        self, needle: str = "", min_len: int = 4
    ) -> list[FoundString]:
        """Search guest memory for printable strings, keeping each match's address + region.

        Scans the heap/mmap/lib regions for printable-ASCII runs of at least `min_len` bytes. With
        `needle`, only runs containing it (as a substring) are returned — grep decrypted memory for a
        marker (class name, URL, license string) and jump straight to its address. Returns a list of
        :class:`FoundString` (addr, text, region); not deduped, ordered by address within each region.
        """
        out: list[FoundString] = []

        @_n.STR_CB
        def cb(addr, text, region, _u):
            out.append(
                FoundString(
                    int(addr),
                    text.decode("latin1", "replace") if text else "",
                    region.decode() if region else "",
                )
            )

        _n.mv_search_strings(
            self._h, needle.encode(), int(min_len), cb, None
        )
        return out

    def set_dex_observer(self, fn: Callable[[bytes, str], None]) -> None:
        """Call `fn(dex_bytes, source)` whenever DEX-looking bytes cross the byte[]/ClassLoader boundary."""

        @_n.DEX_CB
        def cb(data, n, src, _u):
            fn(C.string_at(data, n), src.decode() if src else "")

        self._keep.append(cb)
        _n.mv_set_dex_observer(self._h, cb, None)

    def registered_natives(self) -> list[Native]:
        """Every RegisterNatives'd method -> its native impl address (the methods.txt map)."""
        out: list[Native] = []

        @_n.NATIVE_CB
        def cb(cls, name, sig, fn, _u):
            out.append(
                Native(cls.decode(), name.decode(), sig.decode(), int(fn))
            )

        _n.mv_registered_natives(self._h, cb, None)
        return out

    # ---- monitoring (build properties + syscalls) -------------------------------------------
    def set_property_observer(
        self, fn: Callable[[str, str], None]
    ) -> None:
        """Call `fn(name, value)` on every system/build property the guest reads.

        Shows which device fingerprints a packer probes (ro.build.fingerprint, ro.debuggable,
        ro.build.version.sdk, ro.product.model, ...) and the value it got back.
        """

        @_n.PROP_CB
        def cb(name, value, _u):
            fn(
                name.decode() if name else "",
                value.decode() if value else "",
            )

        self._keep.append(cb)
        _n.mv_set_property_observer(self._h, cb, None)

    def set_syscall_observer(
        self, fn: Callable[[int, str, list[int], int], None]
    ) -> None:
        """Call `fn(nr, name, args, ret)` on every raw syscall (SVC) the guest issues.

        `args` is the 6-element list x0..x5 captured on entry; `ret` is x0 after the handler.
        Traces direct-syscall activity a packer uses to bypass libc hooks: ptrace anti-debug
        probes, getrandom, mprotect W^X flips, openat of /proc, futex, etc.
        """

        @_n.SYSCALL_CB
        def cb(nr, name, args, ret, _u):
            fn(
                int(nr),
                name.decode() if name else "",
                [int(args[i]) for i in range(6)],
                int(ret),
            )

        self._keep.append(cb)
        _n.mv_set_syscall_observer(self._h, cb, None)
