#include "vardoger/android/syscalls.hpp"

#include <unicorn/unicorn.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

namespace vardoger {

namespace {
enum class Sys {
  Unknown,
  ClockGettime,
  Gettimeofday,
  Getpid,
  Getuid,
  Geteuid,
  Gettid,
  Exit,
  ExitGroup,
  Mmap,
  Munmap,
  Mprotect,
  Openat,
  Read,
  Write,
  Close,
  Lseek,
  Fstat,
  Fstatat,
  Faccessat,
  Getrandom,
  Ptrace,
  Noop,
  Nanosleep,
  // ---- expansion: pthread/bionic/runtime plumbing that ART + packers hit ----
  Futex,
  SetTidAddress,
  SchedGetaffinity,
  Prctl,
  Madvise,
  Mremap,
  Readlinkat,
  Uname,
  Sysinfo,
  Getcwd,
  Fcntl,
  Ioctl,
  ClockGetres,
  // ---- armv7 (EABI) completeness ----
  // The legacy path-taking variants put the PATH in A0, whereas the *at()
  // forms put a dirfd in A0 and the path in A1. Mixing them up reads garbage
  // as the path, so they get their own kinds.
  OpenLegacy,    // open(path, flags, mode)
  AccessLegacy,  // access(path, mode)
  StatPath,      // stat64/lstat64(path, statbuf)
  Mmap2,         // mmap2: like mmap, but the offset is in 4 KiB PAGES
  Llseek,        // _llseek(fd, off_hi, off_lo, result*, whence)
  ArmSetTls,     // ARM_set_tls(tp) -> sets TPIDRURO (bionic thread bring-up)
  ArmCacheflush, // ARM_cacheflush(start, end, flags) -> 0
  // ---- shared gaps (both arches) ----
  Getgid,   // getgid/getegid — same modelled app identity as getuid
  Writev,   // writev(fd, iovec*, cnt): liblog/stdio use it, not just write
  Brk,      // brk(addr): classic heap growth; report the current break
};

Sys normalize(Abi abi, uint64_t nr) {
  if (abi == Abi::Arm64) {
    switch (nr) {
      case 113:
        return Sys::ClockGettime;
      case 169:
        return Sys::Gettimeofday;
      case 172:
        return Sys::Getpid;
      case 174:
        return Sys::Getuid;
      case 175:
        return Sys::Geteuid;
      case 178:
        return Sys::Gettid;
      case 93:
        return Sys::Exit;
      case 94:
        return Sys::ExitGroup;
      case 222:
        return Sys::Mmap;
      case 215:
        return Sys::Munmap;
      case 226:
        return Sys::Mprotect;
      case 56:
        return Sys::Openat;
      case 63:
        return Sys::Read;
      case 64:
        return Sys::Write;
      case 57:
        return Sys::Close;
      case 62:
        return Sys::Lseek;
      case 80:
        return Sys::Fstat;
      case 79:
        return Sys::Fstatat;
      case 278:
        return Sys::Getrandom;
      case 48:
        return Sys::Faccessat;
      case 101:
        return Sys::Nanosleep;
      case 117:
        return Sys::Ptrace;
      case 129:
      case 130:
      case 131:
        return Sys::Noop;  // kill/tkill/tgkill -> 0
      case 134:
      case 135:
      case 139:
        return Sys::Noop;  // rt_sigaction/procmask/return
      // ---- expansion (arm64) ----
      case 98:
        return Sys::Futex;  // pthread mutex/cond wait/wake
      case 96:
        return Sys::SetTidAddress;  // bionic thread bring-up -> tid
      case 99:
        return Sys::Noop;  // set_robust_list -> 0
      case 293:
        return Sys::Noop;  // rseq -> 0 (bionic tolerates)
      case 283:
        return Sys::Noop;  // membarrier -> 0
      case 124:
        return Sys::Noop;  // sched_yield -> 0
      case 122:
        return Sys::Noop;  // sched_setaffinity -> 0
      case 123:
        return Sys::SchedGetaffinity;
      case 167:
        return Sys::Prctl;  // PR_SET_NAME / PR_SET_VMA / ...
      case 233:
        return Sys::Madvise;  // -> 0
      case 216:
        return Sys::Mremap;
      case 78:
        return Sys::Readlinkat;  // /proc/self/exe etc.
      case 160:
        return Sys::Uname;
      case 179:
        return Sys::Sysinfo;  // RAM/uptime (emu-detection reads totalram)
      case 17:
        return Sys::Getcwd;
      case 25:
        return Sys::Fcntl;
      case 29:
        return Sys::Ioctl;
      case 114:
        return Sys::ClockGetres;
      case 176:
      case 177:
        return Sys::Getgid;  // getgid / getegid
      case 66:
        return Sys::Writev;
      case 214:
        return Sys::Brk;
      case 439:
        return Sys::Faccessat;  // faccessat2 (extra flags arg, same answer)
      default:
        return Sys::Unknown;
    }
  }
  if (abi == Abi::X86_64) {
    switch (nr) {  // Linux x86_64
      case 0: return Sys::Read;
      case 1: return Sys::Write;
      case 2: return Sys::OpenLegacy;   // open(path,...)
      case 3: return Sys::Close;
      case 4: case 6: return Sys::StatPath;  // stat / lstat
      case 5: return Sys::Fstat;
      case 8: return Sys::Lseek;
      case 9: return Sys::Mmap;
      case 10: return Sys::Mprotect;
      case 11: return Sys::Munmap;
      case 12: return Sys::Brk;
      case 16: return Sys::Ioctl;
      case 20: return Sys::Writev;
      case 21: return Sys::AccessLegacy;
      case 25: return Sys::Mremap;
      case 28: return Sys::Madvise;
      case 35: return Sys::Nanosleep;
      case 39: return Sys::Getpid;
      case 60: return Sys::Exit;
      case 63: return Sys::Uname;
      case 72: return Sys::Fcntl;
      case 79: return Sys::Getcwd;
      case 89: return Sys::Readlinkat;  // readlink(path, buf, sz)
      case 96: return Sys::Gettimeofday;
      case 99: return Sys::Sysinfo;
      case 101: return Sys::Ptrace;
      case 102: return Sys::Getuid;
      case 104: case 108: return Sys::Getgid;
      case 107: return Sys::Geteuid;
      case 157: return Sys::Prctl;
      case 186: return Sys::Gettid;
      case 202: return Sys::Futex;
      case 204: return Sys::SchedGetaffinity;
      case 218: return Sys::SetTidAddress;
      case 228: return Sys::ClockGettime;
      case 229: return Sys::ClockGetres;
      case 231: return Sys::ExitGroup;
      case 257: return Sys::Openat;
      case 262: return Sys::Fstatat;   // newfstatat
      case 267: return Sys::Readlinkat;
      case 269: case 439: return Sys::Faccessat;
      case 318: return Sys::Getrandom;
      case 13: case 14: case 15:       // rt_sigaction/procmask/return
      case 24:                          // sched_yield
      case 62: case 200: case 234:      // kill / tkill / tgkill
      case 273: case 324: case 334:     // set_robust_list / membarrier / rseq
        return Sys::Noop;
      default: return Sys::Unknown;
    }
  }
  if (abi == Abi::X86) {
    switch (nr) {  // Linux i386 (note: close to, but NOT the same as, ARM EABI)
      case 1: return Sys::Exit;
      case 3: return Sys::Read;
      case 4: return Sys::Write;
      case 5: return Sys::OpenLegacy;
      case 6: return Sys::Close;
      case 19: return Sys::Lseek;
      case 20: return Sys::Getpid;
      case 24: case 199: return Sys::Getuid;
      case 26: return Sys::Ptrace;
      case 33: return Sys::AccessLegacy;
      case 45: return Sys::Brk;
      case 47: case 50: case 200: case 202: return Sys::Getgid;
      case 49: case 201: return Sys::Geteuid;
      case 54: return Sys::Ioctl;
      case 55: return Sys::Fcntl;
      case 78: return Sys::Gettimeofday;
      case 90: return Sys::Mmap;    // old_mmap (byte offset)
      case 91: return Sys::Munmap;
      case 116: return Sys::Sysinfo;
      case 122: return Sys::Uname;
      case 125: return Sys::Mprotect;
      case 140: return Sys::Llseek;
      case 146: return Sys::Writev;
      case 162: return Sys::Nanosleep;
      case 163: return Sys::Mremap;
      case 172: return Sys::Prctl;
      case 183: return Sys::Getcwd;
      case 192: return Sys::Mmap2;  // page-shifted offset
      case 195: case 196: return Sys::StatPath;
      case 197: return Sys::Fstat;
      case 219: return Sys::Madvise;
      case 224: return Sys::Gettid;
      case 240: return Sys::Futex;
      case 242: return Sys::SchedGetaffinity;
      case 252: return Sys::ExitGroup;
      case 258: return Sys::SetTidAddress;
      case 265: return Sys::ClockGettime;
      case 266: return Sys::ClockGetres;
      case 295: return Sys::Openat;
      case 300: return Sys::Fstatat;   // fstatat64
      case 305: return Sys::Readlinkat;
      case 307: case 439: return Sys::Faccessat;
      case 355: return Sys::Getrandom;
      case 37: case 238: case 270:     // kill / tkill / tgkill
      case 158:                         // sched_yield
      case 173: case 174: case 175:     // rt_sig*
      case 311: case 375: case 386:     // set_robust_list / membarrier / rseq
        return Sys::Noop;
      default: return Sys::Unknown;
    }
  }
  switch (nr) {  // arm32 EABI
    case 263:
      return Sys::ClockGettime;
    case 78:
      return Sys::Gettimeofday;
    case 20:
      return Sys::Getpid;
    case 24:
    case 199:
      return Sys::Getuid;
    case 49:
    case 201:
      return Sys::Geteuid;
    case 224:
      return Sys::Gettid;
    case 1:
      return Sys::Exit;
    case 248:
      return Sys::ExitGroup;
    case 90:
      return Sys::Mmap;  // old_mmap (byte offset)
    case 192:
      return Sys::Mmap2;  // mmap2: offset is in PAGES, not bytes
    case 91:
      return Sys::Munmap;
    case 125:
      return Sys::Mprotect;
    case 322:
      return Sys::Openat;
    case 5:
      return Sys::OpenLegacy;  // open(path,...): path in A0, not A1
    case 3:
      return Sys::Read;
    case 4:
      return Sys::Write;
    case 6:
      return Sys::Close;
    case 19:
      return Sys::Lseek;
    case 140:
      return Sys::Llseek;  // _llseek: 5 args, 64-bit offset via hi/lo + result*
    case 197:
      return Sys::Fstat;  // fstat64
    case 195:
    case 196:
      return Sys::StatPath;  // stat64 / lstat64 (path in A0)
    case 327:
      return Sys::Fstatat;  // fstatat64
    case 33:
      return Sys::AccessLegacy;  // access(path, mode)
    case 334:
      return Sys::Faccessat;
    case 332:
      return Sys::Readlinkat;
    case 162:
      return Sys::Nanosleep;
    case 242:
      return Sys::SchedGetaffinity;
    case 264:
      return Sys::ClockGetres;
    case 403:
      return Sys::ClockGettime;  // clock_gettime64 (32-bit time_t transition)
    case 37:
    case 238:
    case 268:
      return Sys::Noop;  // kill / tkill / tgkill
    case 173:
    case 174:
    case 175:
      return Sys::Noop;  // rt_sigreturn / rt_sigaction / rt_sigprocmask
    case 338:
    case 389:
    case 398:
      return Sys::Noop;  // set_robust_list / membarrier / rseq
    case 983042:
      return Sys::ArmCacheflush;  // 0xf0002
    case 983045:
      return Sys::ArmSetTls;  // 0xf0005
    case 384:
      return Sys::Getrandom;
    case 47:
    case 50:
    case 200:
    case 202:
      return Sys::Getgid;  // getgid / getegid (+ 32-bit variants)
    case 146:
      return Sys::Writev;
    case 45:
      return Sys::Brk;
    case 439:
      return Sys::Faccessat;  // faccessat2
    case 26:
      return Sys::Ptrace;
    case 240:
      return Sys::Futex;
    case 256:
      return Sys::SetTidAddress;
    case 158:
      return Sys::Noop;  // sched_yield
    case 172:
      return Sys::Prctl;
    case 220:
      return Sys::Madvise;
    case 163:
      return Sys::Mremap;
    case 122:
      return Sys::Uname;
    case 116:
      return Sys::Sysinfo;
    case 183:
      return Sys::Getcwd;
    case 55:
      return Sys::Fcntl;
    case 54:
      return Sys::Ioctl;
    default:
      return Sys::Unknown;
  }
}

// Fill an arm64 struct stat (st_mode @16, st_size @48) for a served fd.
// Syscall arguments follow the KERNEL ABI, which is NOT the C ABI: arm32 passes
// args in r0..r5 (AAPCS32 would put A4+ on the stack), x86_64 uses r10 instead
// of rcx, and i386 passes them in ebx..ebp (cdecl would put them all on the
// stack). So the dispatcher must never read arguments via Reg::A0..A7.
uint64_t sys_arg(Engine& e, int i) {
  static const int a64[6] = {UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                             UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5};
  static const int a32[6] = {UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                             UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5};
  static const int x64[6] = {UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
                             UC_X86_REG_R10, UC_X86_REG_R8,  UC_X86_REG_R9};
  static const int x32[6] = {UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
                             UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP};
  switch (e.abi()) {
    case Abi::Arm64:  return e.read_uc_reg(a64[i]);
    case Abi::Arm32:  return e.read_uc_reg(a32[i]);
    case Abi::X86_64: return e.read_uc_reg(x64[i]);
    case Abi::X86:    return e.read_uc_reg(x32[i]);
  }
  return 0;
}

void write_stat64(Engine& e, uint64_t st, size_t size, uint32_t mode = 0x81A4) {
  std::vector<uint8_t> zero(128, 0);
  e.write(st, zero.data(), zero.size());
  e.write_t<uint32_t>(st + 16, mode);  // st_mode (0x81A4 = S_IFREG|0644)
  e.write_t<uint64_t>(st + 48, size);  // st_size
}
constexpr uint32_t kStatDirMode = 0x41ED;  // S_IFDIR | 0755
constexpr size_t kDirSize = 4096;

// Short mnemonic for the syscall-observer trace. Covers the curated set we
// model; everything else is reported as "sys_<nr>".
const char* sys_name(Sys s) {
  switch (s) {
    case Sys::ClockGettime: return "clock_gettime";
    case Sys::Gettimeofday: return "gettimeofday";
    case Sys::Getpid: return "getpid";
    case Sys::Getuid: return "getuid";
    case Sys::Geteuid: return "geteuid";
    case Sys::Gettid: return "gettid";
    case Sys::Exit: return "exit";
    case Sys::ExitGroup: return "exit_group";
    case Sys::Mmap: return "mmap";
    case Sys::Munmap: return "munmap";
    case Sys::Mprotect: return "mprotect";
    case Sys::Openat: return "openat";
    case Sys::Read: return "read";
    case Sys::Write: return "write";
    case Sys::Close: return "close";
    case Sys::Lseek: return "lseek";
    case Sys::Fstat: return "fstat";
    case Sys::Fstatat: return "fstatat";
    case Sys::Faccessat: return "faccessat";
    case Sys::Getrandom: return "getrandom";
    case Sys::Ptrace: return "ptrace";
    case Sys::Nanosleep: return "nanosleep";
    case Sys::Futex: return "futex";
    case Sys::SetTidAddress: return "set_tid_address";
    case Sys::SchedGetaffinity: return "sched_getaffinity";
    case Sys::Prctl: return "prctl";
    case Sys::Madvise: return "madvise";
    case Sys::Mremap: return "mremap";
    case Sys::Readlinkat: return "readlinkat";
    case Sys::Uname: return "uname";
    case Sys::Sysinfo: return "sysinfo";
    case Sys::Getcwd: return "getcwd";
    case Sys::Fcntl: return "fcntl";
    case Sys::Ioctl: return "ioctl";
    case Sys::ClockGetres: return "clock_getres";
    case Sys::OpenLegacy: return "open";
    case Sys::AccessLegacy: return "access";
    case Sys::StatPath: return "stat64";
    case Sys::Mmap2: return "mmap2";
    case Sys::Llseek: return "_llseek";
    case Sys::ArmSetTls: return "ARM_set_tls";
    case Sys::ArmCacheflush: return "ARM_cacheflush";
    case Sys::Getgid: return "getgid";
    case Sys::Writev: return "writev";
    case Sys::Brk: return "brk";
    case Sys::Noop: return "noop";
    case Sys::Unknown: return "unknown";
  }
  return "unknown";
}
}  // namespace

void Syscalls::dispatch(Engine& e) {
  const uint64_t nr = e.read_reg(Reg::SyscallNr);

  // Syscall-observer trace: snapshot args on entry and fire (with the final
  // return value) on EVERY exit path via an RAII guard, so early-returning
  // handlers (kill/ESRCH, exit) are covered too. No cost when unobserved.
  struct ObsGuard {
    Syscalls* self;
    Engine& e;
    uint64_t nr;
    uint64_t args[6];
    ~ObsGuard() {
      if (self->observer_)
        self->observer_(nr, sys_name(normalize(e.abi(), nr)), args,
                        e.read_reg(Reg::Ret0));
    }
  } obs{this, e, nr, {}};
  if (observer_)
    for (int i = 0; i < 6; ++i)
      obs.args[i] = sys_arg(e, i);

  const int psz = e.pointer_size();
  auto ret = [&](uint64_t v) { e.write_reg(Reg::Ret0, v); };
  auto wword = [&](uint64_t addr, uint64_t v) {
    if (psz == 8)
      e.write_t<uint64_t>(addr, v);
    else
      e.write_t<uint32_t>(addr, static_cast<uint32_t>(v));
  };

  Sys s = normalize(e.abi(), nr);
  // VARDOGER_KILL_ESRCH: some anti-tamper watchdogs do kill(pid, SIGKILL) as a
  // probe and TRAP (brk) when it SUCCEEDS (they expect it to fail in a clean,
  // no-tracer environment). Default kill->0 (success) trips that trap; -ESRCH
  // ("no such process") is the faithful clean-env answer and lets the flow
  // proceed.
  if (std::getenv("VARDOGER_KILL_ESRCH") &&
      (nr == 129 || nr == 130 || nr == 131)) {
    ret(static_cast<uint64_t>(-3));
    return;  // -ESRCH
  }
  // VARDOGER_LEGACY_SYSCALLS: A/B toggle, force the expansion set back to -ENOSYS
  // to bisect a regression against the pre-expansion behavior. (Diagnostic
  // only.)
  if (std::getenv("VARDOGER_LEGACY_SYSCALLS")) switch (s) {
      case Sys::Futex:
      case Sys::SetTidAddress:
      case Sys::SchedGetaffinity:
      case Sys::Prctl:
      case Sys::Madvise:
      case Sys::Mremap:
      case Sys::Readlinkat:
      case Sys::Uname:
      case Sys::Sysinfo:
      case Sys::Getcwd:
      case Sys::Fcntl:
      case Sys::Ioctl:
      case Sys::ClockGetres:
        s = Sys::Unknown;
        break;
      default:
        break;
    }
  switch (s) {
    case Sys::Getpid:
      ret(1234);
      break;
    case Sys::Gettid:
      ret(1234);
      break;
    case Sys::Getuid:
    case Sys::Geteuid:
    case Sys::Getgid:
      ret(10234);
      break;
    case Sys::ArmCacheflush:
      ret(0);
      break;  // i-cache maintenance is a no-op for us
    case Sys::ArmSetTls:  // ARM_set_tls(tp): bionic sets the thread pointer
      e.write_uc_reg(UC_ARM_REG_C13_C0_3, sys_arg(e, 0));  // TPIDRURO
      ret(0);
      break;
    case Sys::Ptrace:
      ret(0);
      break;  // PTRACE_TRACEME "succeeds"
    case Sys::Noop:
      ret(0);
      break;  // signals/kill(tid,0) -> success
    case Sys::Exit:
    case Sys::ExitGroup:
      e.stop();
      break;

    case Sys::ClockGettime: {  // (clockid, timespec*)
      const int clk = static_cast<int>(sys_arg(e, 0));
      const uint64_t ns = sys_.now_ns(), tp = sys_arg(e, 1);
      const bool wall =
          (clk == 0 || clk == 5);  // CLOCK_REALTIME / _COARSE -> wall time
      const uint64_t sec = wall ? sys_.now_unix() : ns / 1'000'000'000ull;
      if (std::getenv("VARDOGER_TIME_LOG"))
        std::fprintf(stderr, "[clock_gettime] clk=%d -> sec=%llu (%#llx)\n",
                     clk, (unsigned long long)sec, (unsigned long long)sec);
      wword(tp, sec);
      wword(tp + psz, ns % 1'000'000'000ull);
      ret(0);
      break;
    }
    case Sys::Gettimeofday: {  // (timeval*, tz) -> wall time
      const uint64_t ns = sys_.now_ns(), tv = sys_arg(e, 0);
      wword(tv, sys_.now_unix());
      wword(tv + psz, (ns % 1'000'000'000ull) / 1000);
      ret(0);
      break;
    }
    case Sys::Mmap:
    case Sys::Mmap2: {  // (addr,len,prot,flags,fd,off)
      const uint64_t reqaddr = sys_arg(e, 0);
      const uint64_t len = sys_arg(e, 1), prot = sys_arg(e, 2);
      const uint64_t flags = sys_arg(e, 3);
      // mmap2 (armv7) passes the offset in 4 KiB PAGES, not bytes — scaling it
      // is what makes a file-backed mmap2 read from the right place.
      const uint64_t off =
          (s == Sys::Mmap2) ? (sys_arg(e, 5) << 12) : sys_arg(e, 5);
      const int64_t fd = static_cast<int64_t>(sys_arg(e, 4));
      constexpr uint64_t kMapAnonymous = 0x20, kMapFixed = 0x10;
      if (std::getenv("VARDOGER_MMAP_LOG"))
        std::fprintf(stderr,
                     "[mmap] req addr=%#llx len=%#llx prot=%#llx flags=%#llx "
                     "fd=%lld off=%#llx\n",
                     (unsigned long long)reqaddr, (unsigned long long)len,
                     (unsigned long long)prot, (unsigned long long)flags,
                     (long long)fd, (unsigned long long)off);
      // MAP_FIXED: honour the request at reqaddr in place. The range may span
      // mapped AND unmapped pages (a packer self-mapping a region at its own
      // base that extends past the loaded span -- some packer loaders do exactly
      // this) -> map the unmapped gaps, then (re)protect the whole range,
      // instead of bump-allocating over an existing region (which throws
      // UC_ERR_MAP).
      if (!std::getenv("VARDOGER_NO_MAPFIXED") && (flags & kMapFixed) && reqaddr) {
        const uint32_t mpf =
            static_cast<uint32_t>(prot) ? static_cast<uint32_t>(prot) : 3;
        const uint64_t lo = reqaddr & ~uint64_t(0xfff);
        const uint64_t hi =
            (reqaddr + (len ? len : 1) + 0xfff) & ~uint64_t(0xfff);
        // Map unmapped gaps; reuse (reprotect) already-mapped pages in place.
        // Tolerant: a packer may MAP_FIXED over the very region it's executing
        // from (packer self-decompress)
        // -> never throw; keep existing content, extend the range, and hand
        // back reqaddr.
        for (uint64_t p = lo; p < hi; p += 0x1000) {
          if (mem_.is_mapped(p)) {
            try {
              mem_.protect(p, 0x1000, mpf);
            } catch (...) {
            }
          } else {
            try {
              mem_.map_fixed(p, 0x1000, mpf, Memory::Kind::Mmap, "mmap-fixed");
            } catch (...) {
            }
          }
        }
        if (!(flags & kMapAnonymous) && fd >= 0 &&
            sys_.is_open(static_cast<int>(fd))) {
          sys_.vseek(static_cast<int>(fd), off);
          std::string content;
          sys_.vread(static_cast<int>(fd), content, len);
          if (!content.empty())
            e.write(reqaddr, content.data(), content.size());
        }
        ret(reqaddr);
        break;
      }
      uint32_t mp =
          static_cast<uint32_t>(prot) ? static_cast<uint32_t>(prot) : 3;
      static const bool wx = std::getenv("VARDOGER_WX") !=
                             nullptr;  // W^X: strip exec from writable maps
      if (wx && (mp & UC_PROT_WRITE) && (mp & UC_PROT_EXEC))
        mp &= ~UC_PROT_EXEC;
      const uint64_t addr = mem_.mmap_alloc(len, mp, "mmap (syscall)");
      // File-backed mmap: fill the mapping from the fd's virtual file.
      if (!(flags & kMapAnonymous) && fd >= 0 &&
          sys_.is_open(static_cast<int>(fd))) {
        sys_.vseek(static_cast<int>(fd), off);
        std::string content;
        sys_.vread(static_cast<int>(fd), content, len);
        if (!content.empty()) e.write(addr, content.data(), content.size());
        std::fprintf(stderr,
                     "[mmap] file-backed fd=%lld off=%#llx len=%#llx -> %#llx "
                     "(%zu bytes)\n",
                     (long long)fd, (unsigned long long)off,
                     (unsigned long long)len, (unsigned long long)addr,
                     content.size());
      }
      ret(addr);
      break;
    }
    case Sys::Munmap:
      ret(0);
      break;
    case Sys::Mprotect: {  // (addr,len,prot)
      // NOTE: do NOT W^X-strip mprotect, packers mprotect their OWN.text to
      // RWX for in-place (de)compression; stripping exec there breaks the
      // loader. W^X targets FRESH mmap decrypt buffers only (handled in the
      // Mmap case + libc mmap).
      mem_.protect(sys_arg(e, 0), sys_arg(e, 1),
                   static_cast<uint32_t>(sys_arg(e, 2)));
      ret(0);
      break;
    }
    case Sys::OpenLegacy: {  // open(path, flags, mode) — path in A0
      const std::string path = e.read_cstr(sys_arg(e, 0));
      const int flags = static_cast<int>(sys_arg(e, 1));
      const int fd = sys_.vopen(path, flags);
      if (std::getenv("VARDOGER_OPEN_LOG"))
        std::fprintf(stderr, "[open] \"%s\" (flags=%#x) -> %s\n", path.c_str(),
                     flags, fd ? "served" : "ENOENT");
      ret(fd ? static_cast<uint64_t>(fd) : static_cast<uint64_t>(-2));
      break;
    }
    case Sys::AccessLegacy: {  // access(path, mode) — path in A0
      const std::string path = e.read_cstr(sys_arg(e, 0));
      bool ok = sys_.vexists(path);
      if (!ok) {
        const int fd = sys_.vopen(path);
        if (fd) { ok = true; sys_.vclose(fd); }
      }
      if (std::getenv("VARDOGER_OPEN_LOG"))
        std::fprintf(stderr, "[access] \"%s\" -> %s\n", path.c_str(),
                     ok ? "ok" : "ENOENT");
      ret(ok ? 0 : static_cast<uint64_t>(-2));
      break;
    }
    case Sys::StatPath: {  // stat64/lstat64(path, statbuf) — path in A0
      const std::string path = e.read_cstr(sys_arg(e, 0));
      const int fd = sys_.vopen(path);
      if (fd) {
        write_stat64(e, sys_arg(e, 1), sys_.vsize(fd));
        sys_.vclose(fd);
        ret(0);
      } else if (sys_.is_dir(path)) {
        write_stat64(e, sys_arg(e, 1), kDirSize, kStatDirMode);
        ret(0);
      } else {
        ret(static_cast<uint64_t>(-2));
      }
      break;
    }
    case Sys::Llseek: {  // (fd, off_hi, off_lo, result*, whence)
      const int fd = static_cast<int>(sys_arg(e, 0));
      if (!sys_.is_open(fd)) { ret(static_cast<uint64_t>(-9)); break; }
      const uint64_t off = (sys_arg(e, 1) << 32) | (sys_arg(e, 2) & 0xffffffffu);
      const uint64_t resultp = sys_arg(e, 3);
      const int whence = static_cast<int>(sys_arg(e, 4));
      const size_t cur = sys_.vtell(fd), sz = sys_.vsize(fd);
      const size_t pos = whence == 1   ? cur + off
                         : whence == 2 ? sz + off
                                       : static_cast<size_t>(off);
      sys_.vseek(fd, pos);
      if (resultp) e.write_t<uint64_t>(resultp, pos);  // loff_t result
      ret(0);
      break;
    }
    case Sys::Writev: {  // (fd, iovec*, iovcnt) -> total bytes "written"
      const int fd = static_cast<int>(sys_arg(e, 0));
      const uint64_t iov = sys_arg(e, 1);
      const int cnt = static_cast<int>(sys_arg(e, 2));
      uint64_t total = 0;
      for (int i = 0; i < cnt && i < 1024; ++i) {
        // struct iovec { void* base; size_t len; } — pointer-sized fields
        const uint64_t base = psz == 8 ? e.read_t<uint64_t>(iov + i * 16)
                                       : e.read_t<uint32_t>(iov + i * 8);
        const uint64_t len = psz == 8 ? e.read_t<uint64_t>(iov + i * 16 + 8)
                                      : e.read_t<uint32_t>(iov + i * 8 + 4);
        if (!len) continue;
        std::vector<uint8_t> buf(len);
        try { e.read(base, buf.data(), len); } catch (...) { break; }
        if (sys_.is_open(fd)) sys_.vwrite(fd, buf.data(), buf.size());
        else if (fd == 1 || fd == 2)
          std::fwrite(buf.data(), 1, buf.size(), fd == 1 ? stdout : stderr);
        total += len;
      }
      ret(total);
      break;
    }
    case Sys::Brk: {  // brk(addr): we don't model a real break; report it
      // Returning the requested address (or a stable non-zero break for the
      // query form) keeps bionic's malloc from treating it as a hard failure;
      // real allocation goes through mmap anyway.
      const uint64_t want = sys_arg(e, 0);
      static uint64_t s_brk = 0;
      if (!s_brk) s_brk = mem_.heap_alloc(0x1000);
      if (want > s_brk) s_brk = want;
      ret(s_brk);
      break;
    }
    case Sys::Openat: {  // (dirfd, path, flags, mode)
      const std::string path = e.read_cstr(sys_arg(e, 1));
      const int flags = static_cast<int>(sys_arg(e, 2));
      const int fd = sys_.vopen(path, flags);
      std::fprintf(
          stderr, "[openat] \"%s\" (flags=%#x) -> %s", path.c_str(), flags,
          fd ? (Vfs::wants_write(flags) ? "created" : "served") : "ENOENT");
      if (path.empty() && std::getenv("VARDOGER_OPEN_LR"))
        std::fprintf(stderr, "  lr=%#llx",
                     (unsigned long long)e.read_reg(Reg::Lr));
      std::fprintf(stderr, "\n");
      ret(fd ? static_cast<uint64_t>(fd)
             : static_cast<uint64_t>(-2));  // -ENOENT
      break;
    }
    case Sys::Read: {  // (fd, buf, count)
      const int fd = static_cast<int>(sys_arg(e, 0));
      const uint64_t buf = sys_arg(e, 1), count = sys_arg(e, 2);
      if (!sys_.is_open(fd)) {
        ret(static_cast<uint64_t>(-9));
        break;
      }  // -EBADF
      const size_t at = sys_.vtell(fd);
      std::string out;
      const size_t got = sys_.vread(fd, out, count);
      if (got) e.write(buf, out.data(), got);
      if (std::getenv("VARDOGER_READ_LOG"))
        std::fprintf(stderr, "[read] fd=%d @%#zx count=%#zx -> %#zx\n", fd, at,
                     (size_t)count, got);
      ret(got);
      break;
    }
    case Sys::Write: {  // (fd, buf, count)
      const int fd = static_cast<int>(sys_arg(e, 0));
      const uint64_t buf = sys_arg(e, 1), count = sys_arg(e, 2);
      if (!sys_.is_open(fd)) {
        ret(count);
        break;
      }  // 1/2 = stdout/err: pretend written
      const uint64_t cap = count > 0x4000000
                               ? 0x4000000
                               : count;  // guard bogus len (anti-tamper)
      std::vector<uint8_t> b(cap, 0);
      for (uint64_t o = 0; o < cap;) {  // tolerant: only mapped pages
        const uint64_t nx = ((buf + o) & ~uint64_t(0xfff)) + 0x1000;
        const uint64_t en = nx < buf + cap ? nx : buf + cap, c = en - (buf + o);
        if (mem_.is_mapped(buf + o)) {
          try {
            e.read(buf + o, b.data() + o, c);
          } catch (...) {
          }
        }
        o += c;
      }
      ret(sys_.vwrite(fd, b.data(), cap));
      break;
    }
    case Sys::Close:
      sys_.vclose(static_cast<int>(sys_arg(e, 0)));
      ret(0);
      break;
    case Sys::Fstat: {  // (fd, statbuf)
      const int fd = static_cast<int>(sys_arg(e, 0));
      if (!sys_.is_open(fd)) {
        ret(static_cast<uint64_t>(-9));
        break;
      }
      write_stat64(e, sys_arg(e, 1), sys_.vsize(fd));
      ret(0);
      break;
    }
    case Sys::Nanosleep:  // don't actually sleep, but YIELD cooperatively so
      if (!std::getenv("VARDOGER_NO_SLEEP_YIELD") && yield_ && yield_())
        break;  // another thread can run
      ret(0);
      break;
    case Sys::Faccessat: {  // (dirfd, path, mode, flags) -> 0 / -ENOENT
      const std::string path = e.read_cstr(sys_arg(e, 1));
      // A served file, a synthetic /proc entry, or a registered app directory
      // (e.g. the /data/app code dir) all count as "exists".
      bool ok = sys_.vexists(path);
      if (!ok) {
        const int fd = sys_.vopen(path);
        if (fd) {
          ok = true;
          sys_.vclose(fd);
        }
      }
      if (std::getenv("VARDOGER_OPEN_LOG"))
        std::fprintf(stderr, "[faccessat] \"%s\" -> %s\n", path.c_str(),
                     ok ? "ok" : "ENOENT");
      ret(ok ? 0 : static_cast<uint64_t>(-2));  // exists -> 0, else -ENOENT
      break;
    }
    case Sys::Fstatat: {  // (dirfd, path, statbuf, flags)
      const std::string path = e.read_cstr(sys_arg(e, 1));
      const int fd = sys_.vopen(path);
      if (fd) {  // a regular file
        write_stat64(e, sys_arg(e, 2), sys_.vsize(fd));
        sys_.vclose(fd);
        ret(0);
        break;
      }
      if (sys_.is_dir(path)) {  // an installed-app directory
        write_stat64(e, sys_arg(e, 2), kDirSize, kStatDirMode);
        ret(0);
        break;
      }
      ret(static_cast<uint64_t>(-2));
      break;
    }
    case Sys::Lseek: {  // (fd, off, whence)
      const int fd = static_cast<int>(sys_arg(e, 0));
      if (!sys_.is_open(fd)) {
        ret(static_cast<uint64_t>(-9));
        break;
      }
      const int64_t off = static_cast<int64_t>(sys_arg(e, 1));
      const int whence = static_cast<int>(sys_arg(e, 2));
      const size_t cur = sys_.vtell(fd), sz = sys_.vsize(fd);
      const size_t pos = whence == 1   ? cur + off
                         : whence == 2 ? sz + off
                                       : static_cast<size_t>(off);
      sys_.vseek(fd, pos);
      if (std::getenv("VARDOGER_READ_LOG"))
        std::fprintf(stderr,
                     "[lseek] fd=%d whence=%d off=%lld -> @%#zx (size=%#zx)\n",
                     fd, whence, (long long)off, pos, sz);
      ret(pos);
      break;
    }
    case Sys::Getrandom: {  // (buf, len, flags)
      const uint64_t buf = sys_arg(e, 0), len = sys_arg(e, 1);
      std::vector<uint8_t> r(len);
      for (size_t i = 0; i < r.size(); ++i)
        r[i] = static_cast<uint8_t>(0x9E * (i + 1));  // deterministic
      if (len) e.write(buf, r.data(), len);
      ret(len);
      break;
    }
    // ---- expansion ----
    case Sys::Futex: {
      // (uaddr, op, val, ...). Single-threaded emulation: WAIT never blocks
      // (the value already changed), WAKE wakes nobody. Return 0 (WAKE would
      // return #woken=0). Masking FUTEX_PRIVATE (0x80) + FUTEX_CLOCK_REALTIME
      // (0x100) leaves the base op; all base ops -> 0 here.
      ret(0);
      break;
    }
    case Sys::SetTidAddress:
      ret(1234);
      break;                       // returns the caller's tid
    case Sys::SchedGetaffinity: {  // (pid, cpusetsize, mask*) -> bytes written
      const uint64_t sz = sys_arg(e, 1), mask = sys_arg(e, 2);
      const uint64_t n =
          sz && sz < 128 ? sz
                         : 8;  // present 8 online CPUs (popcount checks pass)
      std::vector<uint8_t> m(n, 0);
      m[0] = 0xff;  // CPUs 0..7 online
      if (mask) e.write(mask, m.data(), n);
      ret(n);
      break;
    }
    case Sys::Prctl: {  // (option, ...) -> 0 for the naming/vma opts
      const uint64_t opt = sys_arg(e, 0);
      if (opt == 16) {  // PR_GET_NAME: write the 16-byte comm (progname[:15]+NUL)
        const uint64_t p = sys_arg(e, 1);
        if (p) {
          char nm[16] = {0};
          const std::string pn = sys_.progname();
          const size_t n = pn.size() > 15 ? 15 : pn.size();
          std::memcpy(nm, pn.data(), n);  // nm[n..15] stay 0
          e.write(p, nm, sizeof(nm));
        }
      }
      ret(0);  // PR_SET_NAME(15)/PR_SET_VMA(0x53564d41)/... ok
      break;
    }
    case Sys::Madvise:
      ret(0);
      break;             // advisory -> success
    case Sys::Mremap: {  // (old, oldsz, newsz, flags, newaddr) -> grow-copy
      const uint64_t old = sys_arg(e, 0), oldsz = sys_arg(e, 1),
                     newsz = sys_arg(e, 2);
      if (newsz <= oldsz) {
        ret(old);
        break;
      }  // shrink/in-place: keep the mapping
      const uint64_t np =
          mem_.mmap_alloc(newsz, UC_PROT_READ | UC_PROT_WRITE, "mremap");
      if (oldsz && mem_.is_mapped(old)) {
        std::vector<uint8_t> b(oldsz);
        e.read(old, b.data(), oldsz);
        e.write(np, b.data(), oldsz);
      }
      ret(np);
      break;
    }
    case Sys::Readlinkat: {  // (dirfd, path, buf, bufsiz)
      const std::string path = e.read_cstr(sys_arg(e, 1));
      const uint64_t buf = sys_arg(e, 2), bufsiz = sys_arg(e, 3);
      std::string tgt;
      if (path.find("self/exe") != std::string::npos)
        tgt = "/system/bin/app_process64";
      else if (path.find("self/cwd") != std::string::npos)
        tgt = "/";
      if (tgt.empty()) {
        ret(static_cast<uint64_t>(-22));
        break;
      }  // -EINVAL (not a symlink)
      const uint64_t n = tgt.size() < bufsiz ? tgt.size() : bufsiz;
      if (buf && n) e.write(buf, tgt.data(), n);
      ret(n);  // readlink does NOT NUL-terminate
      break;
    }
    case Sys::Uname: {  // struct utsname: 6 x 65-byte fields
      const uint64_t p = sys_arg(e, 0);
      std::vector<uint8_t> u(6 * 65, 0);
      auto put = [&](int i, const char* s) {
        std::snprintf(reinterpret_cast<char*>(u.data() + i * 65), 65, "%s", s);
      };
      put(0, "Linux");
      put(1, "localhost");
      put(2, "4.14.180-perf+");
      put(3, "#1 SMP PREEMPT");
      put(4, "aarch64");
      put(5, "localdomain");
      if (p) e.write(p, u.data(), u.size());
      ret(0);
      break;
    }
    case Sys::Sysinfo: {  // struct sysinfo (arm64): uptime@0, loads@8,
      const uint64_t p =
          sys_arg(e, 0);  // totalram@40, freeram@48, mem_unit@112(u32)
      std::vector<uint8_t> s(128, 0);
      auto u64 = [&](int off, uint64_t v) {
        std::memcpy(s.data() + off, &v, 8);
      };
      u64(0, 43200);  // uptime ~12h (not freshly-booted -> less "emu")
      u64(40, 6ull * 1024 * 1024 *
                  1024);  // totalram 6 GiB (emu-detect wants real-ish RAM)
      u64(48, 3ull * 1024 * 1024 * 1024);  // freeram 3 GiB
      uint32_t unit = 1;
      std::memcpy(s.data() + 112, &unit, 4);
      if (p) e.write(p, s.data(), s.size());
      ret(0);
      break;
    }
    case Sys::Getcwd: {  // (buf, size) -> writes path incl NUL, returns len
      const uint64_t buf = sys_arg(e, 0), sz = sys_arg(e, 1);
      const std::string cwd = "/";
      if (buf && sz > cwd.size()) e.write(buf, cwd.c_str(), cwd.size() + 1);
      ret(buf);  // bionic getcwd returns the buffer ptr
      break;
    }
    case Sys::Fcntl:
      ret(0);
      break;  // F_SETFD/F_SETFL/F_GETFL -> benign 0
    case Sys::Ioctl:
      ret(0);
      break;                  // TCGETS/etc. -> 0 (not a tty, but harmless)
    case Sys::ClockGetres: {  // (clockid, timespec*) -> 1ns resolution
      const uint64_t tp = sys_arg(e, 1);
      if (tp) {
        wword(tp, 0);
        wword(tp + psz, 1);
      }
      ret(0);
      break;
    }

    case Sys::Unknown:
    default: {
      // Rate-limit: a guest that spins on an unhandled syscall (a futex wait,
      // an anti-emulation loop) would otherwise flood stderr and fill the disk.
      // Log the first few per number, then go quiet (a periodic heartbeat every
      // 100k).
      static std::unordered_map<uint64_t, uint64_t> seen;
      const uint64_t c = ++seen[nr];
      if (c <= 5 || (c % 100000) == 0)
        std::fprintf(stderr,
                     "[syscall] unhandled #%llu (abi=%s) pc=%#llx lr=%#llx -> "
                     "-ENOSYS%s\n",
                     static_cast<unsigned long long>(nr),
                     e.abi() == Abi::Arm64 ? "arm64" : "arm32",
                     (unsigned long long)e.read_reg(Reg::Pc),
                     (unsigned long long)e.read_reg(Reg::Lr),
                     c == 5 ? "  [further logs for this nr suppressed]" : "");
      ret(static_cast<uint64_t>(-38));  // -ENOSYS
      break;
    }
  }
}

}  // namespace vardoger
