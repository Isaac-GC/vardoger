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
      default:
        return Sys::Unknown;
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
    case 192:
      return Sys::Mmap;
    case 91:
      return Sys::Munmap;
    case 125:
      return Sys::Mprotect;
    case 322:
      return Sys::Openat;
    case 3:
      return Sys::Read;
    case 4:
      return Sys::Write;
    case 6:
      return Sys::Close;
    case 19:
    case 140:
      return Sys::Lseek;
    case 197:
      return Sys::Fstat;  // fstat64
    case 384:
      return Sys::Getrandom;
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
void write_stat64(Engine& e, uint64_t st, size_t size) {
  std::vector<uint8_t> zero(128, 0);
  e.write(st, zero.data(), zero.size());
  e.write_t<uint32_t>(st + 16, 0x81A4);  // S_IFREG | 0644
  e.write_t<uint64_t>(st + 48, size);    // st_size
}
}  // namespace

void Syscalls::dispatch(Engine& e) {
  const uint64_t nr = e.read_reg(Reg::SyscallNr);
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
      ret(10234);
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
      const int clk = static_cast<int>(e.read_reg(Reg::A0));
      const uint64_t ns = sys_.now_ns(), tp = e.read_reg(Reg::A1);
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
      const uint64_t ns = sys_.now_ns(), tv = e.read_reg(Reg::A0);
      wword(tv, sys_.now_unix());
      wword(tv + psz, (ns % 1'000'000'000ull) / 1000);
      ret(0);
      break;
    }
    case Sys::Mmap: {  // (addr,len,prot,flags,fd,off)
      const uint64_t reqaddr = e.read_reg(Reg::A0);
      const uint64_t len = e.read_reg(Reg::A1), prot = e.read_reg(Reg::A2);
      const uint64_t flags = e.read_reg(Reg::A3), off = e.read_reg(Reg::A5);
      const int64_t fd = static_cast<int64_t>(e.read_reg(Reg::A4));
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
      // base that extends past the loaded span -- Ijiami libexec does exactly
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
        // from (Ijiami libexec self-decompress)
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
      mem_.protect(e.read_reg(Reg::A0), e.read_reg(Reg::A1),
                   static_cast<uint32_t>(e.read_reg(Reg::A2)));
      ret(0);
      break;
    }
    case Sys::Openat: {  // (dirfd, path, flags, mode)
      const std::string path = e.read_cstr(e.read_reg(Reg::A1));
      const int flags = static_cast<int>(e.read_reg(Reg::A2));
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
      const int fd = static_cast<int>(e.read_reg(Reg::A0));
      const uint64_t buf = e.read_reg(Reg::A1), count = e.read_reg(Reg::A2);
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
      const int fd = static_cast<int>(e.read_reg(Reg::A0));
      const uint64_t buf = e.read_reg(Reg::A1), count = e.read_reg(Reg::A2);
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
      sys_.vclose(static_cast<int>(e.read_reg(Reg::A0)));
      ret(0);
      break;
    case Sys::Fstat: {  // (fd, statbuf)
      const int fd = static_cast<int>(e.read_reg(Reg::A0));
      if (!sys_.is_open(fd)) {
        ret(static_cast<uint64_t>(-9));
        break;
      }
      write_stat64(e, e.read_reg(Reg::A1), sys_.vsize(fd));
      ret(0);
      break;
    }
    case Sys::Nanosleep:  // don't actually sleep, but YIELD cooperatively so
      if (!std::getenv("VARDOGER_NO_SLEEP_YIELD") && yield_ && yield_())
        break;  // another thread can run
      ret(0);
      break;
    case Sys::Faccessat: {  // (dirfd, path, mode, flags) -> 0 / -ENOENT
      const std::string path = e.read_cstr(e.read_reg(Reg::A1));
      const int fd = sys_.vopen(path);
      if (fd) sys_.vclose(fd);
      if (std::getenv("VARDOGER_OPEN_LOG"))
        std::fprintf(stderr, "[faccessat] \"%s\" -> %s\n", path.c_str(),
                     fd ? "ok" : "ENOENT");
      ret(fd ? 0 : static_cast<uint64_t>(-2));  // exists -> 0, else -ENOENT
      break;
    }
    case Sys::Fstatat: {  // (dirfd, path, statbuf, flags)
      const int fd = sys_.vopen(e.read_cstr(e.read_reg(Reg::A1)));
      if (!fd) {
        ret(static_cast<uint64_t>(-2));
        break;
      }
      write_stat64(e, e.read_reg(Reg::A2), sys_.vsize(fd));
      sys_.vclose(fd);
      ret(0);
      break;
    }
    case Sys::Lseek: {  // (fd, off, whence)
      const int fd = static_cast<int>(e.read_reg(Reg::A0));
      if (!sys_.is_open(fd)) {
        ret(static_cast<uint64_t>(-9));
        break;
      }
      const int64_t off = static_cast<int64_t>(e.read_reg(Reg::A1));
      const int whence = static_cast<int>(e.read_reg(Reg::A2));
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
      const uint64_t buf = e.read_reg(Reg::A0), len = e.read_reg(Reg::A1);
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
      const uint64_t sz = e.read_reg(Reg::A1), mask = e.read_reg(Reg::A2);
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
      const uint64_t opt = e.read_reg(Reg::A0);
      if (opt == 16) {  // PR_GET_NAME: write a 16-byte thread name
        const uint64_t p = e.read_reg(Reg::A1);
        if (p) {
          const char nm[16] = "app_process";
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
      const uint64_t old = e.read_reg(Reg::A0), oldsz = e.read_reg(Reg::A1),
                     newsz = e.read_reg(Reg::A2);
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
      const std::string path = e.read_cstr(e.read_reg(Reg::A1));
      const uint64_t buf = e.read_reg(Reg::A2), bufsiz = e.read_reg(Reg::A3);
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
      const uint64_t p = e.read_reg(Reg::A0);
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
          e.read_reg(Reg::A0);  // totalram@40, freeram@48, mem_unit@112(u32)
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
      const uint64_t buf = e.read_reg(Reg::A0), sz = e.read_reg(Reg::A1);
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
      const uint64_t tp = e.read_reg(Reg::A1);
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
