#include "vardoger/android/stubs.hpp"

#include <fnmatch.h>
#include <zlib.h>

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "vardoger/android/syscalls.hpp"
#include "vardoger/android/system.hpp"
#include "vardoger/engine/scheduler.hpp"

namespace vardoger {

namespace {
constexpr size_t kWorkerStack =
    0x100000;  // 1 MiB private stack per synchronous worker

// Read a guest buffer WITHOUT throwing on unmapped pages or a bogus length.
// Packers pass anti-tamper scratch buffers (e.g. writing a ".jgck" check file)
// whose length/pointer are computed and may land partly unmapped; a throwing
// read aborts the whole unpack. Cap the length, read mapped pages, zero the
// rest. Returns exactly min(n, cap) bytes.
std::vector<uint8_t> read_guest_tolerant(Engine& e, Memory& mem, uint64_t addr,
                                         uint64_t n) {
  constexpr uint64_t kCap = 0x1000000;  // 16 MiB, far above any real write;
                                        // guards against a bogus len
  const uint64_t len = n > kCap ? kCap : n;
  std::vector<uint8_t> b(len, 0);
  for (uint64_t off = 0; off < len;) {
    const uint64_t page = (addr + off) & ~uint64_t(0xfff);
    const uint64_t next = page + 0x1000;
    const uint64_t end = next < addr + len ? next : addr + len;
    const uint64_t cnt = end - (addr + off);
    if (mem.is_mapped(addr + off)) {
      try {
        e.read(addr + off, b.data() + off, cnt);
      } catch (...) {
      }
    }
    off += cnt;
  }
  return b;
}

// AAPCS64 variadic integer/pointer arg #i: x0..x7 then 8-byte stack slots.
uint64_t aapcs_arg(Engine& e, int i) {
  static const int xr[8] = {UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                            UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5,
                            UC_ARM64_REG_X6, UC_ARM64_REG_X7};
  if (i < 8) return e.read_uc_reg(xr[i]);
  return e.read_t<uint64_t>(e.read_reg(Reg::Sp) + 8 * (i - 8));
}

// Expand a guest printf-style format. `argi` is the index of the first variadic
// arg (2 for sprintf, 3 for snprintf); it advances as args are consumed.
// Handles flags/width/precision (incl. '*'), length modifiers, and d i u o x X
// p c s %.
std::string fmt_expand_cb(Engine& e, uint64_t fmt_ptr,
                          const std::function<uint64_t()>& nextarg) {
  const std::string fmt = e.read_cstr(fmt_ptr);
  std::string out;
  for (size_t i = 0; i < fmt.size();) {
    if (fmt[i] != '%') {
      out += fmt[i++];
      continue;
    }
    std::string spec = "%";
    ++i;
    while (i < fmt.size() && std::strchr("-+ 0#", fmt[i])) spec += fmt[i++];
    if (i < fmt.size() && fmt[i] == '*') {
      spec += std::to_string(int(nextarg()));
      ++i;
    } else
      while (i < fmt.size() && std::isdigit((unsigned char)fmt[i]))
        spec += fmt[i++];
    if (i < fmt.size() && fmt[i] == '.') {
      spec += '.';
      ++i;
      if (i < fmt.size() && fmt[i] == '*') {
        spec += std::to_string(int(nextarg()));
        ++i;
      } else
        while (i < fmt.size() && std::isdigit((unsigned char)fmt[i]))
          spec += fmt[i++];
    }
    int len = 0;  // 0=int, 1=long, 2=long long / size_t
    while (i < fmt.size() && std::strchr("lhzjt", fmt[i])) {
      if (fmt[i] == 'l')
        ++len;
      else if (std::strchr("zjt", fmt[i]))
        len = 2;
      ++i;
    }
    if (i >= fmt.size()) {
      out += spec;
      break;
    }
    const char conv = fmt[i++];
    std::vector<char> buf(256);
    auto put = [&](const std::string& hostspec, auto val) {
      int need = std::snprintf(buf.data(), buf.size(), hostspec.c_str(), val);
      if (need >= int(buf.size())) {
        buf.resize(need + 1);
        std::snprintf(buf.data(), buf.size(), hostspec.c_str(), val);
      }
      out += buf.data();
    };
    switch (conv) {
      case '%':
        out += '%';
        break;
      case 'd':
      case 'i':
        put(spec + "lld",
            (long long)(len >= 1 ? (int64_t)nextarg() : (int32_t)nextarg()));
        break;
      case 'u':
      case 'o':
      case 'x':
      case 'X':
        put(spec + "ll" + conv,
            (unsigned long long)(len >= 1 ? nextarg() : (uint32_t)nextarg()));
        break;
      case 'p':
        put("%p", (void*)(uintptr_t)nextarg());
        break;
      case 'c':
        put(spec + "c", (int)nextarg());
        break;
      case 's': {
        const uint64_t sp = nextarg();
        const std::string s = sp ? e.read_cstr(sp) : "(null)";
        buf.resize(s.size() + 256);
        std::snprintf(buf.data(), buf.size(), (spec + "s").c_str(), s.c_str());
        out += buf.data();
        break;
      }
      default:
        out += spec;
        out += conv;
        break;
    }
  }
  return out;
}
// printf-family: args via AAPCS positions starting at `argi`.
std::string fmt_expand(Engine& e, uint64_t fmt_ptr, int argi) {
  return fmt_expand_cb(e, fmt_ptr,
                       [&e, argi]() mutable { return aapcs_arg(e, argi++); });
}
// vprintf-family: args via an AArch64 va_list (struct: stack@0, gr_top@8,
// vr_top@16, gr_offs@24 (i32), vr_offs@28). Integer/pointer args only
// (sufficient for %x/%s/%d).
std::string fmt_expand_va(Engine& e, uint64_t fmt_ptr, uint64_t va) {
  return fmt_expand_cb(e, fmt_ptr, [&e, va]() -> uint64_t {
    int32_t gr_offs = e.read_t<int32_t>(va + 24);
    if (gr_offs < 0) {
      const uint64_t v =
          e.read_t<uint64_t>(e.read_t<uint64_t>(va + 8) + gr_offs);
      e.write_t<int32_t>(va + 24, gr_offs + 8);
      return v;
    }
    const uint64_t stack = e.read_t<uint64_t>(va + 0);
    e.write_t<uint64_t>(va + 0, stack + 8);
    return e.read_t<uint64_t>(stack);
  });
}
}  // namespace

Stubs::Stubs(Engine& engine, Memory& mem, Trampoline& tramp)
    : engine_(engine), mem_(mem), tramp_(tramp) {}

void Stubs::add(const std::string& name, Trampoline::Handler h) {
  by_name_[name] = tramp_.alloc(name, std::move(h));
}

uint64_t Stubs::resolve(const std::string& name) {
  auto it = by_name_.find(name);
  if (it != by_name_.end()) return it->second;
  // Dalvik-runtime symbols (dvm*) don't exist on ART. Resolve to NULL (like a
  // real ART device) so packers' "is Dalvik present?" probes detect ART and
  // take the right path.
  if (!std::getenv("VARDOGER_NO_DALVIK_NULL") &&
      name.find("dvm") != std::string::npos)
    return 0;
  // Unknown import: hand back a logging stub so the slot is valid, and we learn
  // (when it is actually called) which function to implement next.
  const uint64_t addr = tramp_.alloc("MISSING:" + name, [name](Engine& e) {
    std::fprintf(stderr,
                 "[stub] unimplemented import '%s' called -> returning 0\n",
                 name.c_str());
    e.write_reg(Reg::Ret0, 0);
  });
  by_name_[name] = addr;
  return addr;
}

void Stubs::set_progname(const std::string& name) {
  // Fresh string buffer each call so the name can grow; the pointer cell is
  // allocated once and kept stable so a GOT slot already relocated to it stays
  // valid even if the name changes after load.
  const uint64_t str =
      mem_.mmap_alloc(name.size() + 1, UC_PROT_READ | UC_PROT_WRITE, "progname");
  engine_.write(str, name.c_str(), name.size() + 1);
  if (!progname_cell_)
    progname_cell_ =
        mem_.mmap_alloc(8, UC_PROT_READ | UC_PROT_WRITE, "__progname");
  engine_.write_t<uint64_t>(progname_cell_, str);
  progname_str_ = str;
  // These are DATA symbols: bionic declares `extern const char* __progname;`, so
  // the loader relocates a reference to the ADDRESS of the char* cell, and guest
  // code loads [cell] to get the string pointer.
  by_name_["__progname"] = progname_cell_;
  by_name_["program_invocation_short_name"] = progname_cell_;
  by_name_["program_invocation_name"] = progname_cell_;
  // getprogname() returns the char* itself (not the cell).
  if (!progname_fn_) {
    add("getprogname",
        [this](Engine& e) { e.write_reg(Reg::Ret0, progname_str_); });
    progname_fn_ = true;
  }
}

// Drive one step of the dl_iterate_phdr loop: build dl_phdr_info for the
// current lib and redirect into the guest callback (which returns to
// dl_return_stub_). When the list is exhausted, return 0 to the original
// caller.
void Stubs::dl_iter_step() {
  if (dl_idx_ >= phdr_libs_.size()) {
    engine_.write_reg(Reg::Ret0, 0);
    engine_.redirect(dl_ret_lr_);
    return;
  }
  const PhdrLib& L = phdr_libs_[dl_idx_++];
  for (uint64_t o = 0; o < 64; o += 8)
    engine_.write_t<uint64_t>(dl_info_buf_ + o, 0);
  engine_.write_t<uint64_t>(dl_info_buf_ + 0,
                            L.dlpi_addr);  // dlpi_addr (load base)
  engine_.write_t<uint64_t>(dl_info_buf_ + 8, L.name_addr);   // dlpi_name
  engine_.write_t<uint64_t>(dl_info_buf_ + 16, L.phdr_addr);  // dlpi_phdr
  engine_.write_t<uint16_t>(dl_info_buf_ + 24, L.phnum);      // dlpi_phnum
  engine_.write_reg(Reg::A0, dl_info_buf_);
  engine_.write_reg(Reg::A1, 64);
  engine_.write_reg(Reg::A2, dl_data_);
  engine_.write_reg(Reg::Lr, dl_return_stub_);
  engine_.redirect(dl_cb_);
}

void Stubs::register_pthreads() {
  auto on = [this] { return sched_ && sched_->active(); };

  // pthread_create: register a cooperative worker (runs when the creator
  // yields), or fall back to running it inline if no scheduler is active (e.g.
  // init_array).
  add("pthread_create",
      [this, on](Engine& e) {  // (pthread_t* out, attr, routine, arg)
        const uint64_t out = e.read_reg(Reg::A0);
        const uint64_t routine = e.read_reg(Reg::A2), arg = e.read_reg(Reg::A3);
        if (on()) {
          sched_->spawn(e, out, routine, arg);
          return;
        }  // worker runs first
        if (e.abi() != Abi::Arm64) {
          e.write_reg(Reg::Ret0, 0);
          return;
        }
        const uint64_t tid = next_tid_++;  // inline fallback (no scheduler)
        if (out) e.write_t<uint64_t>(out, tid);
        ThreadCtx ctx{};
        ctx.tid = tid;
        ctx.ret_lr = e.read_reg(Reg::Lr);
        ctx.sp = e.read_reg(Reg::Sp);
        static const int saved_id[12] = {
            UC_ARM64_REG_X19, UC_ARM64_REG_X20, UC_ARM64_REG_X21,
            UC_ARM64_REG_X22, UC_ARM64_REG_X23, UC_ARM64_REG_X24,
            UC_ARM64_REG_X25, UC_ARM64_REG_X26, UC_ARM64_REG_X27,
            UC_ARM64_REG_X28, UC_ARM64_REG_X29, UC_ARM64_REG_X30};
        for (int i = 0; i < 12; ++i) ctx.saved[i] = e.read_uc_reg(saved_id[i]);
        const size_t depth = thread_ctx_.size();
        while (worker_stacks_.size() <= depth)
          worker_stacks_.push_back(mem_.mmap_alloc(
              0x100000, UC_PROT_READ | UC_PROT_WRITE, "thread stack"));
        thread_ctx_.push_back(ctx);
        e.write_reg(Reg::A0, arg);
        e.write_reg(Reg::Sp,
                    (worker_stacks_[depth] + 0x100000) & ~uint64_t(15));
        e.write_reg(Reg::Lr, thread_return_stub_);
        e.redirect(routine);
      });
  // Inline-fallback worker return (only used when no scheduler is active).
  thread_return_stub_ =
      tramp_.alloc("pthread_worker_return", [this](Engine& e) {
        static const int saved_id[12] = {
            UC_ARM64_REG_X19, UC_ARM64_REG_X20, UC_ARM64_REG_X21,
            UC_ARM64_REG_X22, UC_ARM64_REG_X23, UC_ARM64_REG_X24,
            UC_ARM64_REG_X25, UC_ARM64_REG_X26, UC_ARM64_REG_X27,
            UC_ARM64_REG_X28, UC_ARM64_REG_X29, UC_ARM64_REG_X30};
        ThreadCtx ctx = thread_ctx_.back();
        thread_ctx_.pop_back();
        thread_results_[ctx.tid] = e.read_reg(Reg::Ret0);
        for (int i = 0; i < 12; ++i) e.write_uc_reg(saved_id[i], ctx.saved[i]);
        e.write_reg(Reg::Sp, ctx.sp);
        e.write_reg(Reg::Ret0, 0);
        e.redirect(ctx.ret_lr);
      });
  add("pthread_join", [this, on](Engine& e) {  // (tid, void** retval)
    const uint64_t tid = e.read_reg(Reg::A0), out = e.read_reg(Reg::A1);
    if (on()) {
      sched_->do_join(e, tid, out);
      return;
    }
    if (out) {
      auto it = thread_results_.find(tid);
      e.write_t<uint64_t>(out, it == thread_results_.end() ? 0 : it->second);
    }
    e.write_reg(Reg::Ret0, 0);
  });
  add("pthread_self", [this, on](Engine& e) {
    e.write_reg(Reg::Ret0, on() ? sched_->self_tid() : 1);
  });
  add("pthread_detach", [](Engine& e) { e.write_reg(Reg::Ret0, 0); });

  add("pthread_mutex_lock", [this, on](Engine& e) {
    if (on())
      sched_->mutex_lock(e, e.read_reg(Reg::A0));
    else
      e.write_reg(Reg::Ret0, 0);
  });
  add("pthread_mutex_unlock", [this, on](Engine& e) {
    if (on()) sched_->mutex_unlock(e.read_reg(Reg::A0));
    e.write_reg(Reg::Ret0, 0);
  });
  add("pthread_cond_wait", [this, on](Engine& e) {  // (cond, mutex)
    if (on())
      sched_->cond_wait(e, e.read_reg(Reg::A0), e.read_reg(Reg::A1));
    else
      e.write_reg(Reg::Ret0, 0);
  });
  add("pthread_cond_signal", [this, on](Engine& e) {
    if (on()) sched_->cond_wake(e.read_reg(Reg::A0), /*all=*/false);
    e.write_reg(Reg::Ret0, 0);
  });
  add("pthread_cond_broadcast", [this, on](Engine& e) {
    if (on()) sched_->cond_wake(e.read_reg(Reg::A0), /*all=*/true);
    e.write_reg(Reg::Ret0, 0);
  });
  // Yield points: a poll loop's sleep lets the producer thread run.
  const bool sleep_noop =
      std::getenv("VARDOGER_SLEEP_NOOP") != nullptr;  // diagnostic
  for (const char* n : {"sleep", "usleep", "nanosleep", "sched_yield"})
    add(n, [this, on, sleep_noop](Engine& e) {
      if (on() && !sleep_noop)
        sched_->do_yield(e);
      else
        e.write_reg(Reg::Ret0, 0);
    });
  // Benign no-ops (no contention to model on a single host thread).
  for (const char* n :
       {"pthread_mutex_trylock", "pthread_mutex_init", "pthread_mutex_destroy",
        "pthread_cond_init", "pthread_cond_destroy", "pthread_rwlock_rdlock",
        "pthread_rwlock_wrlock", "pthread_rwlock_unlock", "pthread_attr_init",
        "pthread_attr_destroy", "pthread_attr_setdetachstate",
        "pthread_attr_setstacksize"})
    add(n, [](Engine& e) { e.write_reg(Reg::Ret0, 0); });
}

// Guest-facing zlib inflate, bridged to host zlib. Packers commonly zlib/gzip
// the payload (or an inner lib); without this the guest's inflate() makes no
// progress and spins forever. We keep one host z_stream per guest z_stream
// (keyed by its address), copy the guest's input/output windows in and out per
// call, and let host zlib own the streaming state. z_stream field offsets are
// the AArch64 (LP64) layout.
void Stubs::register_zlib() {
  enum {
    OFF_NEXT_IN = 0,
    OFF_AVAIL_IN = 8,
    OFF_TOTAL_IN = 16,
    OFF_NEXT_OUT = 24,
    OFF_AVAIL_OUT = 32,
    OFF_TOTAL_OUT = 40,
    OFF_STATE = 56
  };
  auto zinit = [this](Engine& e, uint64_t strm, int wbits) {
    if (!strm) {
      e.write_reg(Reg::Ret0,
                  static_cast<uint64_t>(static_cast<int64_t>(Z_STREAM_ERROR)));
      return;
    }
    auto it = zstreams_.find(strm);
    if (it != zstreams_.end()) {
      inflateEnd(static_cast<z_streamp>(it->second));
      delete static_cast<z_streamp>(it->second);
    }
    auto* hs = new z_stream{};
    const int rc = inflateInit2(hs, wbits);
    if (rc != Z_OK) {
      delete hs;
      e.write_reg(Reg::Ret0, static_cast<uint64_t>(static_cast<int64_t>(rc)));
      return;
    }
    zstreams_[strm] = hs;
    e.write_t<uint64_t>(strm + OFF_STATE,
                        1);  // non-null so the guest sees "initialised"
    e.write_reg(Reg::Ret0, static_cast<uint64_t>(static_cast<int64_t>(Z_OK)));
  };
  // inflateInit_(strm, version, stream_size): zlib header default. Use 47 =
  // auto-detect zlib OR gzip wrapper (handles both without knowing which the
  // packer used).
  add("inflateInit_",
      [zinit](Engine& e) { zinit(e, e.read_reg(Reg::A0), 47); });
  // inflateInit2_(strm, windowBits, version, stream_size): honour the requested
  // windowBits (negative => raw DEFLATE, which packers favour).
  add("inflateInit2_", [zinit](Engine& e) {
    zinit(e, e.read_reg(Reg::A0),
          static_cast<int>(static_cast<int32_t>(e.read_reg(Reg::A1))));
  });

  add("inflate", [this](Engine& e) {
    const uint64_t strm = e.read_reg(Reg::A0);
    const int flush = static_cast<int>(e.read_reg(Reg::A1));
    auto it = zstreams_.find(strm);
    if (it == zstreams_.end()) {
      e.write_reg(Reg::Ret0,
                  static_cast<uint64_t>(static_cast<int64_t>(Z_STREAM_ERROR)));
      return;
    }
    auto* hs = static_cast<z_streamp>(it->second);
    const uint64_t in_p = e.read_t<uint64_t>(strm + OFF_NEXT_IN);
    const uint32_t in_n = e.read_t<uint32_t>(strm + OFF_AVAIL_IN);
    const uint64_t out_p = e.read_t<uint64_t>(strm + OFF_NEXT_OUT);
    const uint32_t out_n = e.read_t<uint32_t>(strm + OFF_AVAIL_OUT);
    std::vector<uint8_t> in(in_n), out(out_n);
    if (in_n) e.read(in_p, in.data(), in_n);
    // VARDOGER_INFLATE_DUMP=path : append inflate's INPUT (post-cipher,
    // pre-decompress bytes), used to reverse a packer's container cipher by
    // diffing against the encrypted container body.
    if (in_n)
      if (const char* p = std::getenv("VARDOGER_INFLATE_DUMP"))
        std::ofstream(p, std::ios::binary | std::ios::app)
            .write(reinterpret_cast<const char*>(in.data()), in_n);
    hs->next_in = in.data();
    hs->avail_in = in_n;
    hs->next_out = out.data();
    hs->avail_out = out_n;
    const int rc = inflate(hs, flush);
    const uint32_t consumed = in_n - hs->avail_in;
    const uint32_t produced = out_n - hs->avail_out;
    if (produced) e.write(out_p, out.data(), produced);
    e.write_t<uint64_t>(strm + OFF_NEXT_IN, in_p + consumed);
    e.write_t<uint32_t>(strm + OFF_AVAIL_IN, hs->avail_in);
    e.write_t<uint64_t>(strm + OFF_TOTAL_IN,
                        e.read_t<uint64_t>(strm + OFF_TOTAL_IN) + consumed);
    e.write_t<uint64_t>(strm + OFF_NEXT_OUT, out_p + produced);
    e.write_t<uint32_t>(strm + OFF_AVAIL_OUT, hs->avail_out);
    e.write_t<uint64_t>(strm + OFF_TOTAL_OUT,
                        e.read_t<uint64_t>(strm + OFF_TOTAL_OUT) + produced);
    e.write_reg(Reg::Ret0, static_cast<uint64_t>(static_cast<int64_t>(rc)));
  });
  add("inflateEnd", [this](Engine& e) {
    const uint64_t strm = e.read_reg(Reg::A0);
    auto it = zstreams_.find(strm);
    if (it != zstreams_.end()) {
      inflateEnd(static_cast<z_streamp>(it->second));
      delete static_cast<z_streamp>(it->second);
      zstreams_.erase(it);
    }
    e.write_t<uint64_t>(strm + OFF_STATE, 0);
    e.write_reg(Reg::Ret0, static_cast<uint64_t>(static_cast<int64_t>(Z_OK)));
  });
  add("inflateReset", [this](Engine& e) {
    const uint64_t strm = e.read_reg(Reg::A0);
    auto it = zstreams_.find(strm);
    const int rc = it != zstreams_.end()
                       ? inflateReset(static_cast<z_streamp>(it->second))
                       : Z_STREAM_ERROR;
    e.write_reg(Reg::Ret0, static_cast<uint64_t>(static_cast<int64_t>(rc)));
  });
  // uncompress(dest, destLen*, source, sourceLen): one-shot zlib inflate.
  // Packers (Jiagu) use this to decompress the DEX. destLen is uLong* (LP64 = 8
  // bytes), in/out.
  add("uncompress", [this](Engine& e) {
    const uint64_t dest = e.read_reg(Reg::A0), destLenP = e.read_reg(Reg::A1);
    const uint64_t src = e.read_reg(Reg::A2), srcLen = e.read_reg(Reg::A3);
    uLongf destCap = static_cast<uLongf>(e.read_t<uint64_t>(destLenP));
    std::vector<uint8_t> in(srcLen), out(destCap);
    if (srcLen) e.read(src, in.data(), srcLen);
    uLongf outLen = destCap;
    const int rc =
        uncompress(out.data(), &outLen, in.data(), static_cast<uLong>(srcLen));
    if (rc == Z_OK && outLen) e.write(dest, out.data(), outLen);
    e.write_t<uint64_t>(destLenP, outLen);
    if (std::getenv("VARDOGER_ZLIB_LOG"))
      std::fprintf(stderr,
                   "[uncompress] src=%#llx srcLen=%llu -> dest=%#llx "
                   "outLen=%llu rc=%d lr=%#llx%s\n",
                   (unsigned long long)src, (unsigned long long)srcLen,
                   (unsigned long long)dest, (unsigned long long)outLen, rc,
                   (unsigned long long)e.read_reg(Reg::Lr),
                   (rc == Z_OK && outLen >= 8 &&
                    std::memcmp(out.data(), "dex\n", 4) == 0)
                       ? "  [DEX!]"
                       : "");
    if (const char* dir = std::getenv("VARDOGER_ZLIB_DUMP")) {
      static int n = 0;
      char path[256];
      std::snprintf(path, sizeof path, "%s/uncompress_%02d.bin", dir, n++);
      if (rc == Z_OK && outLen) {
        FILE* f = std::fopen(path, "wb");
        if (f) {
          std::fwrite(out.data(), 1, outLen, f);
          std::fclose(f);
          std::fprintf(stderr, "[zlib-dump] wrote %s (%llu bytes)\n", path,
                       (unsigned long long)outLen);
        }
      }
    }
    e.write_reg(Reg::Ret0, static_cast<uint64_t>(static_cast<int64_t>(rc)));
  });
}

void Stubs::register_defaults() {
  // ---- syscall(nr, a1..a6): route to the raw syscall dispatcher ----
  // The libc wrapper passes the number in the first C arg (A0) and up to 6 args
  // in A1..A6; the dispatcher expects the number in SyscallNr (x8) and args in
  // A0..A5. Shuffle then dispatch. Falls back to -ENOSYS only if no dispatcher
  // was wired. Crucial for syscall(gettid) in __cxa_guard/pthread_once
  // static-init guards (see set_syscalls()).
  add("syscall", [this](Engine& e) {
    if (!syscalls_) {
      if (std::getenv("VARDOGER_MMAP_LOG"))
        std::fprintf(
            stderr, "[syscall-import] nr=%#llx NO DISPATCHER -> -ENOSYS(-38)\n",
            (unsigned long long)e.read_reg(Reg::A0));
      e.write_reg(Reg::Ret0, static_cast<uint64_t>(-38));
      return;  // -ENOSYS
    }
    if (std::getenv("VARDOGER_MMAP_LOG"))
      std::fprintf(stderr, "[syscall-import] nr=%#llx a1=%#llx a2=%#llx\n",
                   (unsigned long long)e.read_reg(Reg::A0),
                   (unsigned long long)e.read_reg(Reg::A1),
                   (unsigned long long)e.read_reg(Reg::A2));
    const uint64_t nr = e.read_reg(Reg::A0);
    const uint64_t a[6] = {e.read_reg(Reg::A1), e.read_reg(Reg::A2),
                           e.read_reg(Reg::A3), e.read_reg(Reg::A4),
                           e.read_reg(Reg::A5), e.read_reg(Reg::A6)};
    e.write_reg(Reg::SyscallNr, nr);
    e.write_reg(Reg::A0, a[0]);
    e.write_reg(Reg::A1, a[1]);
    e.write_reg(Reg::A2, a[2]);
    e.write_reg(Reg::A3, a[3]);
    e.write_reg(Reg::A4, a[4]);
    e.write_reg(Reg::A5, a[5]);
    syscalls_->dispatch(e);  // sets Ret0
  });

  // ---- mem* (bounce through host buffers) ----
  auto memcpy_watch = [](Engine& e, uint64_t d, uint64_t s, uint64_t n) {
    static const char* w =
        std::getenv("VARDOGER_MEMCPY_WATCH");  // cached (runs per memcpy)
    if (!w) return;
    const uint64_t tgt = std::strtoull(w, nullptr, 0);
    if (d <= tgt && tgt < d + n) {
      uint64_t pc = 0;
      uc_reg_read(e.raw(), UC_ARM64_REG_PC, &pc);
      std::fprintf(
          stderr,
          "[memcpy] dst=%#llx src=%#llx n=%#llx (val@tgt=%#llx) pc=%#llx\n",
          (unsigned long long)d, (unsigned long long)s, (unsigned long long)n,
          (unsigned long long)e.read_t<uint64_t>(s + (tgt - d)),
          (unsigned long long)pc);
    }
  };
  add("memcpy", [memcpy_watch](Engine& e) {
    const uint64_t d = e.read_reg(Reg::A0), s = e.read_reg(Reg::A1),
                   n = e.read_reg(Reg::A2);
    memcpy_watch(e, d, s, n);
    if (n) {
      std::vector<uint8_t> b(n);
      e.read(s, b.data(), n);
      e.write(d, b.data(), n);
    }
    e.write_reg(Reg::Ret0, d);
  });
  add("memmove", [memcpy_watch](Engine& e) {
    const uint64_t d = e.read_reg(Reg::A0), s = e.read_reg(Reg::A1),
                   n = e.read_reg(Reg::A2);
    memcpy_watch(e, d, s, n);
    if (n) {
      std::vector<uint8_t> b(n);
      e.read(s, b.data(), n);
      e.write(d, b.data(), n);
    }
    e.write_reg(Reg::Ret0, d);
  });
  // Fortified copies (dst, src, n, dstlen), copy n bytes (we don't enforce the
  // bound). These were previously the unknown-import no-op stub, which silently
  // DROPPED the copy.
  auto chk_copy = [memcpy_watch](Engine& e) {
    const uint64_t d = e.read_reg(Reg::A0), s = e.read_reg(Reg::A1),
                   n = e.read_reg(Reg::A2);
    memcpy_watch(e, d, s, n);
    if (n) {
      std::vector<uint8_t> b(n);
      e.read(s, b.data(), n);
      e.write(d, b.data(), n);
    }
    e.write_reg(Reg::Ret0, d);
  };
  add("__memcpy_chk", chk_copy);
  add("__memmove_chk", chk_copy);
  add("mempcpy", [](Engine& e) {  // like memcpy but returns dst+n
    const uint64_t d = e.read_reg(Reg::A0), s = e.read_reg(Reg::A1),
                   n = e.read_reg(Reg::A2);
    if (n) {
      std::vector<uint8_t> b(n);
      e.read(s, b.data(), n);
      e.write(d, b.data(), n);
    }
    e.write_reg(Reg::Ret0, d + n);
  });
  add("memset", [](Engine& e) {
    const uint64_t d = e.read_reg(Reg::A0);
    const auto c = static_cast<uint8_t>(e.read_reg(Reg::A1));
    const uint64_t n = e.read_reg(Reg::A2);
    if (n) {
      std::vector<uint8_t> b(n, c);
      e.write(d, b.data(), n);
    }
    e.write_reg(Reg::Ret0, d);
  });
  add("memcmp", [](Engine& e) {
    const uint64_t a = e.read_reg(Reg::A0), b = e.read_reg(Reg::A1),
                   n = e.read_reg(Reg::A2);
    std::vector<uint8_t> x(n), y(n);
    if (n) {
      e.read(a, x.data(), n);
      e.read(b, y.data(), n);
    }
    const int r = n ? std::memcmp(x.data(), y.data(), n) : 0;
    if (std::getenv("VARDOGER_STR_LOG") && n >= 4 &&
        n <= 64) {  // hash-sized integrity compares
      auto hex = [](const std::vector<uint8_t>& v) {
        std::string s;
        char t[4];
        for (size_t i = 0; i < v.size() && i < 32; ++i) {
          std::snprintf(t, sizeof(t), "%02x", v[i]);
          s += t;
        }
        return s;
      };
      std::fprintf(stderr, "[memcmp n=%llu r=%d] %s vs %s\n",
                   (unsigned long long)n, r, hex(x).c_str(), hex(y).c_str());
    }
    e.write_reg(Reg::Ret0, static_cast<uint64_t>(static_cast<int64_t>(r)));
  });

  // ---- str* (read C strings from guest memory) ----
  add("strlen", [](Engine& e) {
    e.write_reg(Reg::Ret0, e.read_cstr(e.read_reg(Reg::A0)).size());
  });
  add("strnlen", [](Engine& e) {  // (s, maxlen) -> min(strlen(s), maxlen)
    const uint64_t s = e.read_reg(Reg::A0), maxlen = e.read_reg(Reg::A1);
    uint64_t n = 0;
    while (n < maxlen && e.read_t<uint8_t>(s + n) != 0) ++n;
    e.write_reg(Reg::Ret0, n);
  });
  add("memchr", [](Engine& e) {  // (s, c, n) -> &first c, or NULL
    const uint64_t s = e.read_reg(Reg::A0), n = e.read_reg(Reg::A2);
    const uint8_t c = static_cast<uint8_t>(e.read_reg(Reg::A1));
    std::vector<uint8_t> b(n);
    if (n) e.read(s, b.data(), n);
    for (uint64_t i = 0; i < n; ++i)
      if (b[i] == c) {
        e.write_reg(Reg::Ret0, s + i);
        return;
      }
    e.write_reg(Reg::Ret0, 0);
  });
  add("strlcpy", [](Engine& e) {  // (dst, src, size) -> strlen(src)
    const uint64_t dst = e.read_reg(Reg::A0), size = e.read_reg(Reg::A2);
    const std::string src = e.read_cstr(e.read_reg(Reg::A1));
    if (size) {
      const size_t n = std::min<size_t>(src.size(), size - 1);
      if (n) e.write(dst, src.data(), n);
      const uint8_t z = 0;
      e.write(dst + n, &z, 1);
    }
    e.write_reg(Reg::Ret0, src.size());
  });
  add("strchr", [](Engine& e) {  // (s, c) -> &first c (incl NUL), or NULL
    const uint64_t s = e.read_reg(Reg::A0);
    const char c = static_cast<char>(e.read_reg(Reg::A1));
    const std::string str = e.read_cstr(s);
    for (size_t i = 0; i <= str.size(); ++i)
      if (str.c_str()[i] == c) {
        e.write_reg(Reg::Ret0, s + i);
        return;
      }
    e.write_reg(Reg::Ret0, 0);
  });
  add("strrchr", [](Engine& e) {
    const uint64_t s = e.read_reg(Reg::A0);
    const char c = static_cast<char>(e.read_reg(Reg::A1));
    const std::string str = e.read_cstr(s);
    for (size_t i = str.size() + 1; i-- > 0;)
      if (str.c_str()[i] == c) {
        e.write_reg(Reg::Ret0, s + i);
        return;
      }
    e.write_reg(Reg::Ret0, 0);
  });
  add("strcpy", [](Engine& e) {  // (dst, src) -> dst
    const uint64_t dst = e.read_reg(Reg::A0);
    const std::string s = e.read_cstr(e.read_reg(Reg::A1));
    e.write(dst, s.data(), s.size());
    const uint8_t z = 0;
    e.write(dst + s.size(), &z, 1);
    e.write_reg(Reg::Ret0, dst);
  });
  add("strcat", [](Engine& e) {  // (dst, src) -> dst
    const uint64_t dst = e.read_reg(Reg::A0);
    const std::string d = e.read_cstr(dst),
                      s = e.read_cstr(e.read_reg(Reg::A1));
    e.write(dst + d.size(), s.data(), s.size());
    const uint8_t z = 0;
    e.write(dst + d.size() + s.size(), &z, 1);
    e.write_reg(Reg::Ret0, dst);
  });
  for (const char* n :
       {"sigaction", "sigemptyset", "sigaltstack", "sigaddset", "sigprocmask"})
    add(n, [](Engine& e) {
      e.write_reg(Reg::Ret0, 0);
    });  // signal setup -> success no-op
  // Fortified string ops (_chk), same as the plain versions (we don't enforce
  // bounds).
  add("__strcpy_chk", [](Engine& e) {  // (dst, src, dstlen)
    const uint64_t dst = e.read_reg(Reg::A0);
    const std::string s = e.read_cstr(e.read_reg(Reg::A1));
    e.write(dst, s.data(), s.size());
    const uint8_t z = 0;
    e.write(dst + s.size(), &z, 1);
    e.write_reg(Reg::Ret0, dst);
  });
  add("__strcat_chk", [](Engine& e) {  // (dst, src, dstlen)
    const uint64_t dst = e.read_reg(Reg::A0);
    const std::string d = e.read_cstr(dst),
                      s = e.read_cstr(e.read_reg(Reg::A1));
    e.write(dst + d.size(), s.data(), s.size());
    const uint8_t z = 0;
    e.write(dst + d.size() + s.size(), &z, 1);
    e.write_reg(Reg::Ret0, dst);
  });
  add("__strncpy_chk", [](Engine& e) {  // (dst, src, n, dstlen)
    const uint64_t dst = e.read_reg(Reg::A0), n = e.read_reg(Reg::A2);
    const std::string s = e.read_cstr(e.read_reg(Reg::A1));
    for (uint64_t k = 0; k < n; ++k) {
      const uint8_t c = k < s.size() ? (uint8_t)s[k] : 0;
      e.write(dst + k, &c, 1);
    }
    e.write_reg(Reg::Ret0, dst);
  });
  add("rand",
      [](Engine& e) { e.write_reg(Reg::Ret0, 0x4d2); });  // deterministic
  add("srand", [](Engine& e) { e.write_reg(Reg::Ret0, 0); });
  add("strspn", [](Engine& e) {  // (s, accept) -> len of initial accept-run
    const std::string s = e.read_cstr(e.read_reg(Reg::A0)),
                      a = e.read_cstr(e.read_reg(Reg::A1));
    size_t n = 0;
    while (n < s.size() && a.find(s[n]) != std::string::npos) ++n;
    e.write_reg(Reg::Ret0, n);
  });
  add("strcspn", [](Engine& e) {  // (s, reject) -> len until first reject char
    const std::string s = e.read_cstr(e.read_reg(Reg::A0)),
                      r = e.read_cstr(e.read_reg(Reg::A1));
    size_t n = 0;
    while (n < s.size() && r.find(s[n]) == std::string::npos) ++n;
    e.write_reg(Reg::Ret0, n);
  });
  add("strpbrk",
      [](Engine& e) {  // (s, accept) -> ptr to first accept char or NULL
        const uint64_t sp = e.read_reg(Reg::A0);
        const std::string s = e.read_cstr(sp),
                          a = e.read_cstr(e.read_reg(Reg::A1));
        for (size_t n = 0; n < s.size(); ++n)
          if (a.find(s[n]) != std::string::npos) {
            e.write_reg(Reg::Ret0, sp + n);
            return;
          }
        e.write_reg(Reg::Ret0, 0);
      });
  // strtok / strtok_r: tokenize a guest string in place (NUL out delimiters).
  static uint64_t s_strtok_save = 0;
  auto strtok_core = [](Engine& e, uint64_t str, uint64_t delim,
                        uint64_t& save) {
    const std::string d = e.read_cstr(delim);
    auto is_delim = [&](char c) { return d.find(c) != std::string::npos; };
    uint64_t p = str ? str : save;
    if (!p) {
      e.write_reg(Reg::Ret0, 0);
      return;
    }
    while (true) {
      const char c = (char)e.read_t<uint8_t>(p);
      if (!c) {
        save = 0;
        e.write_reg(Reg::Ret0, 0);
        return;
      }
      if (!is_delim(c)) break;
      ++p;
    }
    const uint64_t tok = p;
    while (true) {
      const char c = (char)e.read_t<uint8_t>(p);
      if (!c) {
        save = 0;
        break;
      }
      if (is_delim(c)) {
        const uint8_t z = 0;
        e.write(p, &z, 1);
        save = p + 1;
        break;
      }
      ++p;
    }
    e.write_reg(Reg::Ret0, tok);
  };
  add("strtok", [strtok_core](Engine& e) {
    strtok_core(e, e.read_reg(Reg::A0), e.read_reg(Reg::A1), s_strtok_save);
  });
  add("strtok_r", [strtok_core](Engine& e) {  // (str, delim, saveptr)
    const uint64_t sp = e.read_reg(Reg::A2);
    uint64_t save = sp ? e.read_t<uint64_t>(sp) : 0;
    strtok_core(e, e.read_reg(Reg::A0), e.read_reg(Reg::A1), save);
    if (sp) e.write_t<uint64_t>(sp, save);
  });
  add("fnmatch",
      [](Engine& e) {  // (pattern, string, flags) -> 0 match / FNM_NOMATCH
        const std::string pat = e.read_cstr(e.read_reg(Reg::A0));
        const std::string str = e.read_cstr(e.read_reg(Reg::A1));
        const int flags = static_cast<int>(e.read_reg(Reg::A2));
        const int rc = ::fnmatch(pat.c_str(), str.c_str(), flags);
        if (std::getenv("VARDOGER_FNMATCH_LOG"))
          std::fprintf(stderr, "[fnmatch] pat=\"%s\" str=\"%s\" -> %d\n",
                       pat.c_str(), str.c_str(), rc);
        e.write_reg(Reg::Ret0, static_cast<uint64_t>(static_cast<int64_t>(rc)));
      });
  add("strlcat", [](Engine& e) {  // (dst, src, size)
    const uint64_t dst = e.read_reg(Reg::A0), size = e.read_reg(Reg::A2);
    const std::string d = e.read_cstr(dst),
                      s = e.read_cstr(e.read_reg(Reg::A1));
    if (d.size() < size) {
      const size_t n = std::min<size_t>(s.size(), size - d.size() - 1);
      if (n) e.write(dst + d.size(), s.data(), n);
      const uint8_t z = 0;
      e.write(dst + d.size() + n, &z, 1);
    }
    e.write_reg(Reg::Ret0, d.size() + s.size());
  });
  add("strcmp", [](Engine& e) {
    const std::string a = e.read_cstr(e.read_reg(Reg::A0));
    const std::string b = e.read_cstr(e.read_reg(Reg::A1));
    if (std::getenv("VARDOGER_STR_LOG"))
      std::fprintf(stderr, "[strcmp] \"%s\" vs \"%s\"\n", a.c_str(), b.c_str());
    e.write_reg(Reg::Ret0,
                static_cast<uint64_t>(static_cast<int64_t>(a.compare(b))));
  });
  add("strncmp", [](Engine& e) {
    const uint64_t n = e.read_reg(Reg::A2);
    std::string a = e.read_cstr(e.read_reg(Reg::A0), n);
    std::string b = e.read_cstr(e.read_reg(Reg::A1), n);
    e.write_reg(Reg::Ret0,
                static_cast<uint64_t>(static_cast<int64_t>(a.compare(b))));
  });

  // ---- malloc family (host bump allocator over the guest heap region) ----
  // Large requests go to mmap_alloc (a fresh mapped region), exactly like a
  // real libc's large-alloc path (glibc/scudo mmap above a threshold). This
  // keeps the bump arena for small objects and lets a packer allocate
  // multi-tens-of-MB decrypt buffers (e.g. Virbox clones malloc ~20/26/51 MB in
  // one go) without exhausting the fixed 128 MiB heap, the bump heap OOM'd on
  // the 3rd big buffer, whose subsequent memset(null,…) faulted and aborted the
  // unpack. A bump-heap failure also falls back to mmap so we never spuriously
  // return null while address space remains.
  static const uint64_t kBigAlloc =
      0x400000;  // 4 MiB, above this, map a dedicated region
  static const bool legacy_malloc =
      std::getenv("VARDOGER_LEGACY_MALLOC") != nullptr;  // A/B bisect toggle
  auto big_or_heap = [this](uint64_t n) -> uint64_t {
    if (legacy_malloc)
      return mem_.heap_alloc(n);  // pre-change: bump heap only (may OOM)
    if (n >= kBigAlloc)
      return mem_.big_alloc(n, UC_PROT_READ | UC_PROT_WRITE, "malloc-big");
    const uint64_t r = mem_.heap_alloc(n);
    if (r) return r;
    return mem_.big_alloc(n ? n : 1, UC_PROT_READ | UC_PROT_WRITE,
                          "malloc-of");  // heap exhausted
  };
  add("malloc", [this, big_or_heap](Engine& e) {
    const uint64_t n = e.read_reg(Reg::A0);
    const uint64_t r = big_or_heap(n);
    if (std::getenv("VARDOGER_MMAP_LOG") && n > 0x100000)
      std::fprintf(stderr, "[malloc] %#llx -> %#llx\n", (unsigned long long)n,
                   (unsigned long long)r);
    e.write_reg(Reg::Ret0, r);
  });
  add("calloc", [this, big_or_heap](Engine& e) {
    const uint64_t total = e.read_reg(Reg::A0) * e.read_reg(Reg::A1);
    e.write_reg(Reg::Ret0,
                big_or_heap(total));  // heap + fresh mmap are both zero-filled
  });
  add("realloc", [this, big_or_heap](Engine& e) {
    const uint64_t p = e.read_reg(Reg::A0), n = e.read_reg(Reg::A1);
    if (!p) {
      e.write_reg(Reg::Ret0, big_or_heap(n));
      return;
    }
    const uint64_t np = big_or_heap(n);
    if (n && np) {
      std::vector<uint8_t> b(n);
      e.read(p, b.data(), n);
      e.write(np, b.data(), n);
    }
    e.write_reg(Reg::Ret0, np);  // note: copies n bytes (old size is untracked)
  });
  add("free", [](Engine&) { /* bump allocator: free is a no-op */ });

  // ---- liblog: free telemetry; packers often log the unpack steps ----
  add("__android_log_print", [](Engine& e) {  // (prio, tag, fmt, ...)
    const uint64_t prio = e.read_reg(Reg::A0);
    const std::string tag = e.read_cstr(e.read_reg(Reg::A1));
    const std::string msg =
        fmt_expand(e, e.read_reg(Reg::A2), /*first vararg=*/3);
    std::fprintf(stderr, "[guest-log] (%llu) %s: %s\n",
                 static_cast<unsigned long long>(prio), tag.c_str(),
                 msg.c_str());
    e.write_reg(Reg::Ret0, 0);
  });

  // ---- printf family into a guest buffer (arm64 varargs) ----
  add("sprintf", [](Engine& e) {  // (dst, fmt, ...)
    const uint64_t dst = e.read_reg(Reg::A0);
    const std::string s = fmt_expand(e, e.read_reg(Reg::A1), 2);
    e.write(dst, s.c_str(), s.size() + 1);  // include NUL
    e.write_reg(Reg::Ret0, s.size());
  });
  auto snprintf_impl = [](Engine& e) {  // (dst, size, fmt, ...)
    const uint64_t dst = e.read_reg(Reg::A0), size = e.read_reg(Reg::A1);
    const std::string s = fmt_expand(e, e.read_reg(Reg::A2), 3);
    if (size) {  // truncate to size-1 + NUL
      const size_t n = std::min<size_t>(s.size(), size - 1);
      e.write(dst, s.c_str(), n);
      const uint8_t z = 0;
      e.write(dst + n, &z, 1);
    }
    e.write_reg(Reg::Ret0, s.size());  // C99: length that WOULD be written
  };
  add("snprintf", snprintf_impl);
  add("__snprintf_chk", [](Engine& e) {  // (dst, size, flag, slen, fmt, ...)
    const uint64_t dst = e.read_reg(Reg::A0), size = e.read_reg(Reg::A1);
    const std::string s = fmt_expand(e, e.read_reg(Reg::A4), 5);
    if (size) {
      const size_t n = std::min<size_t>(s.size(), size - 1);
      e.write(dst, s.c_str(), n);
      const uint8_t z = 0;
      e.write(dst + n, &z, 1);
    }
    e.write_reg(Reg::Ret0, s.size());
  });
  auto write_str = [](Engine& e, uint64_t dst, uint64_t cap,
                      const std::string& s) {
    const size_t n = cap ? std::min<size_t>(s.size(), cap - 1) : s.size();
    e.write(dst, s.c_str(), n);
    const uint8_t z = 0;
    e.write(dst + n, &z, 1);
    e.write_reg(Reg::Ret0, s.size());
  };
  add("__sprintf_chk", [write_str](Engine& e) {  // (dst, flag, slen, fmt, ...)
    write_str(e, e.read_reg(Reg::A0), 0, fmt_expand(e, e.read_reg(Reg::A3), 4));
  });
  add("vsprintf", [write_str](Engine& e) {  // (dst, fmt, va_list)
    write_str(e, e.read_reg(Reg::A0), 0,
              fmt_expand_va(e, e.read_reg(Reg::A1), e.read_reg(Reg::A2)));
  });
  add("vsnprintf", [write_str](Engine& e) {  // (dst, size, fmt, va_list)
    write_str(e, e.read_reg(Reg::A0), e.read_reg(Reg::A1),
              fmt_expand_va(e, e.read_reg(Reg::A2), e.read_reg(Reg::A3)));
  });
  add("__vsprintf_chk",
      [write_str](Engine& e) {  // (dst, flag, slen, fmt, va_list)
        write_str(e, e.read_reg(Reg::A0), 0,
                  fmt_expand_va(e, e.read_reg(Reg::A3), e.read_reg(Reg::A4)));
      });
  add("__vsnprintf_chk",
      [write_str](Engine& e) {  // (dst, size, flag, slen, fmt, va_list)
        write_str(e, e.read_reg(Reg::A0), e.read_reg(Reg::A1),
                  fmt_expand_va(e, e.read_reg(Reg::A4), e.read_reg(Reg::A5)));
      });

  // ---- directory enumeration: report "directory does not exist" (NULL) ----
  // Returning a fake non-null DIR* is WRONG for /proc/<pid>/task scans (Ducex's
  // anti-Frida thread sweep): a real device returns NULL for a non-existent
  // pid, so the sweep terminates; a perpetual fake DIR* makes it loop a
  // heap-address- dependent number of times (non-determinism). NULL = "not
  // there" terminates the scan cleanly. (Callers that genuinely enumerate a
  // served dir would need a real DIR model, none of the studied packers
  // require one.)
  add("opendir", [](Engine& e) { e.write_reg(Reg::Ret0, 0); });
  add("readdir",
      [](Engine& e) { e.write_reg(Reg::Ret0, 0); });  // end of stream
  add("readdir64", [](Engine& e) { e.write_reg(Reg::Ret0, 0); });
  add("closedir", [](Engine& e) { e.write_reg(Reg::Ret0, 0); });

  // ---- C++ operator new/delete (libc++) -> the guest heap ----
  auto op_new = [this](Engine& e) {
    const uint64_t n = e.read_reg(Reg::A0);
    e.write_reg(Reg::Ret0, mem_.heap_alloc(n ? n : 1));
  };
  add("_Znwm", op_new);            // operator new(size_t)
  add("_Znam", op_new);            // operator new[](size_t)
  add("_ZdlPv", [](Engine&) {});   // operator delete(void*)
  add("_ZdaPv", [](Engine&) {});   // operator delete[](void*)
  add("_ZdlPvm", [](Engine&) {});  // sized operator delete(void*, size_t)
  add("_ZdaPvm", [](Engine&) {});

  // ---- C++ static-init guards (single-threaded: run init exactly once) ----
  add("__cxa_guard_acquire", [](Engine& e) {  // 1 => caller should initialize
    const uint64_t g = e.read_reg(Reg::A0);
    e.write_reg(Reg::Ret0, e.read_t<uint8_t>(g) == 0 ? 1 : 0);
  });
  add("__cxa_guard_release", [](Engine& e) {  // mark initialized
    const uint8_t one = 1;
    e.write(e.read_reg(Reg::A0), &one, 1);
  });
  add("__cxa_guard_abort", [](Engine&) {});

  add("atoi", [](Engine& e) {
    e.write_reg(Reg::Ret0, static_cast<uint64_t>(static_cast<int64_t>(std::atoi(
                               e.read_cstr(e.read_reg(Reg::A0)).c_str()))));
  });
  // strtol/strtoul family (nptr, endptr, base), the packer parses many
  // numbers; returning 0 (the old "unimplemented" default) corrupts its offset
  // math.
  auto strto = [](Engine& e, bool uns) {
    const uint64_t nptr = e.read_reg(Reg::A0), endptr = e.read_reg(Reg::A1);
    const int base = static_cast<int>(e.read_reg(Reg::A2));
    const std::string s = e.read_cstr(nptr);
    char* end = nullptr;
    const uint64_t v =
        uns ? static_cast<uint64_t>(std::strtoull(s.c_str(), &end, base))
            : static_cast<uint64_t>(std::strtoll(s.c_str(), &end, base));
    if (std::getenv("VARDOGER_STR_LOG"))
      std::fprintf(stderr, "[strto] \"%.40s\" base=%d -> %#llx\n", s.c_str(),
                   base, (unsigned long long)v);
    if (endptr)
      e.write_t<uint64_t>(endptr, nptr + (end - s.c_str()));  // consumed offset
    e.write_reg(Reg::Ret0, v);
  };
  add("strtol", [strto](Engine& e) { strto(e, false); });
  add("strtoll", [strto](Engine& e) { strto(e, false); });
  add("strtoul", [strto](Engine& e) { strto(e, true); });
  add("strtoull", [strto](Engine& e) { strto(e, true); });
  // strtod/atof return a double in D0 (V0), not X0, write the FP return
  // register.
  auto ret_double = [](Engine& e, double v) {
    uint64_t bits;
    std::memcpy(&bits, &v, 8);
    e.write_uc_reg(UC_ARM64_REG_D0, bits);
  };
  add("strtod", [ret_double](Engine& e) {  // (nptr, endptr) -> double
    const uint64_t nptr = e.read_reg(Reg::A0), endptr = e.read_reg(Reg::A1);
    const std::string s = e.read_cstr(nptr);
    char* end = nullptr;
    const double v = std::strtod(s.c_str(), &end);
    if (endptr) e.write_t<uint64_t>(endptr, nptr + (end - s.c_str()));
    ret_double(e, v);
  });
  add("atof", [ret_double](Engine& e) {
    ret_double(e,
               std::strtod(e.read_cstr(e.read_reg(Reg::A0)).c_str(), nullptr));
  });
  add("atol", [](Engine& e) {
    e.write_reg(Reg::Ret0,
                static_cast<uint64_t>(std::strtoll(
                    e.read_cstr(e.read_reg(Reg::A0)).c_str(), nullptr, 10)));
  });
  add("atoll", [](Engine& e) {
    e.write_reg(Reg::Ret0,
                static_cast<uint64_t>(std::strtoll(
                    e.read_cstr(e.read_reg(Reg::A0)).c_str(), nullptr, 10)));
  });

  add("strstr", [](Engine& e) {
    const std::string hay = e.read_cstr(e.read_reg(Reg::A0));
    const std::string needle = e.read_cstr(e.read_reg(Reg::A1));
    const auto pos = hay.find(needle);
    if (std::getenv("VARDOGER_STR_LOG"))
      std::fprintf(stderr,
                   "[strstr] needle=\"%s\" in hay[..40]=\"%.40s\" -> %s\n",
                   needle.c_str(), hay.c_str(),
                   pos == std::string::npos ? "miss" : "HIT");
    e.write_reg(Reg::Ret0,
                pos == std::string::npos ? 0 : e.read_reg(Reg::A0) + pos);
  });
  add("getenv", [](Engine& e) { e.write_reg(Reg::Ret0, 0); });  // nothing set
  add("getpagesize", [](Engine& e) { e.write_reg(Reg::Ret0, 4096); });
  add("sysconf", [](Engine& e) {  // 4 KiB pages, plausible cpu/clk
    switch (e.read_reg(Reg::A0)) {
      case 30:
      case 39:
        e.write_reg(Reg::Ret0, 4096);
        break;  // _SC_PAGE_SIZE / _SC_PAGESIZE
      case 96:
      case 97:
        e.write_reg(Reg::Ret0, 4);
        break;  // _SC_NPROCESSORS_{CONF,ONLN}
      case 2:
        e.write_reg(Reg::Ret0, 100);
        break;  // _SC_CLK_TCK
      default:
        e.write_reg(Reg::Ret0, static_cast<uint64_t>(-1));
        break;
    }
  });

  add("strdup", [this](Engine& e) {
    const std::string s = e.read_cstr(e.read_reg(Reg::A0));
    const uint64_t p = mem_.heap_alloc(s.size() + 1);
    e.write(p, s.c_str(), s.size() + 1);
    e.write_reg(Reg::Ret0, p);
  });
  add("strncpy", [](Engine& e) {
    const uint64_t d = e.read_reg(Reg::A0), n = e.read_reg(Reg::A2);
    const std::string src = e.read_cstr(e.read_reg(Reg::A1), n);
    std::vector<uint8_t> buf(n, 0);  // null-pads to n
    for (size_t i = 0; i < src.size() && i < n; ++i)
      buf[i] = static_cast<uint8_t>(src[i]);
    if (n) e.write(d, buf.data(), n);
    e.write_reg(Reg::Ret0, d);
  });
  auto errno_fn = [this](Engine& e) {  // __errno / __errno_location
    if (!errno_slot_) {
      errno_slot_ = mem_.heap_alloc(8);
      const uint32_t z = 0;
      e.write(errno_slot_, &z, 4);
    }
    e.write_reg(Reg::Ret0, errno_slot_);
  };
  add("__errno", errno_fn);
  add("__errno_location", errno_fn);

  // dynamic-linker / fortified libc helpers used by packers
  // dladdr(addr, Dl_info*): fill { dli_fname, dli_fbase, dli_sname, dli_saddr }
  // for the module containing addr (greatest registered base <= addr). Packers
  // call this on one of their own functions to recover their .so path/name
  // (e.g. Jiagu derives its "<rand>Protected" name from dli_fname); returning 0
  // leaves that name empty. Needs libs registered via register_phdr_lib.
  add("dladdr", [this](Engine& e) {
    const uint64_t addr = e.read_reg(Reg::A0), info = e.read_reg(Reg::A1);
    const PhdrLib* best = nullptr;
    for (const PhdrLib& L : phdr_libs_)
      if (L.dlpi_addr <= addr && (!best || L.dlpi_addr > best->dlpi_addr))
        best = &L;
    if (!best || !info) {
      e.write_reg(Reg::Ret0, 0);
      return;
    }
    e.write_t<uint64_t>(info + 0, best->name_addr);  // dli_fname
    e.write_t<uint64_t>(info + 8, best->dlpi_addr);  // dli_fbase
    e.write_t<uint64_t>(info + 16, 0);               // dli_sname
    e.write_t<uint64_t>(info + 24, 0);               // dli_saddr
    e.write_reg(Reg::Ret0, 1);                       // nonzero = success
  });
  // dlopen/dlsym: packers resolve libc/liblog/libart symbols dynamically
  // (anti-static). Return a unique non-null handle; dlsym resolves by NAME to
  // the same trampoline the ELF loader uses, so dlopen'd calls land on our
  // stubs. (A guest-loaded inner.so would need real loading here, not yet;
  // system libs resolve fine by name.)
  add("dlopen", [this](Engine& e) {
    const uint64_t p = e.read_reg(Reg::A0);
    const std::string name = p ? engine_.read_cstr(p) : std::string{};
    if (p && std::getenv("VARDOGER_DL_LOG"))
      std::fprintf(stderr, "[dlopen] \"%s\"\n", name.c_str());
    // Libs that genuinely DON'T EXIST on a modern (ART) device should fail, or
    // packers' runtime-detection (Dalvik vs ART) takes the wrong branch:
    // libdvm.so (the Dalvik runtime, gone since Android 5). Gated: some packers
    // ABORT if libdvm fails to load (they expect at least one runtime handle),
    // so default to a handle. ART fidelity: on a real ART device (API>=21)
    // libdvm.so DOES NOT EXIST, so dlopen returns NULL. A packer probes
    // dlopen("libdvm.so") to pick its Dalvik-vs-ART code path; a non-null
    // handle makes it wrongly take the Dalvik path (resolve dvm* symbols) and
    // never install its ART hooks (e.g. Ijiami's ClassLinker::LoadMethod /
    // Instrumentation per-method-decrypt). In ART mode (VARDOGER_ART) return NULL
    // so the ART path is taken. VARDOGER_FAKE_DALVIK restores the old handle for
    // the rare (pre-2014) packer that aborts without a Dalvik handle.
    if ((std::getenv("VARDOGER_NO_DALVIK") ||
         (std::getenv("VARDOGER_ART") && !std::getenv("VARDOGER_FAKE_DALVIK"))) &&
        name.find("libdvm") != std::string::npos) {
      if (std::getenv("VARDOGER_DL_LOG"))
        std::fprintf(stderr, "[dlopen]   -> NULL (libdvm absent on ART)\n");
      e.write_reg(Reg::Ret0, 0);
      return;
    }
    // Anti-tamper evasion: packers dlopen() a known hooking/unpacking lib and
    // self-destruct if the handle is NON-null (lib present). Our default
    // non-null handle false-positives them (e.g. Ijiami's OLLVM self_destruct
    // on dlopen("libsotweak.so")). Return NULL for these so the env looks
    // clean.
    static const char* kTamperLibs[] = {
        "libsotweak",  "libxiaojianbang",  "libsubstrate",    "frida",
        "libriru",     "libmemtrack_real", "libwhale",        "libepic",
        "libsandhook", "libdobby",         "libfrida-gadget", "libhoudini_hook",
        "libzygisk",   "libunpacker",      "libfupk",         "libfart",
        "libdexdump",
    };
    if (!std::getenv("VARDOGER_NO_TAMPER_EVASION") && p)
      for (const char* bad : kTamperLibs)
        if (name.find(bad) != std::string::npos) {
          if (std::getenv("VARDOGER_DL_LOG"))
            std::fprintf(stderr, "[dlopen]   -> NULL (tamper-lib evasion)\n");
          e.write_reg(Reg::Ret0, 0);
          return;
        }
    // A dlopen of a lib that genuinely doesn't exist (cache-miss of a
    // to-be-decrypted inner lib) must return NULL so the packer takes its
    // "decrypt+write+retry" path instead of assuming the lib loaded.
    // VARDOGER_DLOPEN_FAIL=substr1,substr2 forces NULL for matching names.
    if (const char* ff = std::getenv("VARDOGER_DLOPEN_FAIL")) {
      std::string s(ff);
      size_t pos = 0;
      while (pos < s.size()) {
        size_t c = s.find(',', pos);
        std::string sub = s.substr(pos, c == std::string::npos ? c : c - pos);
        if (!sub.empty() && name.find(sub) != std::string::npos) {
          e.write_reg(Reg::Ret0, 0);
          return;
        }
        if (c == std::string::npos) break;
        pos = c + 1;
      }
    }
    e.write_reg(Reg::Ret0, mem_.heap_alloc(8));  // unique, non-null
  });
  add("dlsym", [this](Engine& e) {  // (handle, name)
    const uint64_t name_p = e.read_reg(Reg::A1);
    if (!name_p) {
      e.write_reg(Reg::Ret0, 0);
      return;
    }
    const std::string name = engine_.read_cstr(name_p);
    // Android linker debugger-rendezvous functions (rtld_db_dlactivity /
    // _r_debug_state) are BRK-trap stubs in a real bionic linker, the GDB/LLDB
    // SO-load notification point. Anti-debug packers dlsym them from linker64
    // and require the FIRST instruction to be `brk #0` (0xD4200000) as a
    // clean-linker signature (a hooked/patched linker would differ). Return
    // real guest memory whose first word is brk#0.
    if (name.find("rtld_db_dlactivity") != std::string::npos ||
        name.find("r_debug_state") != std::string::npos) {
      static uint64_t s_brkstub = 0;
      if (!s_brkstub) {
        s_brkstub = mem_.mmap_alloc(0x8, UC_PROT_READ | UC_PROT_EXEC,
                                    "rtld_db_dlactivity");
        engine_.write_t<uint32_t>(s_brkstub, 0xD4200000);      // brk #0
        engine_.write_t<uint32_t>(s_brkstub + 4, 0xD65F03C0);  // ret
      }
      if (std::getenv("VARDOGER_DL_LOG"))
        std::fprintf(stderr, "[dlsym] %s -> brk#0 stub %#llx\n", name.c_str(),
                     (unsigned long long)s_brkstub);
      e.write_reg(Reg::Ret0, s_brkstub);
      return;
    }
    // Anti-tamper hook-symbol evasion (mirrors dlopen's libsotweak/libdvm
    // NULLing): a permissive stub returns non-null for EVERY name, so a packer
    // that probes dlsym for a known hooking- framework symbol (MT Manager
    // "SignKill" = Java_cc_binmt_signature_Hook_*, Frida gum_/ frida_agent,
    // Xposed, Substrate) reads the non-null result as "hook installed" and
    // self- destructs. A clean device has none of these symbols -> return NULL
    // so the check passes.
    static const char* kHookSyms[] = {
        "binmt",        "signature_Hook",     // MT Manager "SignKill"
        "pine_backup",  "backup_trampoline",  // Pine
        "frida",        "gum_",
        "gmain",        "gdbus",  // Frida gadget
        "xposed",       "de_robv",
        "XposedBridge",  // Xposed
        "substrate",    "MSHook",
        "MSGetImage",                // Cydia Substrate
        "sandhook",     "SandHook",  // SandHook
        "yahfa",        "YAHFA",     // YAHFA
        "lsplant",      "lsposed",
        "LSPlant",  // LSPlant / LSPosed
        "shadowhook",   "bytehook",
        "fasthook",                        // shadowhook / bytehook / fasthook
        "epic_hook",    "me_weishu_epic",  // Epic
        "Dobby",        "dobby_",
        "whale_",       "hookzz",  // Dobby / Whale / HookZz
    };
    for (const char* h : kHookSyms)
      if (name.find(h) != std::string::npos) {
        if (std::getenv("VARDOGER_DL_LOG"))
          std::fprintf(stderr, "[dlsym] %s -> NULL (hook-symbol evasion)\n",
                       name.c_str());
        e.write_reg(Reg::Ret0, 0);
        return;
      }
    if (dlsym_provider_) {
      const uint64_t a = dlsym_provider_(name);
      if (a) {
        if (std::getenv("VARDOGER_DL_LOG"))
          std::fprintf(stderr, "[dlsym] %s -> REAL %#llx\n", name.c_str(),
                       (unsigned long long)a);
        e.write_reg(Reg::Ret0, a);
        return;
      }
    }
    if (std::getenv("VARDOGER_DL_LOG"))
      std::fprintf(stderr, "[dlsym] %s -> stub\n", name.c_str());
    e.write_reg(Reg::Ret0, resolve(name));
  });
  // ctype: the guest calls these as imports; the fallback's 0 means "not a
  // space/digit", silently breaking the guest's own parsers.
  add("isspace", [](Engine& e) {
    const int c = (int)e.read_reg(Reg::A0);
    e.write_reg(Reg::Ret0, (c == ' ' || c == '\t' || c == '\n' || c == '\v' ||
                            c == '\f' || c == '\r')
                               ? 1
                               : 0);
  });
  add("isdigit", [](Engine& e) {
    const int c = (int)e.read_reg(Reg::A0);
    e.write_reg(Reg::Ret0, (c >= '0' && c <= '9') ? 1 : 0);
  });
  add("isxdigit", [](Engine& e) {
    const int c = (int)e.read_reg(Reg::A0);
    e.write_reg(Reg::Ret0, ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                            (c >= 'A' && c <= 'F'))
                               ? 1
                               : 0);
  });
  add("isalpha", [](Engine& e) {
    const int c = (int)e.read_reg(Reg::A0);
    e.write_reg(Reg::Ret0,
                ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) ? 1 : 0);
  });
  add("toupper", [](Engine& e) {
    int c = (int)e.read_reg(Reg::A0);
    if (c >= 'a' && c <= 'z') c -= 32;
    e.write_reg(Reg::Ret0, (uint64_t)c);
  });
  add("tolower", [](Engine& e) {
    int c = (int)e.read_reg(Reg::A0);
    if (c >= 'A' && c <= 'Z') c += 32;
    e.write_reg(Reg::Ret0, (uint64_t)c);
  });
  add("mkdir", [](Engine& e) { e.write_reg(Reg::Ret0, 0); });   // success
  add("setenv", [](Engine& e) { e.write_reg(Reg::Ret0, 0); });  // success
  add("chmod", [](Engine& e) { e.write_reg(Reg::Ret0, 0); });
  add("chown", [](Engine& e) { e.write_reg(Reg::Ret0, 0); });
  // Jiagu shell-state hook (unresolved import in the VM bytecode). Default 0
  // may read as "failed" and trip a bail; VARDOGER_SHELLSTATE overrides the return
  // for probing.
  add("doSetShellState", [](Engine& e) {
    const char* v = std::getenv("VARDOGER_SHELLSTATE");
    e.write_reg(Reg::Ret0, v ? std::strtoull(v, nullptr, 0) : 1);
  });
  add("dlclose", [](Engine& e) { e.write_reg(Reg::Ret0, 0); });
  add("__strlen_chk", [](Engine& e) {  // (s, maxlen)
    const uint64_t s = e.read_reg(Reg::A0), maxlen = e.read_reg(Reg::A1);
    uint64_t n = 0;
    while (n < maxlen && e.read_t<uint8_t>(s + n)) ++n;
    e.write_reg(Reg::Ret0, n);
  });
  // drand48 family, a 48-bit LCG (Xn+1 = a*Xn + c mod 2^48, a=0x5DEECE66D,
  // c=0xB). Stubbing these to 0 hangs packers that use lrand48() in a loop
  // bound / until-match condition (arm32 Break self-decrypt).
  {
    auto st = std::make_shared<uint64_t>(0x1234ABCD330EULL);
    auto step = [st]() -> uint64_t {
      *st = (0x5DEECE66DULL * *st + 0xBULL) & 0xFFFFFFFFFFFFULL;
      return *st;
    };
    add("srand48", [st](Engine& e) {
      *st = (((uint64_t)(e.read_reg(Reg::A0) & 0xffffffffu)) << 16) | 0x330eULL;
      e.write_reg(Reg::Ret0, 0);
    });
    add("seed48", [st](Engine& e) {
      (void)e;
      *st = 0x1234ABCD330EULL;
      e.write_reg(Reg::Ret0, 0);
    });
    add("lcong48", [st](Engine& e) {
      (void)e;
      e.write_reg(Reg::Ret0, 0);
    });
    add("lrand48", [step](Engine& e) {
      e.write_reg(Reg::Ret0, (uint32_t)((step() >> 17) & 0x7FFFFFFFu));
    });  // [0, 2^31)
    add("nrand48", [step](Engine& e) {
      e.write_reg(Reg::Ret0, (uint32_t)((step() >> 17) & 0x7FFFFFFFu));
    });
    add("mrand48", [step](Engine& e) {
      e.write_reg(Reg::Ret0, (uint32_t)((step() >> 16) & 0xFFFFFFFFu));
    });  // [-2^31, 2^31)
    add("jrand48", [step](Engine& e) {
      e.write_reg(Reg::Ret0, (uint32_t)((step() >> 16) & 0xFFFFFFFFu));
    });
  }
  add("mprotect", [this](Engine& e) {  // (addr, len, prot) -> mem.protect
    const uint64_t addr = e.read_reg(Reg::A0), len = e.read_reg(Reg::A1),
                   prot = e.read_reg(Reg::A2);
    uint32_t up = 0;
    if (prot & 1) up |= UC_PROT_READ;
    if (prot & 2) up |= UC_PROT_WRITE;
    if (prot & 4) up |= UC_PROT_EXEC;
    // Page-by-page + tolerant: packers mprotect ranges whose tail our loader
    // didn't materialize (notably the arm32 self-decrypt, which mprotects
    // across a freshly-decrypted mmap). Map any unmapped page, protect the
    // mapped ones, never abort (a raw mem.protect over an unmapped tail throws
    // UC_ERR_NOMEM and kills the self-decrypt before .text is even readable).
    const uint64_t lo = addr & ~0xfffULL,
                   hi = (addr + (len ? len : 1) + 0xfff) & ~0xfffULL;
    for (uint64_t p = lo; p < hi; p += 0x1000) {
      if (!mem_.is_mapped(p))
        mem_.map_fixed(p, 0x1000, up ? up : (UC_PROT_READ | UC_PROT_WRITE),
                       Memory::Kind::Other, "mprotect-fill");
      else
        mem_.protect(p, 0x1000, up);
    }
    e.write_reg(Reg::Ret0, 0);
  });
  // case-insensitive compares (returning 0 == "equal" from the fallback
  // silently corrupts ABI/filename branches, packers compare a lot).
  auto lc = [](uint8_t c) {
    return (c >= 'A' && c <= 'Z') ? uint8_t(c + 32) : c;
  };
  add("strcasecmp", [lc](Engine& e) {
    const std::string a = e.read_cstr(e.read_reg(Reg::A0)),
                      b = e.read_cstr(e.read_reg(Reg::A1));
    if (std::getenv("VARDOGER_STR_LOG"))
      std::fprintf(stderr, "[strcasecmp] \"%s\" vs \"%s\"\n", a.c_str(),
                   b.c_str());
    size_t i = 0;
    for (; i < a.size() && i < b.size(); ++i) {
      int d = lc(a[i]) - lc(b[i]);
      if (d) {
        e.write_reg(Reg::Ret0, (uint64_t)(int64_t)d);
        return;
      }
    }
    e.write_reg(Reg::Ret0, (uint64_t)(int64_t)(lc(i < a.size() ? a[i] : 0) -
                                               lc(i < b.size() ? b[i] : 0)));
  });
  add("strncasecmp", [lc](Engine& e) {
    const std::string a = e.read_cstr(e.read_reg(Reg::A0)),
                      b = e.read_cstr(e.read_reg(Reg::A1));
    const uint64_t n = e.read_reg(Reg::A2);
    for (uint64_t i = 0; i < n; ++i) {
      const uint8_t ca = i < a.size() ? a[i] : 0, cb = i < b.size() ? b[i] : 0;
      const int d = lc(ca) - lc(cb);
      if (d || !ca) {
        e.write_reg(Reg::Ret0, (uint64_t)(int64_t)d);
        return;
      }
    }
    e.write_reg(Reg::Ret0, 0);
  });
  // minimal sscanf: whitespace, literals, and
  // %[*][width][l|ll]{d,i,u,o,x,X,p,s,c}. Returns the assignment count. Packers
  // use it to parse /proc/self/maps + versions.
  add("sscanf", [](Engine& e) {
    const std::string in = e.read_cstr(e.read_reg(Reg::A0)),
                      fmt = e.read_cstr(e.read_reg(Reg::A1));
    if (std::getenv("VARDOGER_STR_LOG"))
      std::fprintf(stderr, "[sscanf] fmt=%.40s | in=%.60s\n", fmt.c_str(),
                   in.c_str());
    size_t ip = 0;
    int argi = 2, matched = 0;
    for (size_t fp = 0; fp < fmt.size(); ++fp) {
      unsigned char fc = fmt[fp];
      if (std::isspace(fc)) {
        while (ip < in.size() && std::isspace((unsigned char)in[ip])) ++ip;
        continue;
      }
      if (fc != '%') {
        if (ip < in.size() && in[ip] == (char)fc) {
          ++ip;
          continue;
        }
        break;
      }
      ++fp;
      bool suppress = false;
      if (fp < fmt.size() && fmt[fp] == '*') {
        suppress = true;
        ++fp;
      }
      int width = 0;
      while (fp < fmt.size() && std::isdigit((unsigned char)fmt[fp]))
        width = width * 10 + (fmt[fp++] - '0');
      int lng = 0;
      while (fp < fmt.size() && (fmt[fp] == 'l' || fmt[fp] == 'h' ||
                                 fmt[fp] == 'z' || fmt[fp] == 'j')) {
        if (fmt[fp] == 'l') ++lng;
        ++fp;
      }
      if (fp >= fmt.size()) break;
      const char conv = fmt[fp];
      if (conv != 'c' && conv != '%')
        while (ip < in.size() && std::isspace((unsigned char)in[ip])) ++ip;
      if (conv == '%') {
        if (ip < in.size() && in[ip] == '%') ++ip;
        continue;
      }
      if (std::strchr("diuoxXp", conv)) {
        const int base = (conv == 'x' || conv == 'X' || conv == 'p')
                             ? 16
                             : (conv == 'o' ? 8 : 10);
        const size_t start = ip;
        bool neg = false;
        if (ip < in.size() && (in[ip] == '+' || in[ip] == '-'))
          neg = in[ip++] == '-';
        if (base == 16 && ip + 1 < in.size() && in[ip] == '0' &&
            (in[ip + 1] == 'x' || in[ip + 1] == 'X'))
          ip += 2;
        uint64_t val = 0;
        size_t digs = 0;
        while (ip < in.size() && (!width || (int)(ip - start) < width)) {
          const char c = in[ip];
          int d;
          if (c >= '0' && c <= '9')
            d = c - '0';
          else if (c >= 'a' && c <= 'f')
            d = c - 'a' + 10;
          else if (c >= 'A' && c <= 'F')
            d = c - 'A' + 10;
          else
            break;
          if (d >= base) break;
          val = val * base + d;
          ++ip;
          ++digs;
        }
        if (!digs) break;
        if (neg) val = (uint64_t)(-(int64_t)val);
        if (!suppress) {
          const uint64_t o = aapcs_arg(e, argi++);
          if (lng)
            e.write_t<uint64_t>(o, val);
          else
            e.write_t<uint32_t>(o, (uint32_t)val);
          ++matched;
        }
      } else if (conv == 's') {
        std::string tok;
        while (ip < in.size() && !std::isspace((unsigned char)in[ip]) &&
               (!width || (int)tok.size() < width))
          tok += in[ip++];
        if (tok.empty()) break;
        if (!suppress) {
          const uint64_t o = aapcs_arg(e, argi++);
          e.write(o, tok.c_str(), tok.size() + 1);
          ++matched;
        }
      } else if (conv == 'c') {
        const int n = width ? width : 1;
        if ((int)(in.size() - ip) < n) break;
        if (!suppress) {
          const uint64_t o = aapcs_arg(e, argi++);
          e.write(o, in.data() + ip, n);
          ++matched;
        }
        ip += n;
      } else
        break;
    }
    e.write_reg(Reg::Ret0, (uint64_t)(int64_t)matched);
  });
  add("__strncpy_chk2", [](Engine& e) {  // (dst, src, n, dstlen, srclen)
    const uint64_t dst = e.read_reg(Reg::A0), src = e.read_reg(Reg::A1),
                   n = e.read_reg(Reg::A2);
    std::vector<uint8_t> b(n, 0);
    for (uint64_t i = 0; i < n; ++i) {
      uint8_t c = e.read_t<uint8_t>(src + i);
      b[i] = c;
      if (!c) break;
    }
    if (n) e.write(dst, b.data(), n);
    e.write_reg(Reg::Ret0, dst);
  });

  register_zlib();  // inflate/inflateInit*/inflateEnd backed by host zlib

  // ---- pthreads: routed through the cooperative Scheduler when one is active
  // (real worker contexts that interleave at yield points), else benign
  // fallbacks.
  register_pthreads();
  // pthread_once(once, init): run init() exactly once via PC redirection (no
  // nesting). init is void(void), so it returns straight to pthread_once's
  // caller, as if pthread_once ran it and returned. (X0 is whatever init left;
  // callers virtually always ignore pthread_once's return value.)
  add("pthread_once", [](Engine& e) {
    const uint64_t once = e.read_reg(Reg::A0), init = e.read_reg(Reg::A1);
    if (e.read_t<uint32_t>(once) == 0) {
      e.write_t<uint32_t>(once,
                          2);  // mark done before running (re-entrancy safe)
      e.redirect(init);        // continue into init(); do NOT set Ret0
    } else {
      e.write_reg(Reg::Ret0, 0);
    }
  });
  add("pthread_key_create", [this](Engine& e) {  // (key*, dtor)
    const uint64_t key = next_pthread_key_++;
    if (e.pointer_size() == 8)
      e.write_t<uint64_t>(e.read_reg(Reg::A0), key);
    else
      e.write_t<uint32_t>(e.read_reg(Reg::A0), static_cast<uint32_t>(key));
    e.write_reg(Reg::Ret0, 0);
  });
  add("pthread_setspecific", [this](Engine& e) {  // (key, value)
    tls_values_[e.read_reg(Reg::A0)] = e.read_reg(Reg::A1);
    e.write_reg(Reg::Ret0, 0);
  });
  add("pthread_getspecific", [this](Engine& e) {
    auto it = tls_values_.find(e.read_reg(Reg::A0));
    e.write_reg(Reg::Ret0, it == tls_values_.end() ? 0 : it->second);
  });

  // dl_iterate_phdr(callback, data): invoke `callback(&info, sizeof(info),
  // data)` for each registered library via guest re-entry (PC redirect + return
  // trampoline), so packers can discover their own load base/phdrs. Stops early
  // if the callback returns non-zero.
  if (!dl_return_stub_)
    dl_return_stub_ = tramp_.alloc("dl_iterate_phdr_return", [this](Engine& e) {
      if (e.read_reg(Reg::Ret0) != 0) {
        e.redirect(dl_ret_lr_);
        return;
      }  // callback said stop
      dl_iter_step();  // else next lib
    });
  add("dl_iterate_phdr", [this](Engine& e) {
    dl_cb_ = e.read_reg(Reg::A0);
    dl_data_ = e.read_reg(Reg::A1);
    dl_ret_lr_ = e.read_reg(Reg::Lr);
    dl_idx_ = 0;
    if (std::getenv("VARDOGER_DL_LOG"))
      std::fprintf(stderr, "[dl_iterate_phdr] cb=%#llx data=%#llx libs=%zu\n",
                   (unsigned long long)dl_cb_, (unsigned long long)dl_data_,
                   phdr_libs_.size());
    if (!dl_info_buf_)
      dl_info_buf_ =
          mem_.mmap_alloc(64, UC_PROT_READ | UC_PROT_WRITE, "dl_phdr_info");
    if (!dl_cb_ || phdr_libs_.empty()) {
      e.write_reg(Reg::Ret0, 0);
      return;
    }
    dl_iter_step();
  });

  // getauxval(type): the ELF auxiliary vector. Return realistic values (0 =
  // "not present" makes glibc/bionic fall back to other discovery, e.g.
  // dl_iterate_phdr).
  add("getauxval", [this](Engine& e) {
    const uint64_t t = e.read_reg(Reg::A0);
    static uint64_t aux_random = 0;
    uint64_t v = 0;
    switch (t) {
      case 6:
        v = 0x1000;
        break;  // AT_PAGESZ
      case 4:
        v = 56;
        break;  // AT_PHENT (Elf64_Phdr size)
      case 16:
        v = 0x000000000020b7ffull;
        break;  // AT_HWCAP (typical arm64)
      case 26:
        v = 0x2;
        break;  // AT_HWCAP2
      case 23:
        v = 0;
        break;  // AT_SECURE = not setuid
      case 25:  // AT_RANDOM -> 16 bytes of (deterministic) entropy
        if (!aux_random) {
          aux_random =
              mem_.mmap_alloc(16, UC_PROT_READ | UC_PROT_WRITE, "AT_RANDOM");
          for (int i = 0; i < 16; ++i)
            engine_.write_t<uint8_t>(aux_random + i, (uint8_t)(0x3B * (i + 1)));
        }
        v = aux_random;
        break;
      default:
        v = 0;
        break;  // AT_PHDR/AT_BASE/... unknown -> 0 (fall back)
    }
    if (std::getenv("VARDOGER_DL_LOG"))
      std::fprintf(stderr, "[getauxval] type=%llu -> %#llx\n",
                   (unsigned long long)t, (unsigned long long)v);
    e.write_reg(Reg::Ret0, v);
  });

  // ---- C++ runtime teardown hooks: safe no-ops (we control teardown) ----
  add("__cxa_finalize", [](Engine& e) { e.write_reg(Reg::Ret0, 0); });
  add("__cxa_atexit", [](Engine& e) { e.write_reg(Reg::Ret0, 0); });
  add("atexit", [](Engine& e) { e.write_reg(Reg::Ret0, 0); });
  // abort/_exit/raise: terminate this emulation cleanly (a labeled stop) rather
  // than returning 0 and running off into garbage, these are deliberate
  // bail-outs.
  add("abort", [](Engine& e) {
    const bool noop = std::getenv("VARDOGER_ABORT_NOOP") != nullptr;
    std::fprintf(stderr, "[abort] guest called abort() lr=%#llx - %s\n",
                 (unsigned long long)e.read_reg(Reg::Lr),
                 noop ? "NOOP (returning to lr)" : "stopping");
    if (!noop)
      e.stop();  // else the trampoline RET returns to lr, neutralizing the
                 // anti-analysis abort
  });
  add("exit", [](Engine& e) {
    const bool noop = std::getenv("VARDOGER_EXIT_NOOP") != nullptr;
    std::fprintf(stderr, "[exit] guest called exit(%lld) lr=%#llx - %s\n",
                 (long long)e.read_reg(Reg::A0),
                 (unsigned long long)e.read_reg(Reg::Lr),
                 noop ? "NOOP (returning to lr)" : "stopping");
    if (!noop)
      e.stop();  // else fall through: trampoline returns to lr, neutralizing
                 // the anti-analysis exit
  });
  add("_exit", [](Engine& e) { e.stop(); });
  add("_Exit", [](Engine& e) { e.stop(); });
  add("atexit", [](Engine& e) { e.write_reg(Reg::Ret0, 0); });
}

void Stubs::register_system(System& sys) {
  // Anti-debug: ptrace(PTRACE_TRACEME) returns 0 on a non-traced process.
  add("ptrace", [](Engine& e) { e.write_reg(Reg::Ret0, 0); });

  // ---- directory enumeration (opendir/readdir/closedir), backed by synthetic
  // + VFS entries ---- Packers enumerate dirs to check the environment (e.g.
  // /sys/class/net for network interfaces, /proc/self/fd, the app lib dir). The
  // default stubs returned NULL (dir doesn't exist), which fails those checks.
  // Model a real listing. DIR* is a host-side token; readdir fills a bionic
  // arm64 struct dirent { u64 d_ino; i64 d_off; u16 d_reclen; u8 d_type; char
  // d_name[256] } (name@19).
  // DT_* d_type values used in struct dirent.
  enum : uint8_t { kDtDir = 4, kDtReg = 8, kDtLnk = 10 };
  struct DirEntry {
    std::string name;
    uint8_t type;
  };
  struct DirState {
    std::vector<DirEntry> ents;
    size_t idx;
    uint64_t buf;
  };
  static std::map<uint64_t, DirState> g_dirs;
  static uint64_t g_dir_token = 0x0D190000ull;
  auto dir_entries = [&sys](std::string path) -> std::vector<DirEntry> {
    while (path.size() > 1 && path.back() == '/') path.pop_back();
    // name -> d_type; a directory classification wins over a file one (e.g. a
    // component seen both as a served file's parent and a registered dir).
    std::map<std::string, uint8_t> ent;
    auto put = [&](const std::string& name, uint8_t type) {
      auto it = ent.find(name);
      if (it == ent.end())
        ent[name] = type;
      else if (type == kDtDir)
        it->second = kDtDir;
    };
    // Synthetic well-known dirs (interfaces are symlinks on a real device).
    if (path == "/sys/class/net") {
      put("lo", kDtLnk);
      put("wlan0", kDtLnk);
    }
    // Contribute the immediate child of `full` under `path`: a directory if
    // `full` lies deeper than one level (an intermediate dir) or is itself a
    // registered directory, else a regular file (e.g. base.apk in the code dir).
    auto consider = [&](const std::string& full, bool leaf_is_dir) {
      if (full.size() <= path.size() + 1 ||
          full.compare(0, path.size(), path) != 0 || full[path.size()] != '/')
        return;
      const std::string rest = full.substr(path.size() + 1);
      const auto slash = rest.find('/');
      const std::string comp = rest.substr(0, slash);
      if (comp.empty()) return;
      put(comp, (slash != std::string::npos || leaf_is_dir) ? kDtDir : kDtReg);
    };
    for (const auto& kv : sys.vfs().files()) consider(kv.first, false);
    for (const auto& d : sys.vfs().dirs()) consider(d, true);

    std::vector<DirEntry> out{{".", kDtDir}, {"..", kDtDir}};
    for (const auto& kv : ent) out.push_back({kv.first, kv.second});
    return out;
  };
  add("opendir", [this, dir_entries](Engine& e) {
    const std::string path = e.read_cstr(e.read_reg(Reg::A0));
    std::vector<DirEntry> ents = dir_entries(path);
    if (std::getenv("VARDOGER_OPEN_LOG"))
      std::fprintf(stderr, "[opendir] \"%s\" -> %zu entries\n", path.c_str(),
                   ents.size());
    // Return a valid DIR* even for an empty dir (just "."/"."), a real
    // existing-but-empty directory (e.g. a fresh .jiagu cache) is enumerable,
    // not ENOENT. Packers that stat/list their cache dir and then populate it
    // need opendir to SUCCEED here.
    const uint64_t tok = g_dir_token += 0x100;
    const uint64_t buf = mem_.heap_alloc(300);
    g_dirs[tok] = DirState{std::move(ents), 0, buf};
    e.write_reg(Reg::Ret0, tok);
  });
  auto do_readdir = [this](Engine& e) {
    const uint64_t tok = e.read_reg(Reg::A0);
    auto it = g_dirs.find(tok);
    if (it == g_dirs.end() || it->second.idx >= it->second.ents.size()) {
      e.write_reg(Reg::Ret0, 0);
      return;
    }
    DirState& d = it->second;
    const DirEntry& de = d.ents[d.idx];
    const uint64_t b = d.buf;
    e.write_t<uint64_t>(b + 0, d.idx + 1);          // d_ino
    e.write_t<int64_t>(b + 8, (int64_t)d.idx + 1);  // d_off
    e.write_t<uint16_t>(b + 16, 275);               // d_reclen
    e.write_t<uint8_t>(b + 18, de.type);            // d_type (DT_DIR/REG/LNK)
    std::vector<uint8_t> name(de.name.begin(), de.name.end());
    name.push_back(0);
    e.write(b + 19, name.data(), name.size());
    d.idx++;
    e.write_reg(Reg::Ret0, b);
  };
  add("readdir", do_readdir);
  add("readdir64", do_readdir);
  add("closedir", [](Engine& e) {
    g_dirs.erase(e.read_reg(Reg::A0));
    e.write_reg(Reg::Ret0, 0);
  });

  // ---- wall-clock time/date (one consistent "now"; packers gate on license
  // dates) ---- struct tm layout (arm64 bionic): 9 ints at +0,4,8,..,32 then
  // 64-bit gmtoff/zone.
  auto rd_tm = [](Engine& e, uint64_t p) {
    std::tm t{};
    t.tm_sec = (int)e.read_t<int32_t>(p + 0);
    t.tm_min = (int)e.read_t<int32_t>(p + 4);
    t.tm_hour = (int)e.read_t<int32_t>(p + 8);
    t.tm_mday = (int)e.read_t<int32_t>(p + 12);
    t.tm_mon = (int)e.read_t<int32_t>(p + 16);
    t.tm_year = (int)e.read_t<int32_t>(p + 20);
    t.tm_wday = (int)e.read_t<int32_t>(p + 24);
    t.tm_yday = (int)e.read_t<int32_t>(p + 28);
    t.tm_isdst = (int)e.read_t<int32_t>(p + 32);
    return t;
  };
  auto wr_tm = [this](Engine& e, uint64_t p, const std::tm& t) {
    if (!mem_.is_mapped(p)) {
      std::fprintf(stderr, "[time] wr_tm to unmapped %#llx - skip\n",
                   (unsigned long long)p);
      return;
    }
    e.write_t<int32_t>(p + 0, t.tm_sec);
    e.write_t<int32_t>(p + 4, t.tm_min);
    e.write_t<int32_t>(p + 8, t.tm_hour);
    e.write_t<int32_t>(p + 12, t.tm_mday);
    e.write_t<int32_t>(p + 16, t.tm_mon);
    e.write_t<int32_t>(p + 20, t.tm_year);
    e.write_t<int32_t>(p + 24, t.tm_wday);
    e.write_t<int32_t>(p + 28, t.tm_yday);
    e.write_t<int32_t>(p + 32, t.tm_isdst);
  };
  add("time", [&sys, this](Engine& e) {  // (time_t* out)
    const uint64_t t = sys.now_unix(), out = e.read_reg(Reg::A0);
    if (out && mem_.is_mapped(out))
      e.write_t<uint64_t>(out, t);
    else if (out)
      std::fprintf(stderr, "[time] out unmapped %#llx - skip\n",
                   (unsigned long long)out);
    e.write_reg(Reg::Ret0, t);
  });
  add("gettimeofday",
      [&sys, this](Engine& e) {  // (struct timeval* tv, tz) -> {sec, usec}
        const uint64_t tv = e.read_reg(Reg::A0);
        if (tv && mem_.is_mapped(tv)) {
          e.write_t<uint64_t>(tv, sys.now_unix());  // tv_sec
          e.write_t<uint64_t>(tv + 8,
                              (sys.now_ns() / 1000) % 1000000);  // tv_usec
        }
        e.write_reg(Reg::Ret0, 0);
      });
  add("mktime", [rd_tm](Engine& e) {  // (struct tm*) -> epoch (UTC)
    std::tm t = rd_tm(e, e.read_reg(Reg::A0));
    e.write_reg(Reg::Ret0, (uint64_t)(int64_t)timegm(&t));
  });
  auto gmt_r = [wr_tm](Engine& e) {  // (time_t*, struct tm* out)
    const time_t t = (time_t)e.read_t<uint64_t>(e.read_reg(Reg::A0));
    const uint64_t out = e.read_reg(Reg::A1);
    std::tm r{};
    ::gmtime_r(&t, &r);
    wr_tm(e, out, r);
    e.write_reg(Reg::Ret0, out);
  };
  add("gmtime_r", gmt_r);
  add("localtime_r", gmt_r);  // emulate UTC == local
  auto gmt1 = [this,
               wr_tm](Engine& e) {  // (time_t*) -> struct tm* (static buf)
    if (!tm_buf_) tm_buf_ = mem_.heap_alloc(64);
    const time_t t = (time_t)e.read_t<uint64_t>(e.read_reg(Reg::A0));
    std::tm r{};
    ::gmtime_r(&t, &r);
    wr_tm(e, tm_buf_, r);
    e.write_reg(Reg::Ret0, tm_buf_);
  };
  add("gmtime", gmt1);
  add("localtime", gmt1);

  // Device fingerprint, consistent with the JNI Build.* fields §7).
  add("__system_property_get", [&sys](Engine& e) {
    const std::string name = e.read_cstr(e.read_reg(Reg::A0));
    const uint64_t out = e.read_reg(Reg::A1);
    const std::string v = sys.get_property(name);
    if (std::getenv("VARDOGER_PROP_LOG"))
      std::fprintf(stderr, "[getprop] \"%s\" -> \"%s\"\n", name.c_str(),
                   v.c_str());
    e.write(out, v.c_str(), v.size() + 1);  // value + NUL
    e.write_reg(Reg::Ret0, v.size());
  });

  // __system_property_find returns an opaque prop_info*; the guest passes it to
  // __system_property_read[_callback]. We don't model those, so report "not
  // found" (0), callers fall back to __system_property_get, which we do
  // answer.
  add("__system_property_find", [](Engine& e) { e.write_reg(Reg::Ret0, 0); });

  add("getpid", [](Engine& e) { e.write_reg(Reg::Ret0, 1234); });
  // getppid: an app's parent is zygote/zygote64. A 0 (unimplemented) trips
  // anti-debug guardians that expect a normal parent; return a plausible
  // zygote-like pid.
  add("getppid", [](Engine& e) { e.write_reg(Reg::Ret0, 903); });
  add("gettid", [](Engine& e) { e.write_reg(Reg::Ret0, 1234); });
  add("getuid", [](Engine& e) { e.write_reg(Reg::Ret0, 10234); });
  add("geteuid", [](Engine& e) { e.write_reg(Reg::Ret0, 10234); });
  // access(): 0 if the VFS serves/holds the path, else -1. Keeps
  // su/magisk/frida probes "not present" while letting a packer access() a file
  // it just dropped.
  add("access", [&sys](Engine& e) {
    const std::string p = e.read_cstr(e.read_reg(Reg::A0));
    e.write_reg(Reg::Ret0, sys.vexists(p) ? 0 : static_cast<uint64_t>(-1));
  });

  // stat family: return 0 + fill a minimal aarch64 `struct stat` IFF the path
  // exists in the VFS, else -1. A bare "return 0 (exists)" for every stat is
  // WRONG, Ijiami's N.al gates on stat!=0 for a probe path and, on the false
  // "exists" answer, walks a C++ vtable path expecting a real stat'd file (null
  // vtable slot -> crash). Faithful existence check keeps the packer on its
  // normal decrypt path. (bionic struct stat: st_mode@0x10, st_size@0x30.)
  auto do_stat = [&sys](Engine& e, Reg path_reg, Reg buf_reg) {
    const std::string p = e.read_cstr(e.read_reg(path_reg));
    // System pseudo-paths genuinely exist on a real device; treat them as
    // present even if not explicitly materialised in the VFS. App-specific
    // paths fall back to the VFS existence check.
    auto sys_path = [](const std::string& s) {
      return s.rfind("/proc", 0) == 0 || s.rfind("/system", 0) == 0 ||
             s.rfind("/apex", 0) == 0 || s.rfind("/dev", 0) == 0;
    };
    if (!sys.vexists(p) && !sys_path(p)) {
      e.write_reg(Reg::Ret0, static_cast<uint64_t>(-1));
      return;
    }
    const uint64_t buf = e.read_reg(buf_reg);
    if (buf) {
      uint8_t st[128] = {0};
      uint32_t mode = 0x81a4;  // S_IFREG | 0644
      uint64_t sz = 0;
      const int fd = sys.vopen(p);
      if (fd) {  // a regular file
        sz = sys.vsize(fd);
        sys.vclose(fd);
      } else if (sys.is_dir(p)) {  // an installed-app directory
        mode = 0x41ed;             // S_IFDIR | 0755
        sz = 4096;
      }
      std::memcpy(st + 0x10, &mode, 4);  // st_mode
      std::memcpy(st + 0x30, &sz, 8);    // st_size
      e.write(buf, st, sizeof st);
    }
    e.write_reg(Reg::Ret0, 0);
  };
  add("stat", [do_stat](Engine& e) { do_stat(e, Reg::A0, Reg::A1); });
  add("stat64", [do_stat](Engine& e) { do_stat(e, Reg::A0, Reg::A1); });
  add("lstat", [do_stat](Engine& e) { do_stat(e, Reg::A0, Reg::A1); });
  add("lstat64", [do_stat](Engine& e) { do_stat(e, Reg::A0, Reg::A1); });
  add("fstatat", [do_stat](Engine& e) {
    do_stat(e, Reg::A1, Reg::A2);
  });  // (dirfd,path,buf,flags)
  add("fstatat64", [do_stat](Engine& e) { do_stat(e, Reg::A1, Reg::A2); });
  add("newfstatat", [do_stat](Engine& e) { do_stat(e, Reg::A1, Reg::A2); });

  // --- file API: stdio + POSIX, over the VFS's SINGLE fd table (fds are shared
  // with
  //     the raw-syscall layer, so an openat'd file fstat's correctly; written
  //     files read back). The VFS is read-WRITE, packers drop a decrypted DEX
  //     to disk. ---
  add("fopen", [&sys](Engine& e) {  // (path, mode) -> FILE*==fd
    const std::string path = e.read_cstr(e.read_reg(Reg::A0));
    const std::string mode = e.read_cstr(e.read_reg(Reg::A1));
    int flags = Vfs::kRdOnly;
    if (mode.find('w') != std::string::npos)
      flags = Vfs::kWrOnly | Vfs::kCreat | Vfs::kTrunc;
    else if (mode.find('a') != std::string::npos)
      flags = Vfs::kWrOnly | Vfs::kCreat | Vfs::kAppend;
    if (mode.find('+') != std::string::npos) flags |= Vfs::kRdWr;
    const int fd = sys.vopen(path, flags);
    if (std::getenv("VARDOGER_OPEN_LOG"))
      std::fprintf(stderr, "[fopen] \"%s\" (%s) -> %s\n", path.c_str(),
                   mode.c_str(), fd ? "ok" : "FAIL");
    e.write_reg(Reg::Ret0, static_cast<uint64_t>(fd));
  });
  add("fwrite", [&sys](Engine& e) {  // (ptr, size, nmemb, fd)
    const uint64_t ptr = e.read_reg(Reg::A0), size = e.read_reg(Reg::A1),
                   nmemb = e.read_reg(Reg::A2);
    const int fd = static_cast<int>(e.read_reg(Reg::A3));
    const size_t n = size * nmemb;
    std::vector<uint8_t> b(n);
    if (n) e.read(ptr, b.data(), n);
    const size_t put = sys.vwrite(fd, b.data(), n);
    e.write_reg(Reg::Ret0, size ? put / size : 0);
  });
  add("write", [&sys, this](Engine& e) {  // (fd, buf, count)
    const int fd = static_cast<int>(e.read_reg(Reg::A0));
    const uint64_t buf = e.read_reg(Reg::A1), n = e.read_reg(Reg::A2);
    if (!sys.is_open(fd)) {
      e.write_reg(Reg::Ret0, n);
      return;
    }  // 1/2 = stdout/err: pretend OK
    std::vector<uint8_t> b = read_guest_tolerant(
        e, mem_, buf, n);  // tolerant: only mapped bytes, capped
    e.write_reg(Reg::Ret0, sys.vwrite(fd, b.data(), b.size()));
  });
  add("fgets", [&sys](Engine& e) {
    const uint64_t buf = e.read_reg(Reg::A0), n = e.read_reg(Reg::A1);
    const int fd = static_cast<int>(e.read_reg(Reg::A2));
    std::string line;
    if (!sys.vgets(fd, line, n)) {
      e.write_reg(Reg::Ret0, 0);
      return;
    }  // EOF -> NULL
    e.write(buf, line.c_str(), line.size() + 1);
    e.write_reg(Reg::Ret0, buf);
  });
  add("fread", [&sys](Engine& e) {
    const uint64_t ptr = e.read_reg(Reg::A0), size = e.read_reg(Reg::A1),
                   nmemb = e.read_reg(Reg::A2);
    const int fd = static_cast<int>(e.read_reg(Reg::A3));
    std::string out;
    const size_t got = sys.vread(fd, out, size * nmemb);
    if (got) e.write(ptr, out.data(), got);
    e.write_reg(Reg::Ret0, size ? got / size : 0);
  });
  add("fclose", [&sys](Engine& e) {
    sys.vclose(static_cast<int>(e.read_reg(Reg::A0)));
    e.write_reg(Reg::Ret0, 0);
  });
  add("feof", [&sys](Engine& e) {  // nonzero once pos >= size
    const int fd = static_cast<int>(e.read_reg(Reg::A0));
    e.write_reg(Reg::Ret0,
                sys.is_open(fd) && sys.vtell(fd) >= sys.vsize(fd) ? 1 : 0);
  });
  // fseek/ftell over the VFS. Without these a packer that reads its OWN .so via
  // fopen+fseek(END)+ftell+fread (e.g. to parse section headers for an
  // encrypted section like ".bitcode") sees a 0-byte file and fails silently.
  // Reusable primitive.
  auto do_fseek = [&sys](Engine& e) {  // (FILE*==fd, offset, whence) -> 0/-1
    const int fd = static_cast<int>(e.read_reg(Reg::A0));
    const int64_t off = static_cast<int64_t>(e.read_reg(Reg::A1));
    const int whence = static_cast<int>(e.read_reg(Reg::A2));
    if (!sys.is_open(fd)) {
      e.write_reg(Reg::Ret0, static_cast<uint64_t>(-1));
      return;
    }
    const int64_t base =
        (whence == 1 /*SEEK_CUR*/)   ? static_cast<int64_t>(sys.vtell(fd))
        : (whence == 2 /*SEEK_END*/) ? static_cast<int64_t>(sys.vsize(fd))
                                     : 0;
    const int64_t np = base + off;
    if (np < 0) {
      e.write_reg(Reg::Ret0, static_cast<uint64_t>(-1));
      return;
    }
    sys.vseek(fd, static_cast<size_t>(np));
    e.write_reg(Reg::Ret0, 0);
  };
  add("fseek", do_fseek);
  add("fseeko", do_fseek);  // arm64: off_t is 64-bit, same ABI
  auto do_ftell = [&sys](Engine& e) {
    const int fd = static_cast<int>(e.read_reg(Reg::A0));
    e.write_reg(Reg::Ret0,
                sys.is_open(fd) ? sys.vtell(fd) : static_cast<uint64_t>(-1));
  };
  add("ftell", do_ftell);
  add("ftello", do_ftell);
  add("rewind", [&sys](Engine& e) {  // (FILE*==fd) -> void
    const int fd = static_cast<int>(e.read_reg(Reg::A0));
    if (sys.is_open(fd)) sys.vseek(fd, 0);
  });
  add("fileno",
      [](Engine& e) { /* FILE*==fd already */ });  // returns A0 unchanged
  // localeconv(): return a valid `struct lconv*` (never NULL). clang's
  // number/float formatting reads lconv->decimal_point (offset 0); a NULL
  // return -> guest derefs null and faults.
  add("localeconv", [this](Engine& e) {
    static uint64_t lc = 0;
    if (!lc) {
      const uint64_t dot =
          mem_.mmap_alloc(2, UC_PROT_READ | UC_PROT_WRITE, "lconv.dp");
      e.write(dot, ".", 2);
      const uint64_t empty =
          mem_.mmap_alloc(1, UC_PROT_READ | UC_PROT_WRITE, "lconv.empty");
      const char z = 0;
      e.write(empty, &z, 1);
      lc = mem_.mmap_alloc(0x80, UC_PROT_READ | UC_PROT_WRITE, "lconv");
      std::vector<uint8_t> buf(0x80,
                               0x7f);  // char fields = CHAR_MAX (unspecified)
      auto setp = [&](int off, uint64_t p) {
        for (int i = 0; i < 8; ++i) buf[off + i] = (p >> (8 * i)) & 0xff;
      };
      setp(0, dot);  // decimal_point = "."
      for (int off = 8; off <= 72; off += 8)
        setp(off, empty);  // the other 8 char* -> ""
      e.write(lc, buf.data(), buf.size());
    }
    e.write_reg(Reg::Ret0, lc);
  });
  // mmap as a libc IMPORT (distinct from the SVC syscall): packers mmap RWX
  // buffers to decrypt+materialize native code into. Returning 0 (the fallback)
  // fails that silently.
  auto do_mmap = [&sys, this](Engine& e) {
    const uint64_t reqaddr = e.read_reg(Reg::A0);
    const uint64_t len = e.read_reg(Reg::A1), prot = e.read_reg(Reg::A2);
    const uint64_t flags = e.read_reg(Reg::A3), off = e.read_reg(Reg::A5);
    const int64_t fd = static_cast<int64_t>(e.read_reg(Reg::A4));
    uint32_t p = static_cast<uint32_t>(prot) ? static_cast<uint32_t>(prot) : 7;
    if (std::getenv("VARDOGER_MMAP_LOG"))
      std::fprintf(
          stderr,
          "[mmap-libc ENTRY] addr=%#llx len=%#llx flags=%#llx fd=%lld\n",
          (unsigned long long)reqaddr, (unsigned long long)len,
          (unsigned long long)flags, (long long)fd);
    // MAP_FIXED at a requested address (Ijiami libexec self-decompresses over
    // its own base): honour it in place -- map unmapped gaps, reprotect mapped
    // pages, never bump-allocate/throw.
    if (!std::getenv("VARDOGER_NO_MAPFIXED") && (flags & 0x10) && reqaddr) {
      static const bool wx0 = std::getenv("VARDOGER_WX") != nullptr;
      uint32_t pf = p;
      if (wx0 && (pf & UC_PROT_WRITE) && (pf & UC_PROT_EXEC))
        pf &= ~UC_PROT_EXEC;
      const uint64_t lo = reqaddr & ~uint64_t(0xfff),
                     hi =
                         (reqaddr + (len ? len : 1) + 0xfff) & ~uint64_t(0xfff);
      for (uint64_t q = lo; q < hi; q += 0x1000) {
        if (mem_.is_mapped(q)) {
          try {
            mem_.protect(q, 0x1000, pf);
          } catch (...) {
          }
        } else {
          try {
            mem_.map_fixed(q, 0x1000, pf, Memory::Kind::Mmap, "mmap-fixed");
          } catch (...) {
          }
        }
      }
      if (!(flags & 0x20) && fd >= 0 && sys.is_open(static_cast<int>(fd))) {
        sys.vseek(static_cast<int>(fd), off);
        std::string c;
        sys.vread(static_cast<int>(fd), c, len);
        if (!c.empty()) e.write(reqaddr, c.data(), c.size());
      }
      e.write_reg(Reg::Ret0, reqaddr);
      return;
    }
    // W^X mode (VARDOGER_WX): map writable buffers NON-exec so a self-decrypting
    // worker's writes don't trigger Unicorn's per-write TB invalidation (the
    // SMC slowdown). A fetch-fault hook re-adds exec
    // + captures when execution first enters the decrypted page. See
    //
    static const bool wx = std::getenv("VARDOGER_WX") != nullptr;
    if (wx && (p & UC_PROT_WRITE) && (p & UC_PROT_EXEC)) p &= ~UC_PROT_EXEC;
    uint64_t addr;
    try {
      addr = mem_.mmap_alloc(len, p, "mmap (libc)");
    } catch (...) {
      e.write_reg(Reg::Ret0, (uint64_t)-1);
      return;
    }  // catch bogus mmap -> MAP_FAILED
    if (std::getenv("VARDOGER_MMAP_LOG"))
      std::fprintf(stderr,
                   "[mmap-libc] len=%#llx prot=%#llx fd=%lld -> %#llx\n",
                   (unsigned long long)len, (unsigned long long)prot,
                   (long long)fd, (unsigned long long)addr);
    if (!(flags & 0x20) && fd >= 0 &&
        sys.is_open(static_cast<int>(fd))) {  // file-backed
      sys.vseek(static_cast<int>(fd), off);
      std::string content;
      sys.vread(static_cast<int>(fd), content, len);
      if (!content.empty()) e.write(addr, content.data(), content.size());
    }
    e.write_reg(Reg::Ret0, addr);
  };
  add("mmap", do_mmap);
  add("mmap64", do_mmap);
  add("munmap", [](Engine& e) { e.write_reg(Reg::Ret0, 0); });

  auto do_open = [&sys](Engine& e, Reg path_reg, Reg flags_reg) {
    const std::string path = e.read_cstr(e.read_reg(path_reg));
    const int fd = sys.vopen(path, static_cast<int>(e.read_reg(flags_reg)));
    if (std::getenv("VARDOGER_OPEN_LOG"))
      std::fprintf(stderr, "[open] \"%s\" -> %s\n", path.c_str(),
                   fd ? "ok" : "ENOENT");
    e.write_reg(Reg::Ret0,
                fd ? static_cast<uint64_t>(fd) : static_cast<uint64_t>(-1));
  };
  add("open", [do_open](Engine& e) {
    do_open(e, Reg::A0, Reg::A1);
  });  // (path, flags, ...)
  add("openat", [do_open](Engine& e) {
    do_open(e, Reg::A1, Reg::A2);
  });  // (dirfd, path, flags, ...)
  // Bionic _FORTIFY_SOURCE variants: __open_2(path, flags) / __openat_2(dirfd,
  // path, flags). Packers compiled with fortified libc call these instead of
  // open/openat; leaving them unimplemented (->0) makes the open fail and the
  // packer bail (e.g. can't read its own base.apk).
  add("__open_2", [do_open](Engine& e) { do_open(e, Reg::A0, Reg::A1); });
  add("__openat_2", [do_open](Engine& e) { do_open(e, Reg::A1, Reg::A2); });
  add("read", [&sys](Engine& e) {
    const int fd = static_cast<int>(e.read_reg(Reg::A0));
    const uint64_t buf = e.read_reg(Reg::A1), n = e.read_reg(Reg::A2);
    if (!sys.is_open(fd)) {
      e.write_reg(Reg::Ret0, static_cast<uint64_t>(-1));
      return;
    }
    std::string out;
    const size_t got =
        sys.vread(fd, out, n > 0x1000000 ? 0x1000000 : n);  // cap bogus len
    if (got) e.write(buf, out.data(), got);
    e.write_reg(Reg::Ret0, got);
  });
  add("close", [&sys](Engine& e) {
    sys.vclose(static_cast<int>(e.read_reg(Reg::A0)));
    e.write_reg(Reg::Ret0, 0);
  });
  add("lseek", [&sys](Engine& e) {  // (fd, off, whence)
    const int fd = static_cast<int>(e.read_reg(Reg::A0));
    if (!sys.is_open(fd)) {
      e.write_reg(Reg::Ret0, static_cast<uint64_t>(-1));
      return;
    }
    const int64_t off = static_cast<int64_t>(e.read_reg(Reg::A1));
    const int whence = static_cast<int>(e.read_reg(Reg::A2));
    const size_t cur = sys.vtell(fd), sz = sys.vsize(fd);
    const size_t pos = whence == 1   ? cur + off
                       : whence == 2 ? sz + off
                                     : static_cast<size_t>(off);
    sys.vseek(fd, pos);
    e.write_reg(Reg::Ret0, pos);
  });
  auto do_fstat = [&sys](Engine& e, int fd, uint64_t st) {  // arm64 struct stat
    if (!sys.is_open(fd)) {
      e.write_reg(Reg::Ret0, static_cast<uint64_t>(-1));
      return;
    }
    std::vector<uint8_t> zero(128, 0);
    e.write(st, zero.data(), zero.size());
    e.write_t<uint32_t>(st + 16, 0x81A4);         // S_IFREG|0644
    e.write_t<uint64_t>(st + 48, sys.vsize(fd));  // st_size
    e.write_reg(Reg::Ret0, 0);
  };
  add("fstat", [do_fstat](Engine& e) {
    do_fstat(e, static_cast<int>(e.read_reg(Reg::A0)), e.read_reg(Reg::A1));
  });
  add("lseek64", [&sys](Engine& e) {  // (fd, off64, whence) -> off64
    if (std::getenv("VARDOGER_LSEEK0")) {
      e.write_reg(Reg::Ret0, 0);
      return;
    }  // diagnostic: old buggy path
    const int fd = static_cast<int>(e.read_reg(Reg::A0));
    if (!sys.is_open(fd)) {
      e.write_reg(Reg::Ret0, static_cast<uint64_t>(-1));
      return;
    }
    const int64_t off = static_cast<int64_t>(e.read_reg(Reg::A1));
    const int whence = static_cast<int>(e.read_reg(Reg::A2));
    const size_t cur = sys.vtell(fd), sz = sys.vsize(fd);
    const size_t pos = whence == 1   ? cur + off
                       : whence == 2 ? sz + off
                                     : static_cast<size_t>(off);
    sys.vseek(fd, pos);
    if (std::getenv("VARDOGER_LSEEK_LOG"))
      std::fprintf(stderr,
                   "[lseek64] fd=%d off=%lld whence=%d -> %zu (size=%zu)\n", fd,
                   (long long)off, whence, pos, sz);
    e.write_reg(Reg::Ret0, pos);
  });
  add("puts", [](Engine& e) { e.write_reg(Reg::Ret0, 1); });  // success
  add("raise", [](Engine& e) {
    e.write_reg(Reg::Ret0, 0);
  });  // no-op (anti-debug raise)
  add("__read_chk",
      [&sys](Engine& e) {  // (fd, buf, count, buflen) -> like read
        const int fd = static_cast<int>(e.read_reg(Reg::A0));
        const uint64_t buf = e.read_reg(Reg::A1), n = e.read_reg(Reg::A2);
        if (!sys.is_open(fd)) {
          e.write_reg(Reg::Ret0, static_cast<uint64_t>(-1));
          return;
        }
        std::string out;
        const size_t got = sys.vread(fd, out, n);
        if (got) e.write(buf, out.data(), got);
        e.write_reg(Reg::Ret0, got);
      });
  // NDK AAsset API, backed by the VFS: packers (ijiami) read their encrypted
  // payload from assets via these. An AAsset* handle IS the VFS fd;
  // AAssetManager* is a constant token.
  add("AAssetManager_fromJava", [](Engine& e) {
    e.write_reg(Reg::Ret0, 0xA55E7000ull);
  });                                            // non-null mgr token
  add("AAssetManager_open", [&sys](Engine& e) {  // (mgr, name, mode) -> AAsset*
    const std::string name = e.read_cstr(e.read_reg(Reg::A1));
    int fd = sys.vopen("assets/" + name);
    if (!fd) fd = sys.vopen("/android_asset/" + name);
    if (!fd) fd = sys.vopen(name);
    // Diagnostic: treat a missing asset as an existing EMPTY one (some packers
    // gate purely on existence of runtime-generated marker assets). Materialise
    // an empty file + reopen.
    if (!fd && std::getenv("VARDOGER_AASSET_FAKEMISS")) {
      sys.add_file("assets/" + name, std::string());
      fd = sys.vopen("assets/" + name);
    }
    std::fprintf(stderr, "[AAsset] open \"%s\" -> %s (lr=%#llx)\n",
                 name.c_str(), fd ? "ok" : "MISS",
                 (unsigned long long)e.read_reg(Reg::Lr));
    e.write_reg(Reg::Ret0, fd ? static_cast<uint64_t>(fd) : 0);
  });
  add("AAsset_read", [&sys](Engine& e) {  // (asset, buf, count) -> bytes
    const int fd = static_cast<int>(e.read_reg(Reg::A0));
    const uint64_t buf = e.read_reg(Reg::A1), n = e.read_reg(Reg::A2);
    if (!sys.is_open(fd)) {
      e.write_reg(Reg::Ret0, static_cast<uint64_t>(-1));
      return;
    }
    std::string out;
    const size_t got = sys.vread(fd, out, n);
    if (got) e.write(buf, out.data(), got);
    if (const char* w = std::getenv("VARDOGER_MEMCPY_WATCH")) {
      uint64_t t = std::strtoull(w, nullptr, 0);
      if (buf <= t && t < buf + got)
        std::fprintf(stderr, "[AAsset_read] buf=%#llx got=%#llx val@t=%#llx\n",
                     (unsigned long long)buf, (unsigned long long)got,
                     (unsigned long long)e.read_t<uint64_t>(t));
    }
    e.write_reg(Reg::Ret0, got);
  });
  add("AAsset_getLength", [&sys](Engine& e) {
    const int fd = static_cast<int>(e.read_reg(Reg::A0));
    e.write_reg(Reg::Ret0, sys.is_open(fd) ? sys.vsize(fd) : 0);
  });
  add("AAsset_getLength64", [&sys](Engine& e) {
    const int fd = static_cast<int>(e.read_reg(Reg::A0));
    e.write_reg(Reg::Ret0, sys.is_open(fd) ? sys.vsize(fd) : 0);
  });
  add("AAsset_seek", [&sys](Engine& e) {  // (asset, off, whence) -> pos
    const int fd = static_cast<int>(e.read_reg(Reg::A0));
    if (!sys.is_open(fd)) {
      e.write_reg(Reg::Ret0, static_cast<uint64_t>(-1));
      return;
    }
    const int64_t off = static_cast<int64_t>(e.read_reg(Reg::A1));
    const int wh = static_cast<int>(e.read_reg(Reg::A2));
    const size_t cur = sys.vtell(fd), sz = sys.vsize(fd);
    const size_t pos = wh == 1   ? cur + off
                       : wh == 2 ? sz + off
                                 : static_cast<size_t>(off);
    sys.vseek(fd, pos);
    e.write_reg(Reg::Ret0, pos);
  });
  add("AAsset_close", [&sys](Engine& e) {
    sys.vclose(static_cast<int>(e.read_reg(Reg::A0)));
    e.write_reg(Reg::Ret0, 0);
  });
  add("__system_property_read", [](Engine& e) { e.write_reg(Reg::Ret0, 0); });
}

}  // namespace vardoger
