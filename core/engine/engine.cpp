#include "vardoger/engine/engine.hpp"

#include <cstring>
#include <stdexcept>
#include <vector>

namespace vardoger {

namespace {
void check(uc_err err, const char* what) {
  if (err != UC_ERR_OK)
    throw std::runtime_error(std::string(what) + ": " + uc_strerror(err));
}
}  // namespace

Engine::Engine(Abi abi) : abi_(abi) {
  const uc_arch arch = (abi_ == Abi::Arm64) ? UC_ARCH_ARM64 : UC_ARCH_ARM;
  // Thumb vs ARM on arm32 is selected per-run from CPSR.T (see run()).
  check(uc_open(arch, UC_MODE_ARM, &uc_), "uc_open");
  // Select a CPU model that implements FEAT_LSE (large-system atomics:
  // ldadd/swp/cas/..). The default arm64 model lacks it, so LSE atomics -
  // emitted by modern clang for std::atomic/shared_ptr refcounts when the
  // target advertises HWCAP_ATOMICS, fault and get misrouted (PC never
  // advances -> infinite spin). UC_CPU_ARM64_MAX enables all features.
  if (abi_ == Abi::Arm64)
    uc_ctl_set_cpu_model(
        uc_, UC_CPU_ARM64_MAX);  // best-effort; ignore if unsupported
}

Engine::~Engine() {
  if (uc_) uc_close(uc_);
}

// ---------------------------------------------------------------- registers --

int Engine::reg_id(Reg r) const {
  if (abi_ == Abi::Arm64) {
    switch (r) {
      case Reg::A0:
      case Reg::Ret0:
        return UC_ARM64_REG_X0;
      case Reg::A1:
      case Reg::Ret1:
        return UC_ARM64_REG_X1;
      case Reg::A2:
        return UC_ARM64_REG_X2;
      case Reg::A3:
        return UC_ARM64_REG_X3;
      case Reg::A4:
        return UC_ARM64_REG_X4;
      case Reg::A5:
        return UC_ARM64_REG_X5;
      case Reg::A6:
        return UC_ARM64_REG_X6;
      case Reg::A7:
        return UC_ARM64_REG_X7;
      case Reg::Sp:
        return UC_ARM64_REG_SP;
      case Reg::Lr:
        return UC_ARM64_REG_X30;  // == UC_ARM64_REG_LR
      case Reg::Pc:
        return UC_ARM64_REG_PC;
      case Reg::SyscallNr:
        return UC_ARM64_REG_X8;
    }
  } else {
    switch (r) {
      case Reg::A0:
      case Reg::Ret0:
        return UC_ARM_REG_R0;
      case Reg::A1:
      case Reg::Ret1:
        return UC_ARM_REG_R1;
      case Reg::A2:
        return UC_ARM_REG_R2;
      case Reg::A3:
        return UC_ARM_REG_R3;
      case Reg::Sp:
        return UC_ARM_REG_SP;
      case Reg::Lr:
        return UC_ARM_REG_LR;
      case Reg::Pc:
        return UC_ARM_REG_PC;
      case Reg::SyscallNr:
        return UC_ARM_REG_R7;
      case Reg::A4:
      case Reg::A5:
      case Reg::A6:
      case Reg::A7:
        throw std::runtime_error(
            "arm32: argument slots A4..A7 live on the stack, not in registers; "
            "use the ABI/Args helper rather than read_reg/write_reg");
    }
  }
  throw std::runtime_error("reg_id: unmapped register role");
}

uint64_t Engine::read_uc_reg(int id) const {
  uint64_t v = 0;  // zero-init so a 32-bit read leaves the high half clean
  check(uc_reg_read(uc_, id, &v), "uc_reg_read");
  return v;
}

void Engine::write_uc_reg(int id, uint64_t v) {
  check(uc_reg_write(uc_, id, &v), "uc_reg_write");
}

uint64_t Engine::read_reg(Reg r) const { return read_uc_reg(reg_id(r)); }
void Engine::write_reg(Reg r, uint64_t v) { write_uc_reg(reg_id(r), v); }

// ------------------------------------------------------------------- memory --

void Engine::map(uint64_t addr, size_t size, uint32_t perms) {
  check(uc_mem_map(uc_, addr, size, perms), "uc_mem_map");
}
void Engine::unmap(uint64_t addr, size_t size) {
  check(uc_mem_unmap(uc_, addr, size), "uc_mem_unmap");
}
void Engine::protect(uint64_t addr, size_t size, uint32_t perms) {
  check(uc_mem_protect(uc_, addr, size, perms), "uc_mem_protect");
}
void Engine::read(uint64_t addr, void* dst, size_t n) const {
  check(uc_mem_read(uc_, addr, dst, n), "uc_mem_read");
}
void Engine::write(uint64_t addr, const void* src, size_t n) {
  static const char* ew =
      std::getenv("VARDOGER_EWRITE_WATCH");  // cached (this runs on every write)
  if (ew) {
    const uint64_t t = std::strtoull(ew, nullptr, 0);
    if (addr < t + 8 && t < addr + n) {  // overlaps the 8-byte field at t
      uint64_t pc = 0;
      uc_reg_read(uc_, UC_ARM64_REG_PC, &pc);
      uint64_t v = 0;
      std::memcpy(&v, static_cast<const uint8_t*>(src) + (t - addr),
                  sizeof(v) <= n - (t - addr) ? sizeof(v) : n - (t - addr));
      std::fprintf(stderr,
                   "[e.write] addr=%#llx n=%#llx val@t=%#llx pc=%#llx\n",
                   (unsigned long long)addr, (unsigned long long)n,
                   (unsigned long long)v, (unsigned long long)pc);
    }
  }
  uc_err werr = uc_mem_write(uc_, addr, src, n);
  if (werr != UC_ERR_OK) {
    static const bool automap = std::getenv("VARDOGER_AUTOMAP") != nullptr;
    if (automap &&
        (werr == UC_ERR_WRITE_UNMAPPED || werr == UC_ERR_WRITE_PROT)) {
      const uint64_t base = addr & ~uint64_t(0xfff);
      const uint64_t end = (addr + n + 0xfff) & ~uint64_t(0xfff);
      uc_mem_map(uc_, base, static_cast<size_t>(end - base), UC_PROT_ALL);
      werr = uc_mem_write(uc_, addr, src, n);
      if (werr == UC_ERR_OK) return;
    }
  }
  if (werr != UC_ERR_OK) {
    uint64_t pc = 0;
    uc_reg_read(uc_, UC_ARM64_REG_PC, &pc);
    // VARDOGER_WRITEFAULT_SRC: on a failed host write, peek the SOURCE bytes, a
    // large write to a bad dest is often a decrypt/memcpy of plaintext (e.g. a
    // recovered DEX) into a null-derived buffer.
    if (std::getenv("VARDOGER_WRITEFAULT_SRC") && n >= 16) {
      const uint8_t* s = static_cast<const uint8_t*>(src);
      std::fprintf(stderr,
                   "[writefault-src] n=%#llx first16=", (unsigned long long)n);
      for (int i = 0; i < 16; ++i) std::fprintf(stderr, "%02x ", s[i]);
      std::fprintf(stderr, " ascii=%.8s\n", reinterpret_cast<const char*>(s));
    }
    char buf[160];
    std::snprintf(buf, sizeof(buf), "uc_mem_write addr=%#llx n=%#llx pc=%#llx",
                  (unsigned long long)addr, (unsigned long long)n,
                  (unsigned long long)pc);
    check(werr, buf);
  }
}

std::string Engine::read_cstr(uint64_t addr, size_t max) const {
  std::string s;
  for (size_t i = 0; i < max; ++i) {
    uint8_t c = 0;
    if (uc_mem_read(uc_, addr + i, &c, 1) != UC_ERR_OK) break;  // hit unmapped
    if (c == 0) break;
    s.push_back(static_cast<char>(c));
  }
  return s;
}

// ---------------------------------------------------------------- execution --

void Engine::run(uint64_t start, uint64_t until, uint64_t timeout_us,
                 size_t count) {
  if (abi_ == Abi::Arm32) {
    // Interworking: the low bit of an entry address selects Thumb vs ARM.
    // Reflect it in CPSR.T and start at the even address.
    constexpr uint64_t kThumbBit = 1u << 5;
    uint64_t cpsr = read_uc_reg(UC_ARM_REG_CPSR);
    if (start & 1)
      cpsr |= kThumbBit;
    else
      cpsr &= ~kThumbBit;
    write_uc_reg(UC_ARM_REG_CPSR, cpsr);
    start &= ~uint64_t(1);
    until &= ~uint64_t(1);
  }
  // Restore in_emu_ on every exit path, a stub handler may throw a C++
  // exception that unwinds through uc_emu_start, which must not leave the
  // re-entrancy flag stuck (else later top-level calls wrongly look nested).
  struct Restore {
    bool& f;
    bool prev;
    ~Restore() { f = prev; }
  } restore{in_emu_, in_emu_};
  in_emu_ = true;
  for (int wx_iters = 0;; ++wx_iters) {
    const uc_err err = uc_emu_start(uc_, start, until, timeout_us, count);
    // W^X exec-on-fetch: on "execute a non-exec page", flip that page
    // executable OUTSIDE emulation and resume from the faulting PC
    // (stop-fix-restart, the in-hook protect+retry crashes Unicorn).
    if (err == UC_ERR_FETCH_PROT && wx_ && wx_iters < 2000000) {
      const uint64_t pc =
          read_reg(Reg::Pc) &
          ~uint64_t(1);  // ABI-aware PC (arm32 uses UC_ARM_REG_PC;
      const uint64_t page =
          pc & ~uint64_t(0xFFF);  // hardcoded UC_ARM64_REG_PC spun on arm32)
      uc_mem_protect(uc_, page, 0x1000,
                     UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC);
      if (wx_page_cb_) wx_page_cb_(page);
      start = pc;  // resume at the fault
      continue;
    }
    check(err, "uc_emu_start");
    break;
  }
}

void Engine::stop() { check(uc_emu_stop(uc_), "uc_emu_stop"); }

void Engine::set_args(std::initializer_list<uint64_t> args) {
  const int nreg = (abi_ == Abi::Arm64) ? 8 : 4;
  int i = 0;
  std::vector<uint64_t> overflow;
  for (uint64_t a : args) {
    if (i < nreg)
      write_reg(static_cast<Reg>(static_cast<int>(Reg::A0) + i), a);
    else
      overflow.push_back(a);
    ++i;
  }
  if (!overflow.empty()) {
    const int psz = pointer_size();
    size_t bytes = overflow.size() * static_cast<size_t>(psz);
    if (abi_ == Abi::Arm64)
      bytes = (bytes + 15) & ~size_t(15);  // 16-byte align
    uint64_t sp = read_reg(Reg::Sp) - bytes;
    uint64_t cur = sp;
    for (uint64_t a : overflow) {
      if (psz == 8)
        write_t<uint64_t>(cur, a);
      else
        write_t<uint32_t>(cur, static_cast<uint32_t>(a));
      cur += psz;
    }
    write_reg(Reg::Sp, sp);
  }
}

uint64_t Engine::call(uint64_t fn, std::initializer_list<uint64_t> args,
                      uint64_t magic_return) {
  // Stock Unicorn cannot re-enter uc_emu_start: a nested call runs but its
  // teardown joins the shared QEMU CPU thread and corrupts the outer loop
  // ("qemu_thread_join: No such process"). Fail fast, from inside a stub
  // handler use redirect() (PC redirection, no nesting) instead.
  if (in_emu_)
    throw std::runtime_error(
        "nested Engine::call is unsupported by Unicorn; "
        "use Engine::redirect() for guest callbacks");
  set_args(args);
  write_reg(Reg::Lr, magic_return);
  run(fn, magic_return);
  return read_reg(Reg::Ret0);
}

uint64_t Engine::call(uint64_t fn, std::initializer_list<uint64_t> args,
                      uint64_t magic_return, uint64_t timeout_us) {
  if (in_emu_)
    throw std::runtime_error(
        "nested Engine::call is unsupported by Unicorn; "
        "use Engine::redirect() for guest callbacks");
  set_args(args);
  write_reg(Reg::Lr, magic_return);
  run(fn, magic_return, timeout_us);
  return read_reg(Reg::Ret0);
}

void Engine::redirect(uint64_t fn) {
  // From inside a stub handler: point PC at `fn` so the *current* emulation
  // continues into it (no nested uc_emu_start). LR is left untouched, so fn's
  // return flows to wherever the original call site expected. Args, if any, are
  // already in the argument registers from the original call. Void callbacks
  // only, the libc function's own return value (X0/R0) is whatever fn leaves.
  if (abi_ == Abi::Arm32) {
    constexpr uint64_t kThumbBit = 1u << 5;
    uint64_t cpsr = read_uc_reg(UC_ARM_REG_CPSR);
    if (fn & 1)
      cpsr |= kThumbBit;
    else
      cpsr &= ~kThumbBit;
    write_uc_reg(UC_ARM_REG_CPSR, cpsr);
    fn &= ~uint64_t(1);
  }
  write_reg(Reg::Pc, fn);
}

// --------------------------------------------------------------------- hooks
// --

void Engine::on_interrupt(IntrHandler h) {
  on_intr_ = std::move(h);
  if (!intr_hook_)
    check(uc_hook_add(uc_, &intr_hook_, UC_HOOK_INTR,
                      reinterpret_cast<void*>(&Engine::intr_thunk), this, 1, 0),
          "uc_hook_add(INTR)");
}

void Engine::on_code(CodeHandler h) {
  on_code_ = std::move(h);
  if (!code_hook_)
    check(uc_hook_add(uc_, &code_hook_, UC_HOOK_CODE,
                      reinterpret_cast<void*>(&Engine::code_thunk), this, 1, 0),
          "uc_hook_add(CODE)");
}

void Engine::on_unmapped(UnmappedHandler h) {
  on_unmapped_ = std::move(h);
  if (!unmapped_hook_)
    check(uc_hook_add(uc_, &unmapped_hook_, UC_HOOK_MEM_UNMAPPED,
                      reinterpret_cast<void*>(&Engine::unmapped_thunk), this, 1,
                      0),
          "uc_hook_add(MEM_UNMAPPED)");
}

void Engine::intr_thunk(uc_engine*, uint32_t intno, void* user) {
  auto* self = static_cast<Engine*>(user);
  if (self->on_intr_) self->on_intr_(*self, intno);
}

void Engine::code_thunk(uc_engine*, uint64_t addr, uint32_t size, void* user) {
  auto* self = static_cast<Engine*>(user);
  if (self->on_code_) self->on_code_(*self, addr, size);
}

bool Engine::unmapped_thunk(uc_engine*, uc_mem_type type, uint64_t addr,
                            int size, int64_t value, void* user) {
  auto* self = static_cast<Engine*>(user);
  if (self->on_unmapped_)
    return self->on_unmapped_(*self, type, addr, size, value);
  return false;  // don't retry the access; let it fault
}

}  // namespace vardoger
