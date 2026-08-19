#include "vardoger/engine/trampoline.hpp"

#include <cstdio>
#include <stdexcept>

#include "vardoger/engine/address_space.hpp"

namespace vardoger {

namespace {
constexpr uint64_t kStubSize = 8;  // SVC (+RET/BX LR), 4 bytes each

// arm64: svc #0 ; ret
constexpr uint32_t kA64_SVC0 = 0xD4000001;
constexpr uint32_t kA64_RET = 0xD65F03C0;
// arm32 (ARM mode): svc #0 ; bx lr
constexpr uint32_t kA32_SVC0 = 0xEF000000;
constexpr uint32_t kA32_BXLR = 0xE12FFF1E;
// x86 / x86_64: int 0x80 ; ret  (3 bytes, padded to the stub slot).
// `int 0x80` is used for BOTH, rather than the x86_64 `syscall` instruction,
// because it traps through UC_HOOK_INTR just like ARM's SVC — so trampoline
// dispatch stays one code path. Real guest `syscall` instructions are a
// separate concern and are hooked in Engine (UC_HOOK_INSN).
constexpr uint8_t kX86_STUB[3] = {0xCD, 0x80, 0xC3};
}  // namespace

Trampoline::Trampoline(Engine& engine, Memory& mem)
    : engine_(engine), base_(kTrampolineBase), next_(kTrampolineBase) {
  // R+X is enough, uc_mem_write (used by alloc) bypasses guest protections.
  mem.map_fixed(kTrampolineBase, kTrampolineSize, UC_PROT_READ | UC_PROT_EXEC,
                Memory::Kind::Trampoline, "trampoline");
}

uint64_t Trampoline::alloc(std::string name, Handler h) {
  if (next_ + kStubSize > base_ + kTrampolineSize)
    throw std::runtime_error("trampoline page exhausted");
  const uint64_t addr = next_;
  next_ += kStubSize;

  if (engine_.abi() == Abi::Arm64) {
    engine_.write_t<uint32_t>(addr, kA64_SVC0);
    engine_.write_t<uint32_t>(addr + 4, kA64_RET);
  } else if (engine_.abi() == Abi::Arm32) {
    engine_.write_t<uint32_t>(addr, kA32_SVC0);
    engine_.write_t<uint32_t>(addr + 4, kA32_BXLR);
  } else {
    engine_.write(addr, kX86_STUB, sizeof(kX86_STUB));
  }
  handlers_.push_back({std::move(name), std::move(h)});
  return addr;
}

bool Trampoline::contains(uint64_t addr) const {
  return addr >= base_ && addr < base_ + kTrampolineSize;
}

bool Trampoline::dispatch(Engine& e) {
  const uint64_t pc = e.read_reg(Reg::Pc);
  if (!contains(pc)) return false;
  // The PC may sit anywhere inside the stub slot: at the trap instruction, or
  // already advanced past it (ARM: +4 at the RET; x86: +2 after `int 0x80`).
  // Rounding down to the slot is arch-independent.
  const uint64_t off = pc - base_;
  const uint64_t idx = off / kStubSize;
  if (idx >= handlers_.size())
    throw std::runtime_error("trampoline dispatch: PC not on a known stub");
  static const bool trace = std::getenv("VARDOGER_CALL_LOG") != nullptr;
  if (trace) {
    const std::string& nm = handlers_[idx].name;
    handlers_[idx].handler(e);
    std::fprintf(stderr, "[call] %-28s -> %#llx\n", nm.c_str(),
                 (unsigned long long)e.read_reg(Reg::Ret0));
    return true;
  }
  handlers_[idx].handler(e);
  return true;
}

}  // namespace vardoger
