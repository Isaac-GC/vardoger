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
  } else {
    engine_.write_t<uint32_t>(addr, kA32_SVC0);
    engine_.write_t<uint32_t>(addr + 4, kA32_BXLR);
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
  // PC may be at the SVC (offset%8==0) or already advanced to the RET (==4).
  const uint64_t off = pc - base_;
  const uint64_t stub = (off % kStubSize == 0) ? pc : pc - 4;
  const uint64_t idx = (stub - base_) / kStubSize;
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
