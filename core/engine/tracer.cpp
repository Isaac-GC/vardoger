#include "vardoger/engine/tracer.hpp"

#include <array>
#include <cstdio>

namespace vardoger {

Tracer::Tracer(Engine& engine, uint64_t lo, uint64_t hi)
    : engine_(engine), dis_(engine.abi()), lo_(lo), hi_(hi) {}

void Tracer::attach() {
  engine_.on_code([this](Engine& e, uint64_t addr, uint32_t size) {
    if (!enabled_ || addr < lo_ || addr >= hi_) return;

    std::array<uint8_t, 16> bytes{};
    const uint32_t n =
        size > bytes.size() ? static_cast<uint32_t>(bytes.size()) : size;
    e.read(addr, bytes.data(), n);

    bool thumb = false;
    if (e.abi() == Abi::Arm32)
      thumb = (e.read_uc_reg(UC_ARM_REG_CPSR) & (1u << 5)) != 0;

    const DecodedInsn insn = dis_.one(bytes.data(), n, addr, thumb);
    std::printf("    %s\n", dis_.format(insn).c_str());
  });
}

}  // namespace vardoger
