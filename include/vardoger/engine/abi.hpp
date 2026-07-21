// vardoger: ABI abstraction.
//
// The rest of the VM speaks in register *roles* (Reg) and an Abi tag instead of
// Unicorn's per-architecture register constants, so higher layers don't
// hardcode UC_ARM64_REG_X0 vs UC_ARM_REG_R0.
#pragma once

#include <cstdint>

namespace vardoger {

enum class Abi { Arm64, Arm32 };

// ABI-independent register roles.
//
// NOTE: A4..A7 are only physical registers on arm64. On arm32 (AAPCS32) only
// the first four arguments are register-passed (R0..R3); A4+ live on the stack
// and must be handled by the future ABI/Args helper, not by Engine::read_reg.
enum class Reg {
  A0,
  A1,
  A2,
  A3,
  A4,
  A5,
  A6,
  A7,  // argument registers (A0/A1 double as returns)
  Ret0,
  Ret1,  // return-value registers (alias A0/A1)
  Sp,
  Lr,
  Pc,
  SyscallNr,  // x8 on arm64, r7 on arm32
};

constexpr int kPointerSize(Abi abi) { return abi == Abi::Arm64 ? 8 : 4; }

}  // namespace vardoger
