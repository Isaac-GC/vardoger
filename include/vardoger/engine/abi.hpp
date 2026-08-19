// vardoger: ABI abstraction.
//
// The rest of the VM speaks in register *roles* (Reg) and an Abi tag instead of
// Unicorn's per-architecture register constants, so higher layers don't
// hardcode UC_ARM64_REG_X0 vs UC_ARM_REG_R0.
#pragma once

#include <cstdint>

namespace vardoger {

enum class Abi { Arm64, Arm32, X86, X86_64 };

// ABI-independent register roles.
//
// NOTE: how many of A0..A7 are physical registers is ABI-specific.
//   arm64  (AAPCS64):  A0..A7  = x0..x7
//   arm32  (AAPCS32):  A0..A3  = r0..r3; A4+ live on the STACK
//   x86_64 (SysV):     A0..A5  = rdi,rsi,rdx,rcx,r8,r9; A6+ on the stack
//   x86    (cdecl):    ALL arguments live on the stack
// Engine::read_reg/write_reg throw for a slot that isn't a register on the
// active ABI; use the Args helper for stack-passed arguments.
//
// Reg::Lr is likewise not universal: ARM has a link register, but on x86 the
// return address is PUSHED on the stack by `call`. Engine::call() handles that
// difference so callers keep using one interface.
enum class Reg {
  A0,
  A1,
  A2,
  A3,
  A4,
  A5,
  A6,
  A7,  // argument registers (on ARM, A0/A1 double as returns)
  Ret0,
  Ret1,  // return-value registers (rax/rdx on x86; alias A0/A1 on ARM)
  Sp,
  Lr,  // ARM only — x86 keeps the return address on the stack
  Pc,
  SyscallNr,  // x8 arm64, r7 arm32, rax/eax on x86
};

constexpr bool kIs64(Abi abi) {
  return abi == Abi::Arm64 || abi == Abi::X86_64;
}
constexpr bool kIsX86(Abi abi) { return abi == Abi::X86 || abi == Abi::X86_64; }
constexpr bool kIsArm(Abi abi) {
  return abi == Abi::Arm64 || abi == Abi::Arm32;
}
// True when the ABI keeps the return address on the stack (no link register).
constexpr bool kRetAddrOnStack(Abi abi) { return kIsX86(abi); }

constexpr int kPointerSize(Abi abi) { return kIs64(abi) ? 8 : 4; }

}  // namespace vardoger
