// vardoger: sequential argument reader (AAPCS64 / AAPCS32).
//
// JNI/stub handlers read their arguments in order through this helper, which
// abstracts "registers first, then the stack" across both ABIs. The first JNI
// argument is always JNIEnv*/JavaVM*, so handlers typically call next_int()
// once to skip it, then read the declared args.
//
// NOTE: integer/pointer args only for now. Float/double args (arm32 softfp
// pairs, arm64 V-registers) are not handled yet, none of the P0 JNI functions
// need them.
#pragma once

#include <cstdint>

#include "vardoger/engine/engine.hpp"

namespace vardoger {

class Args {
 public:
  explicit Args(Engine& e) : e_(e) {}

  uint64_t next_int() {
    const int nreg = (e_.abi() == Abi::Arm64) ? 8 : 4;
    if (reg_idx_ < nreg)
      return e_.read_reg(
          static_cast<Reg>(static_cast<int>(Reg::A0) + reg_idx_++));
    // Overflow args sit at the top of the caller's stack (SP+0, +psz, ...);
    // the trampoline stub doesn't perturb SP before the SVC traps.
    const int psz = e_.pointer_size();
    const uint64_t at = e_.read_reg(Reg::Sp) + stack_off_;
    stack_off_ += psz;
    return (psz == 8) ? e_.read_t<uint64_t>(at) : e_.read_t<uint32_t>(at);
  }

 private:
  Engine& e_;
  int reg_idx_ = 0;
  uint64_t stack_off_ = 0;
};

}  // namespace vardoger
