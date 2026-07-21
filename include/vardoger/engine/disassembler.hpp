// vardoger: Capstone disassembler wrapper.
//
// Decodes single instructions for the active ABI (arm64, or arm32 ARM/Thumb).
// Used by the Tracer and, later, by the Dex2C lifter. See
// §7.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

// Homebrew's capstone.pc points -I at .../include/capstone, so the conventional
// <capstone/capstone.h> doesn't resolve there; fall back to <capstone.h>.
#if __has_include(<capstone/capstone.h>)
#include <capstone/capstone.h>
#else
#include <capstone.h>
#endif

#include "vardoger/engine/abi.hpp"

// NOTE: Capstone 5 spells the arch CS_ARCH_ARM64. Capstone 6 renamed it to
// CS_ARCH_AARCH64, if you upgrade, switch the constant in disassembler.cpp.

namespace vardoger {

struct DecodedInsn {
  uint64_t address = 0;
  uint32_t size = 0;
  std::string mnemonic;
  std::string op_str;
  bool valid = false;
};

class Disassembler {
 public:
  explicit Disassembler(Abi abi);
  ~Disassembler();
  Disassembler(const Disassembler&) = delete;
  Disassembler& operator=(const Disassembler&) = delete;

  // Decode one instruction located (virtually) at `address` from `code` (len
  // n). `thumb` is ignored on arm64.
  DecodedInsn one(const uint8_t* code, size_t n, uint64_t address,
                  bool thumb = false) const;

  // "0x........  mnemonic  operands"
  std::string format(const DecodedInsn& insn) const;

 private:
  csh pick(bool thumb) const;

  Abi abi_;
  csh a64_ = 0;    // arm64
  csh arm_ = 0;    // arm32, ARM mode
  csh thumb_ = 0;  // arm32, Thumb mode
};

}  // namespace vardoger
