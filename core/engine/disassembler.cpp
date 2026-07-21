#include "vardoger/engine/disassembler.hpp"

#include <cstdio>
#include <stdexcept>

namespace vardoger {

Disassembler::Disassembler(Abi abi) : abi_(abi) {
  if (abi_ == Abi::Arm64) {
    if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &a64_) != CS_ERR_OK)
      throw std::runtime_error("cs_open(arm64) failed");
  } else {
    if (cs_open(CS_ARCH_ARM, CS_MODE_ARM, &arm_) != CS_ERR_OK)
      throw std::runtime_error("cs_open(arm) failed");
    if (cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &thumb_) != CS_ERR_OK)
      throw std::runtime_error("cs_open(thumb) failed");
  }
}

Disassembler::~Disassembler() {
  if (a64_) cs_close(&a64_);
  if (arm_) cs_close(&arm_);
  if (thumb_) cs_close(&thumb_);
}

csh Disassembler::pick(bool thumb) const {
  if (abi_ == Abi::Arm64) return a64_;
  return thumb ? thumb_ : arm_;
}

DecodedInsn Disassembler::one(const uint8_t* code, size_t n, uint64_t address,
                              bool thumb) const {
  DecodedInsn out;
  out.address = address;

  cs_insn* insn = nullptr;
  size_t count = cs_disasm(pick(thumb), code, n, address, /*count=*/1, &insn);
  if (count >= 1) {
    out.size = insn[0].size;
    out.mnemonic = insn[0].mnemonic;
    out.op_str = insn[0].op_str;
    out.valid = true;
  }
  if (insn) cs_free(insn, count);
  return out;
}

std::string Disassembler::format(const DecodedInsn& insn) const {
  char buf[192];
  if (!insn.valid) {
    std::snprintf(buf, sizeof(buf), "0x%08llx  (undecodable)",
                  static_cast<unsigned long long>(insn.address));
    return buf;
  }
  std::snprintf(buf, sizeof(buf), "0x%08llx  %-8s %s",
                static_cast<unsigned long long>(insn.address),
                insn.mnemonic.c_str(), insn.op_str.c_str());
  return buf;
}

}  // namespace vardoger
