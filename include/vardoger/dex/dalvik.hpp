// vardoger: minimal register-based Dalvik interpreter (task #12, phase 2).
//
// Runs the packer stub's lifecycle methods
// (StubApp.attachBaseContext/onCreate/a, QHClassLoader.loadClass) so the
// packer's natives fire IN ORDER and its lazy class-load decrypt triggers. NOT
// a conformant ART: a subset of ~40-60 opcodes, grown on demand (unknown
// opcodes log + abort the method). Objects/strings/primitives are opaque u64
// "slots" (object slots are JavaRuntime handles); the host wires the
// environment via callbacks so the interpreter stays decoupled from the
// JNI/native machinery.
// ART_CLASS_RESOLUTION.md.
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "vardoger/dex/dex_file.hpp"

namespace vardoger {

class Dalvik {
 public:
  // How a method is invoked, the host needs this to dispatch correctly (super
  // MUST go to the declared type's SUPERclass, not the receiver's override,
  // else attachBaseContext recurses).
  enum class InvokeKind { Virtual, Super, Direct, Static, Interface };

  // Invoke a method by its DEX method_idx with already-evaluated args (first =
  // receiver for non-static). Returns the result slot (0 for void). The host
  // decides: interpreted -> re-enter run(); packer native -> JNI/scheduler;
  // framework -> host stub.
  using InvokeFn = std::function<uint64_t(InvokeKind kind, uint32_t method_idx,
                                          const std::vector<uint64_t>& args)>;
  using StaticGet = std::function<uint64_t(uint32_t field_idx)>;
  using StaticSet = std::function<void(uint32_t field_idx, uint64_t val)>;
  using InstGet = std::function<uint64_t(uint64_t obj, uint32_t field_idx)>;
  using InstSet =
      std::function<void(uint64_t obj, uint32_t field_idx, uint64_t val)>;
  using ConstStr =
      std::function<uint64_t(uint32_t string_idx)>;            // -> string slot
  using NewInst = std::function<uint64_t(uint32_t type_idx)>;  // -> object slot
  using NewArray =
      std::function<uint64_t(uint32_t type_idx, int32_t len)>;  // -> array slot
  using ArrayLen = std::function<int32_t(uint64_t arr)>;        // array-length
  using ArrayGet = std::function<uint64_t(uint64_t arr, int32_t idx)>;
  using ArraySet = std::function<void(uint64_t arr, int32_t idx, uint64_t val)>;

  Dalvik(const DexFile& dex) : dex_(dex) {}

  InvokeFn on_invoke;
  StaticGet on_sget;
  StaticSet on_sput;
  InstGet on_iget;
  InstSet on_iput;
  ConstStr on_const_string;
  NewInst on_new_instance;
  NewArray on_new_array;
  ArrayLen on_array_length;
  ArrayGet on_aget;
  ArraySet on_aput;

  // Run a method (given its code_item + registers) with args placed in the last
  // ins_size regs. Returns the return-value slot. Depth-bounded; logs on
  // unknown opcode.
  uint64_t run(const DexFile::Code& code, const std::vector<uint64_t>& args,
               const std::string& dbg = {});

  bool trace = false;  // log each instruction
  int max_depth = 64;

 private:
  const DexFile& dex_;
  int depth_ = 0;
};

}  // namespace vardoger
