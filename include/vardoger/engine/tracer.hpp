// vardoger: instruction tracer.
//
// A toggleable UC_HOOK_CODE that disassembles each executed instruction in a
// gated address range and prints it. Keep it OFF for bulk runs; per-instruction
// hooks are slow. and §4.
#pragma once

#include <cstdint>

#include "vardoger/engine/disassembler.hpp"
#include "vardoger/engine/engine.hpp"

namespace vardoger {

class Tracer {
 public:
  // Trace instructions whose PC is in [lo, hi).
  Tracer(Engine& engine, uint64_t lo, uint64_t hi);

  void attach();  // install the UC_HOOK_CODE callback
  void set_enabled(bool on) { enabled_ = on; }
  bool enabled() const { return enabled_; }

 private:
  Engine& engine_;
  Disassembler dis_;
  uint64_t lo_;
  uint64_t hi_;
  bool enabled_ = true;
};

}  // namespace vardoger
