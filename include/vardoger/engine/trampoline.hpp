// vardoger: SVC trampoline page.
//
// The mechanism that lets emulated guest code call host C++. Each registered
// handler gets a tiny `SVC #0 ; RET` stub on the trampoline page; the guest's
// import slots / JNI vtable entries point at these stub addresses. When the
// guest calls one, the SVC traps into the engine's interrupt hook, which calls
// dispatch here to run the host handler.
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "vardoger/engine/engine.hpp"
#include "vardoger/engine/memory.hpp"

namespace vardoger {

class Trampoline {
 public:
  using Handler = std::function<void(Engine&)>;  // reads args, sets Ret0

  Trampoline(Engine& engine, Memory& mem);

  // Assign a stub for `h`; returns the stub's guest address (store it in a GOT
  // slot / vtable entry so the guest calls into `h`).
  uint64_t alloc(std::string name, Handler h);

  bool contains(uint64_t addr) const;

  // Call from the engine interrupt hook. If PC is on the trampoline page, run
  // the corresponding handler and return true; otherwise return false (it's a
  // real syscall for the syscall layer to handle).
  bool dispatch(Engine& e);

  size_t count() const { return handlers_.size(); }

  // Name of the stub at `addr` (for diagnostics: identify what a vtable slot
  // points at). "" if not a stub.
  std::string name_at(uint64_t addr) const {
    if (!contains(addr)) return {};
    const size_t idx = (addr - base_) / 8;  // kStubSize
    return idx < handlers_.size() ? handlers_[idx].name : std::string{};
  }

 private:
  struct Entry {
    std::string name;
    Handler handler;
  };

  Engine& engine_;
  uint64_t base_;
  uint64_t next_;
  std::vector<Entry> handlers_;  // index = (stub_addr - base_) / kStubSize
};

}  // namespace vardoger
