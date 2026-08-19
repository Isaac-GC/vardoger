// vardoger: Unicorn engine wrapper.
//
// The lowest layer of the VM. Owns the uc_engine*, sets the CPU mode for the
// active ABI, and exposes register/memory/execution/hook primitives that every
// higher layer uses. Nothing above this file should call uc_* directly.
//
#pragma once

#include <unicorn/unicorn.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <initializer_list>
#include <string>

#include "vardoger/engine/abi.hpp"

namespace vardoger {

class Engine;

// Host-side hook callbacks. Engine routes Unicorn's C callbacks to these.
using IntrHandler = std::function<void(Engine&, uint32_t intno)>;
using CodeHandler = std::function<void(Engine&, uint64_t addr, uint32_t size)>;
using UnmappedHandler = std::function<bool(
    Engine&, uc_mem_type type, uint64_t addr, int size, int64_t value)>;

// Default emulation timeout (microseconds) so a runaway guest loop can't hang
// us.
inline constexpr uint64_t kDefaultTimeoutUs = 10'000'000;  // 10 s

class Engine {
 public:
  explicit Engine(Abi abi);
  ~Engine();
  Engine(const Engine&) = delete;
  Engine& operator=(const Engine&) = delete;

  Abi abi() const { return abi_; }
  int pointer_size() const { return kPointerSize(abi_); }
  uc_engine* raw() const { return uc_; }

  // --- registers (by ABI-independent role) ---
  uint64_t read_reg(Reg r) const;
  void write_reg(Reg r, uint64_t v);
  // raw escape hatch for the few spots that need a specific UC_*_REG_* id
  uint64_t read_uc_reg(int uc_reg_id) const;
  void write_uc_reg(int uc_reg_id, uint64_t v);

  // --- memory ---
  void map(uint64_t addr, size_t size, uint32_t perms);
  void unmap(uint64_t addr, size_t size);
  void protect(uint64_t addr, size_t size, uint32_t perms);
  void read(uint64_t addr, void* dst, size_t n) const;
  void write(uint64_t addr, const void* src, size_t n);
  template <class T>
  T read_t(uint64_t addr) const {
    T v{};
    read(addr, &v, sizeof(T));
    return v;
  }
  template <class T>
  void write_t(uint64_t addr, const T& v) {
    write(addr, &v, sizeof(T));
  }
  std::string read_cstr(uint64_t addr, size_t max = 4096) const;

  // --- execution ---
  void run(uint64_t start, uint64_t until,
           uint64_t timeout_us = kDefaultTimeoutUs, size_t count = 0);
  void stop();

  // W^X exec-on-fetch (SMC/unpacker support): when set, a UC_ERR_FETCH_PROT
  // (execute a non-exec page, e.g. freshly self-decrypted code in a W-stripped
  // buffer) is handled by flipping that page executable OUTSIDE emulation and
  // resuming, the robust stop-fix-restart pattern (in-hook
  // uc_mem_protect+retry crashes Unicorn 2.x). Optional callback fires with the
  // newly-exec page.
  void set_wx(bool on) { wx_ = on; }
  void set_wx_page_cb(std::function<void(uint64_t page)> cb) {
    wx_page_cb_ = std::move(cb);
  }
  // Call a guest function: set args per ABI, LR = magic_return, run until it,
  // return Ret0. Throws if called re-entrantly
  // (from a stub handler), use redirect there instead.
  uint64_t call(uint64_t fn, std::initializer_list<uint64_t> args,
                uint64_t magic_return);
  // Same, but bound the guest run to `timeout_us` wall-clock (a runaway/looping
  // callback stops there). Used by the per-method decode drive so each direct
  // call stays fast (Unicorn JITs within the window) instead of running to the
  // 10 s default; matches the cooperative scheduler's per-slice bound.
  uint64_t call(uint64_t fn, std::initializer_list<uint64_t> args,
                uint64_t magic_return, uint64_t timeout_us);
  // From inside a stub handler: redirect the current emulation into `fn` (a
  // guest callback) without nesting. For void callbacks. See engine.cpp.
  void redirect(uint64_t fn);

  // --- hooks ---
  void on_interrupt(IntrHandler h);  // UC_HOOK_INTR (trampoline/syscall split)
  void on_code(CodeHandler h);       // UC_HOOK_CODE (tracer)
  void on_unmapped(UnmappedHandler h);  // UC_HOOK_MEM_UNMAPPED (diagnostics)
  // Fired when uc_emu_start returns a fatal error (a guest fault), BEFORE run()
  // throws — so a debugger can report the fault to its client and let the user
  // inspect (post-mortem) instead of the session dying silently. Gets the error
  // and the faulting PC. run() still throws afterward (callers handle that).
  using ErrorHandler = std::function<void(uc_err, uint64_t pc)>;
  void on_error(ErrorHandler h) { on_error_ = std::move(h); }

 private:
  int reg_id(Reg r) const;
  void set_args(std::initializer_list<uint64_t> args);
  // Place the return address per ABI (link register, or pushed on x86).
  void set_return_address(uint64_t magic_return);

  bool wx_ = false;
  std::function<void(uint64_t)> wx_page_cb_;

  static void intr_thunk(uc_engine*, uint32_t intno, void* user);
  static void code_thunk(uc_engine*, uint64_t addr, uint32_t size, void* user);
  static bool unmapped_thunk(uc_engine*, uc_mem_type, uint64_t addr, int size,
                             int64_t value, void* user);

  Abi abi_;
  uc_engine* uc_ = nullptr;
  bool in_emu_ = false;  // true while a uc_emu_start is on the stack
  IntrHandler on_intr_;
  CodeHandler on_code_;
  UnmappedHandler on_unmapped_;
  ErrorHandler on_error_;
  uc_hook intr_hook_ = 0, code_hook_ = 0, unmapped_hook_ = 0;
};

}  // namespace vardoger
