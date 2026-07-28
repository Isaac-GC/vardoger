// vardoger: GDB Remote Serial Protocol (RSP) server.
//
// Lets an external debugger drive the emulated CPU: lldb (the macOS-native
// debugger), gdb-multiarch, and the RSP clients built into Binary Ninja and
// IDA all speak this protocol. You attach over TCP, read/write registers and
// guest memory, set breakpoints, single-step, and continue, exactly as if the
// guest .so were a live process, while vardoger keeps providing the faithful
// Android surface underneath.
//
// Design: the stub owns one UC_HOOK_CODE. On every guest instruction it checks
// whether we should stop (a software breakpoint at PC, a pending single-step,
// or an asynchronous Ctrl-C from the client). When we stop, it serves RSP
// commands *from inside the hook* and only returns once the client resumes.
// Because the hook never lets uc_emu_start unwind, the cooperative scheduler
// above never sees the pause: the debugger sits transparently between two guest
// instructions. This also means breakpoints are tracked host-side (a set of
// addresses), so we never patch guest memory with BRK and stepping works even
// on execute-only / freshly-decrypted pages.
//
// POSIX sockets only (macOS + Linux). The listener binds 127.0.0.1, so the
// debug channel is never exposed off-host.
#pragma once

#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

#include "vardoger/engine/engine.hpp"
#include "vardoger/engine/memory.hpp"

namespace vardoger {

class GdbStub {
 public:
  GdbStub(Engine& engine, Memory& mem);
  ~GdbStub();
  GdbStub(const GdbStub&) = delete;
  GdbStub& operator=(const GdbStub&) = delete;

  // Bind 127.0.0.1:<port>, block until a debugger connects, then serve the
  // initial handshake (register/memory queries, breakpoint setup) until the
  // client issues its first continue/step. Returns true once attached and the
  // client is ready for the target to run; false if the client detached during
  // the handshake or the socket setup failed (see last error via the C ABI).
  //
  // The natural flow is: load the .so and run its init, call gdb_listen(), then
  // drive JNI_OnLoad / a target function through Engine — it now runs under the
  // debugger. Set breakpoints, then "continue", during the handshake.
  bool listen(uint16_t port);

  bool attached() const { return client_fd_ >= 0; }
  void detach();

  // Called by the driver after a top-level run (Engine::call / run_init /
  // Scheduler::run) returns, so a client that issued "continue" and then ran
  // off the end of the function gets a final stop it can inspect (X0 holds the
  // return value) and cleanly terminate the session. No-op if not attached or
  // the client never resumed.
  void end_run();

 private:
  enum class Resume { Continue, Step, Detach, Kill, Closed };

  // --- Unicorn code-hook plumbing ---
  static void code_thunk(uc_engine*, uint64_t addr, uint32_t size, void* user);
  void on_instruction(uint64_t pc);
  void install_hook();
  void remove_hook();

  // --- RSP transport ---
  bool read_packet(std::string& out);  // false on connection close
  void send_packet(const std::string& payload);
  void send_ack(bool ok);
  bool poll_interrupt();  // non-blocking: did the client send Ctrl-C (0x03)?
  void close_client();

  // --- RSP command handling ---
  // Serve packets until the client resumes/detaches; returns why we stopped
  // serving. Shared by the handshake (listen) and every in-hook stop.
  Resume serve();
  void handle_packet(const std::string& pkt, std::string& reply,
                     Resume& resume, bool& resumed);
  void send_stop_reply(int signal);

  // register table helpers (aarch64 / arm)
  std::string read_all_regs_hex();
  void write_all_regs_hex(const std::string& hex);
  std::string read_one_reg_hex(size_t regnum);
  void write_one_reg_hex(size_t regnum, const std::string& hex);
  std::string target_xml() const;
  std::string register_info(size_t regnum) const;  // lldb qRegisterInfoN

  Engine& engine_;
  Memory& mem_;

  int listen_fd_ = -1;
  int client_fd_ = -1;
  bool no_ack_ = false;      // QStartNoAckMode is in effect
  bool arm_no_ack_ = false;  // enable no-ack after the current reply is sent
  bool resumed_ = false;     // client has continued/stepped at least once

  // stop conditions consulted by the per-instruction hook
  std::unordered_set<uint64_t> breakpoints_;
  bool stepping_ = false;
  bool pending_int_ = false;
  uint64_t poll_ctr_ = 0;

  uc_hook code_hook_ = 0;
  int last_signal_ = 5;  // SIGTRAP
};

}  // namespace vardoger
