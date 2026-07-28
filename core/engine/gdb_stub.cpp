// vardoger: GDB Remote Serial Protocol server. See gdb_stub.hpp for the design.
#include "vardoger/engine/gdb_stub.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <stdexcept>
#include <vector>

#include <unicorn/unicorn.h>

namespace vardoger {
namespace {

constexpr int kSigTrap = 5;
constexpr int kSigInt = 2;

// -------------------------------------------------------------- register table
// One table drives everything the client needs to agree with us on: the g/G
// packet order and width, p/P indexing, the target.xml feature description
// (gdb / Binary Ninja / IDA), and lldb's qRegisterInfo. `generic` maps a role
// onto the debugger's $pc / $sp aliases.
struct RegDesc {
  const char* name;
  int uc_id;
  int bits;             // 32, 64, or 128
  const char* type;     // gdb xml type (nullptr -> derive from bits)
  const char* generic;  // lldb generic role, or nullptr
  bool fpu;             // belongs to the FP/SIMD feature (aarch64.fpu)
};

// AArch64: core (x0..x30, sp, pc, cpsr — org.gnu.gdb.aarch64.core) followed by
// the FP/SIMD set (v0..v31 128-bit, fpsr, fpcr — org.gnu.gdb.aarch64.fpu). One
// table drives the g-packet order, so the core regs must stay first (their
// regnums 0..33 are what pc=32 / sp=31 references). gdb/BN/IDA learn the layout
// from target.xml; lldb from qRegisterInfo.
const RegDesc kArm64[] = {
    {"x0", UC_ARM64_REG_X0, 64, nullptr, "arg1"},
    {"x1", UC_ARM64_REG_X1, 64, nullptr, "arg2"},
    {"x2", UC_ARM64_REG_X2, 64, nullptr, "arg3"},
    {"x3", UC_ARM64_REG_X3, 64, nullptr, "arg4"},
    {"x4", UC_ARM64_REG_X4, 64, nullptr, nullptr},
    {"x5", UC_ARM64_REG_X5, 64, nullptr, nullptr},
    {"x6", UC_ARM64_REG_X6, 64, nullptr, nullptr},
    {"x7", UC_ARM64_REG_X7, 64, nullptr, nullptr},
    {"x8", UC_ARM64_REG_X8, 64, nullptr, nullptr},
    {"x9", UC_ARM64_REG_X9, 64, nullptr, nullptr},
    {"x10", UC_ARM64_REG_X10, 64, nullptr, nullptr},
    {"x11", UC_ARM64_REG_X11, 64, nullptr, nullptr},
    {"x12", UC_ARM64_REG_X12, 64, nullptr, nullptr},
    {"x13", UC_ARM64_REG_X13, 64, nullptr, nullptr},
    {"x14", UC_ARM64_REG_X14, 64, nullptr, nullptr},
    {"x15", UC_ARM64_REG_X15, 64, nullptr, nullptr},
    {"x16", UC_ARM64_REG_X16, 64, nullptr, nullptr},
    {"x17", UC_ARM64_REG_X17, 64, nullptr, nullptr},
    {"x18", UC_ARM64_REG_X18, 64, nullptr, nullptr},
    {"x19", UC_ARM64_REG_X19, 64, nullptr, nullptr},
    {"x20", UC_ARM64_REG_X20, 64, nullptr, nullptr},
    {"x21", UC_ARM64_REG_X21, 64, nullptr, nullptr},
    {"x22", UC_ARM64_REG_X22, 64, nullptr, nullptr},
    {"x23", UC_ARM64_REG_X23, 64, nullptr, nullptr},
    {"x24", UC_ARM64_REG_X24, 64, nullptr, nullptr},
    {"x25", UC_ARM64_REG_X25, 64, nullptr, nullptr},
    {"x26", UC_ARM64_REG_X26, 64, nullptr, nullptr},
    {"x27", UC_ARM64_REG_X27, 64, nullptr, nullptr},
    {"x28", UC_ARM64_REG_X28, 64, nullptr, nullptr},
    {"x29", UC_ARM64_REG_X29, 64, nullptr, "fp"},
    {"x30", UC_ARM64_REG_X30, 64, nullptr, "lr"},
    {"sp", UC_ARM64_REG_SP, 64, "data_ptr", "sp"},
    {"pc", UC_ARM64_REG_PC, 64, "code_ptr", "pc"},
    // NZCV holds the condition flags in bits 28..31; a debugger reads cpsr
    // mainly for those. (Unicorn's PSTATE is not reliably reconstructable.)
    {"cpsr", UC_ARM64_REG_NZCV, 32, nullptr, "flags"},
    // FP/SIMD: v0..v31 are 128-bit; read/written as raw bytes via uc_reg_read
    // (a uint64_t path would truncate/overflow). fpsr/fpcr are 32-bit.
    {"v0", UC_ARM64_REG_V0, 128, nullptr, nullptr, true},
    {"v1", UC_ARM64_REG_V1, 128, nullptr, nullptr, true},
    {"v2", UC_ARM64_REG_V2, 128, nullptr, nullptr, true},
    {"v3", UC_ARM64_REG_V3, 128, nullptr, nullptr, true},
    {"v4", UC_ARM64_REG_V4, 128, nullptr, nullptr, true},
    {"v5", UC_ARM64_REG_V5, 128, nullptr, nullptr, true},
    {"v6", UC_ARM64_REG_V6, 128, nullptr, nullptr, true},
    {"v7", UC_ARM64_REG_V7, 128, nullptr, nullptr, true},
    {"v8", UC_ARM64_REG_V8, 128, nullptr, nullptr, true},
    {"v9", UC_ARM64_REG_V9, 128, nullptr, nullptr, true},
    {"v10", UC_ARM64_REG_V10, 128, nullptr, nullptr, true},
    {"v11", UC_ARM64_REG_V11, 128, nullptr, nullptr, true},
    {"v12", UC_ARM64_REG_V12, 128, nullptr, nullptr, true},
    {"v13", UC_ARM64_REG_V13, 128, nullptr, nullptr, true},
    {"v14", UC_ARM64_REG_V14, 128, nullptr, nullptr, true},
    {"v15", UC_ARM64_REG_V15, 128, nullptr, nullptr, true},
    {"v16", UC_ARM64_REG_V16, 128, nullptr, nullptr, true},
    {"v17", UC_ARM64_REG_V17, 128, nullptr, nullptr, true},
    {"v18", UC_ARM64_REG_V18, 128, nullptr, nullptr, true},
    {"v19", UC_ARM64_REG_V19, 128, nullptr, nullptr, true},
    {"v20", UC_ARM64_REG_V20, 128, nullptr, nullptr, true},
    {"v21", UC_ARM64_REG_V21, 128, nullptr, nullptr, true},
    {"v22", UC_ARM64_REG_V22, 128, nullptr, nullptr, true},
    {"v23", UC_ARM64_REG_V23, 128, nullptr, nullptr, true},
    {"v24", UC_ARM64_REG_V24, 128, nullptr, nullptr, true},
    {"v25", UC_ARM64_REG_V25, 128, nullptr, nullptr, true},
    {"v26", UC_ARM64_REG_V26, 128, nullptr, nullptr, true},
    {"v27", UC_ARM64_REG_V27, 128, nullptr, nullptr, true},
    {"v28", UC_ARM64_REG_V28, 128, nullptr, nullptr, true},
    {"v29", UC_ARM64_REG_V29, 128, nullptr, nullptr, true},
    {"v30", UC_ARM64_REG_V30, 128, nullptr, nullptr, true},
    {"v31", UC_ARM64_REG_V31, 128, nullptr, nullptr, true},
    {"fpsr", UC_ARM64_REG_FPSR, 32, nullptr, nullptr, true},
    {"fpcr", UC_ARM64_REG_FPCR, 32, nullptr, nullptr, true},
};

// ARM (AArch32): r0..r12, sp, lr, pc, cpsr. Contiguous regnums under a custom
// feature name so gdb uses our layout verbatim rather than the standard arm
// core's sparse numbering. Secondary target (the runtime is arm64-first).
const RegDesc kArm32[] = {
    {"r0", UC_ARM_REG_R0, 32, nullptr, "arg1"},
    {"r1", UC_ARM_REG_R1, 32, nullptr, "arg2"},
    {"r2", UC_ARM_REG_R2, 32, nullptr, "arg3"},
    {"r3", UC_ARM_REG_R3, 32, nullptr, "arg4"},
    {"r4", UC_ARM_REG_R4, 32, nullptr, nullptr},
    {"r5", UC_ARM_REG_R5, 32, nullptr, nullptr},
    {"r6", UC_ARM_REG_R6, 32, nullptr, nullptr},
    {"r7", UC_ARM_REG_R7, 32, nullptr, nullptr},
    {"r8", UC_ARM_REG_R8, 32, nullptr, nullptr},
    {"r9", UC_ARM_REG_R9, 32, nullptr, nullptr},
    {"r10", UC_ARM_REG_R10, 32, nullptr, nullptr},
    {"r11", UC_ARM_REG_R11, 32, nullptr, "fp"},
    {"r12", UC_ARM_REG_R12, 32, nullptr, nullptr},
    {"sp", UC_ARM_REG_SP, 32, "data_ptr", "sp"},
    {"lr", UC_ARM_REG_LR, 32, nullptr, "lr"},
    {"pc", UC_ARM_REG_PC, 32, "code_ptr", "pc"},
    {"cpsr", UC_ARM_REG_CPSR, 32, nullptr, "flags"},
};

struct RegTable {
  const RegDesc* regs;
  size_t count;
  const char* arch;     // <architecture> in target.xml
  const char* feature;  // <feature name=...>
};

RegTable table_for(Abi abi) {
  if (abi == Abi::Arm64)
    return {kArm64, std::size(kArm64), "aarch64",
            "org.gnu.gdb.aarch64.core"};
  return {kArm32, std::size(kArm32), "arm", "org.vardoger.arm.core"};
}

// ---------------------------------------------------------------- hex helpers
char hex_digit(int v) { return "0123456789abcdef"[v & 0xf]; }

int unhex_digit(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return 0;
}

// A register value as little-endian hex (the wire order for g/p/G/P).
std::string reg_to_hex(uint64_t v, int bits) {
  std::string s;
  for (int i = 0; i < bits / 8; ++i) {
    uint8_t b = static_cast<uint8_t>(v >> (8 * i));
    s.push_back(hex_digit(b >> 4));
    s.push_back(hex_digit(b & 0xf));
  }
  return s;
}

std::string bytes_to_hex(const uint8_t* p, size_t n) {
  std::string s;
  s.reserve(n * 2);
  for (size_t i = 0; i < n; ++i) {
    s.push_back(hex_digit(p[i] >> 4));
    s.push_back(hex_digit(p[i] & 0xf));
  }
  return s;
}

uint64_t parse_hex_u64(const std::string& s, size_t& i) {
  uint64_t v = 0;
  while (i < s.size() && std::isxdigit((unsigned char)s[i]))
    v = (v << 4) | unhex_digit(s[i++]);
  return v;
}

// Read any register (32/64/128-bit) into `out` as little-endian bytes. The
// 128-bit V registers MUST go through a 16-byte buffer: reading one into a
// uint64_t would have Unicorn write 16 bytes into 8 and smash the stack.
void read_reg_bytes(uc_engine* uc, const RegDesc& r, uint8_t out[16]) {
  std::memset(out, 0, 16);
  if (r.bits <= 64) {
    uint64_t v = 0;
    uc_reg_read(uc, r.uc_id, &v);
    for (int i = 0; i < r.bits / 8; ++i) out[i] = static_cast<uint8_t>(v >> (8 * i));
  } else {
    uc_reg_read(uc, r.uc_id, out);  // Unicorn fills exactly 16 LE bytes
  }
}

void write_reg_bytes(uc_engine* uc, const RegDesc& r, const uint8_t* in) {
  if (r.bits <= 64) {
    uint64_t v = 0;
    for (int i = 0; i < r.bits / 8; ++i) v |= static_cast<uint64_t>(in[i]) << (8 * i);
    uc_reg_write(uc, r.uc_id, &v);
  } else {
    uc_reg_write(uc, r.uc_id, in);
  }
}

std::string reg_hex(uc_engine* uc, const RegDesc& r) {
  uint8_t buf[16];
  read_reg_bytes(uc, r, buf);
  return bytes_to_hex(buf, r.bits / 8);
}

// Parse `bits/8` bytes of little-endian hex from `hex` into `out`.
void hex_to_reg_bytes(const std::string& hex, const RegDesc& r, uint8_t out[16]) {
  std::memset(out, 0, 16);
  for (int b = 0; b < r.bits / 8 && (size_t)(2 * b + 1) < hex.size(); ++b)
    out[b] = static_cast<uint8_t>((unhex_digit(hex[2 * b]) << 4) |
                                  unhex_digit(hex[2 * b + 1]));
}

}  // namespace

GdbStub::GdbStub(Engine& engine, Memory& mem) : engine_(engine), mem_(mem) {}

GdbStub::~GdbStub() {
  remove_hook();
  close_client();
  if (listen_fd_ >= 0) ::close(listen_fd_);
}

// ------------------------------------------------------------------ lifecycle
bool GdbStub::listen(uint16_t port) {
  if (attached()) return true;

  listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
  if (listen_fd_ < 0) throw std::runtime_error("gdb: socket() failed");
  int one = 1;
  ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  // 127.0.0.1 only
  addr.sin_port = htons(port);
  if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
    ::close(listen_fd_);
    listen_fd_ = -1;
    throw std::runtime_error("gdb: bind() failed (port in use?)");
  }
  if (::listen(listen_fd_, 1) < 0) {
    ::close(listen_fd_);
    listen_fd_ = -1;
    throw std::runtime_error("gdb: listen() failed");
  }

  std::fprintf(stderr, "[gdb] waiting for a debugger on 127.0.0.1:%u ...\n",
               port);
  client_fd_ = ::accept(listen_fd_, nullptr, nullptr);
  if (client_fd_ < 0) {
    ::close(listen_fd_);
    listen_fd_ = -1;
    throw std::runtime_error("gdb: accept() failed");
  }
  int nd = 1;
  ::setsockopt(client_fd_, IPPROTO_TCP, TCP_NODELAY, &nd, sizeof(nd));
  std::fprintf(stderr, "[gdb] client attached\n");

  no_ack_ = false;
  resumed_ = false;
  stepping_ = false;
  pending_int_ = false;
  last_signal_ = kSigTrap;
  install_hook();

  // Serve the handshake (qSupported, register/memory reads, breakpoint setup)
  // until the client is ready to run. Anything but a clean resume means the
  // debugger went away before the target ran.
  const Resume r = serve();
  if (r == Resume::Continue || r == Resume::Step) {
    resumed_ = true;
    if (r == Resume::Step) stepping_ = true;
    return true;
  }
  close_client();
  return false;
}

void GdbStub::detach() {
  remove_hook();
  close_client();
  if (listen_fd_ >= 0) {
    ::close(listen_fd_);
    listen_fd_ = -1;
  }
}

void GdbStub::close_client() {
  if (client_fd_ >= 0) {
    ::close(client_fd_);
    client_fd_ = -1;
  }
  resumed_ = false;
  breakpoints_.clear();
  stepping_ = false;
}

void GdbStub::end_run() {
  if (!attached() || !resumed_) return;
  // The driven function returned while the client was "running". Report a final
  // stop so the user can inspect the return state, then honor one more command:
  // a resume means "nothing left to run" -> report process exit and end.
  send_stop_reply(kSigTrap);
  const Resume r = serve();
  if (r == Resume::Continue || r == Resume::Step) send_packet("W00");
  resumed_ = false;
}

// -------------------------------------------------------------- code hook glue
void GdbStub::install_hook() {
  if (code_hook_) return;
  uc_hook_add(engine_.raw(), &code_hook_, UC_HOOK_CODE,
              reinterpret_cast<void*>(&GdbStub::code_thunk), this, 1, 0);
}

void GdbStub::remove_hook() {
  if (code_hook_) {
    uc_hook_del(engine_.raw(), code_hook_);
    code_hook_ = 0;
  }
}

void GdbStub::code_thunk(uc_engine*, uint64_t addr, uint32_t, void* user) {
  static_cast<GdbStub*>(user)->on_instruction(addr);
}

void GdbStub::on_instruction(uint64_t pc) {
  if (client_fd_ < 0) return;  // detached: cheapest possible path

  bool brk = stepping_ || pending_int_ || breakpoints_.count(pc);
  if (!brk) {
    // Cheap async-interrupt check: only poll the socket occasionally so a plain
    // "continue" run isn't a syscall per instruction.
    if ((++poll_ctr_ & 0x3fff) == 0 && poll_interrupt()) {
      pending_int_ = true;
      brk = true;
    }
    if (!brk) return;
  }

  const int sig = pending_int_ ? kSigInt : kSigTrap;
  stepping_ = false;
  pending_int_ = false;
  send_stop_reply(sig);

  switch (serve()) {
    case Resume::Continue:
      break;  // return -> uc runs the instruction at pc and hooks the next
    case Resume::Step:
      stepping_ = true;  // stop again on the following instruction
      break;
    case Resume::Kill:
      close_client();
      engine_.stop();
      break;
    case Resume::Detach:
    case Resume::Closed:
      close_client();
      break;
  }
}

// ------------------------------------------------------------------ transport
void GdbStub::send_ack(bool ok) {
  const char c = ok ? '+' : '-';
  (void)::send(client_fd_, &c, 1, 0);
}

// Read one full "$<payload>#<cksum>" packet (or a raw 0x03 interrupt, returned
// as "\x03"). Returns false if the connection closed.
bool GdbStub::read_packet(std::string& out) {
  out.clear();
  for (;;) {
    char c;
    ssize_t n = ::recv(client_fd_, &c, 1, 0);
    if (n <= 0) return false;
    if (c == 0x03) {
      out = std::string(1, '\x03');
      return true;
    }
    if (c != '$') continue;  // skip stray acks / noise until a packet start

    uint8_t sum = 0;
    for (;;) {
      n = ::recv(client_fd_, &c, 1, 0);
      if (n <= 0) return false;
      if (c == '#') break;
      out.push_back(c);
      sum = static_cast<uint8_t>(sum + static_cast<uint8_t>(c));
    }
    char cs[2];
    if (::recv(client_fd_, &cs[0], 1, 0) <= 0) return false;
    if (::recv(client_fd_, &cs[1], 1, 0) <= 0) return false;
    const uint8_t want = static_cast<uint8_t>((unhex_digit(cs[0]) << 4) |
                                              unhex_digit(cs[1]));
    if (!no_ack_) send_ack(sum == want);
    if (sum != want) {
      out.clear();
      continue;  // client will retransmit
    }
    return true;
  }
}

void GdbStub::send_packet(const std::string& payload) {
  std::string msg;
  msg.reserve(payload.size() + 4);
  msg.push_back('$');
  uint8_t sum = 0;
  for (char c : payload) {
    msg.push_back(c);
    sum = static_cast<uint8_t>(sum + static_cast<uint8_t>(c));
  }
  msg.push_back('#');
  msg.push_back(hex_digit(sum >> 4));
  msg.push_back(hex_digit(sum & 0xf));
  (void)::send(client_fd_, msg.data(), msg.size(), 0);
  if (!no_ack_) {
    char ack;  // consume the client's '+' (best effort; ignore '-')
    (void)::recv(client_fd_, &ack, 1, 0);
  }
}

bool GdbStub::poll_interrupt() {
  char c;
  const ssize_t n = ::recv(client_fd_, &c, 1, MSG_DONTWAIT);
  if (n == 1) return c == 0x03;
  return false;
}

// ------------------------------------------------------------- command serving
GdbStub::Resume GdbStub::serve() {
  std::string pkt;
  while (read_packet(pkt)) {
    std::string reply;
    Resume resume = Resume::Closed;
    bool is_resume = false;
    arm_no_ack_ = false;
    handle_packet(pkt, reply, resume, is_resume);
    if (is_resume) return resume;
    send_packet(reply);
    // QStartNoAckMode: the "OK" above is the last acked packet; drop acks now.
    if (arm_no_ack_) no_ack_ = true;
  }
  return Resume::Closed;
}

void GdbStub::send_stop_reply(int signal) {
  last_signal_ = signal;
  // T<sig>; report pc and sp inline so the client shows the stop location
  // without a follow-up 'g'. Register numbers are hex indices into our table.
  const RegTable t = table_for(engine_.abi());
  std::string pkt = "T";
  pkt.push_back(hex_digit((signal >> 4) & 0xf));
  pkt.push_back(hex_digit(signal & 0xf));
  for (size_t i = 0; i < t.count; ++i) {
    const char* g = t.regs[i].generic;
    if (!g || (std::strcmp(g, "pc") != 0 && std::strcmp(g, "sp") != 0)) continue;
    pkt.push_back(hex_digit((i >> 4) & 0xf));
    pkt.push_back(hex_digit(i & 0xf));
    pkt.push_back(':');
    pkt += reg_to_hex(engine_.read_uc_reg(t.regs[i].uc_id), t.regs[i].bits);
    pkt.push_back(';');
  }
  pkt += "thread:1;";
  send_packet(pkt);
}

// ----------------------------------------------------------------- registers
std::string GdbStub::read_all_regs_hex() {
  const RegTable t = table_for(engine_.abi());
  std::string s;
  for (size_t i = 0; i < t.count; ++i) s += reg_hex(engine_.raw(), t.regs[i]);
  return s;
}

void GdbStub::write_all_regs_hex(const std::string& hex) {
  const RegTable t = table_for(engine_.abi());
  size_t off = 0;
  for (size_t i = 0; i < t.count; ++i) {
    const int nib = t.regs[i].bits / 4;
    if (off + nib > hex.size()) break;
    uint8_t buf[16];
    hex_to_reg_bytes(hex.substr(off, nib), t.regs[i], buf);
    write_reg_bytes(engine_.raw(), t.regs[i], buf);
    off += nib;
  }
}

std::string GdbStub::read_one_reg_hex(size_t regnum) {
  const RegTable t = table_for(engine_.abi());
  if (regnum >= t.count) return "xxxxxxxx";
  return reg_hex(engine_.raw(), t.regs[regnum]);
}

void GdbStub::write_one_reg_hex(size_t regnum, const std::string& hex) {
  const RegTable t = table_for(engine_.abi());
  if (regnum >= t.count) return;
  uint8_t buf[16];
  hex_to_reg_bytes(hex, t.regs[regnum], buf);
  write_reg_bytes(engine_.raw(), t.regs[regnum], buf);
}

// The XML target description gdb / Binary Ninja / IDA fetch via qXfer to learn
// our register layout (order + widths must match read_all_regs_hex).
std::string GdbStub::target_xml() const {
  const RegTable t = table_for(engine_.abi());
  // Emit a <reg> line; regnum is the global table index (so g-packet order and
  // regnums agree). type comes from the table, else uint128 for 128-bit vectors,
  // else omitted (gdb defaults by bitsize).
  auto emit = [&](std::string& x, size_t i) {
    const RegDesc& r = t.regs[i];
    const char* type = r.type ? r.type : (r.bits == 128 ? "uint128" : nullptr);
    x += "    <reg name=\"";
    x += r.name;
    x += "\" bitsize=\"";
    x += std::to_string(r.bits);
    x += "\" regnum=\"";
    x += std::to_string(i);
    x += "\"";
    if (type) {
      x += " type=\"";
      x += type;
      x += "\"";
    }
    x += "/>\n";
  };

  std::string x =
      "<?xml version=\"1.0\"?>\n<!DOCTYPE target SYSTEM \"gdb-target.dtd\">\n"
      "<target version=\"1.0\">\n  <architecture>";
  x += t.arch;
  x += "</architecture>\n  <feature name=\"";
  x += t.feature;
  x += "\">\n";
  for (size_t i = 0; i < t.count; ++i)
    if (!t.regs[i].fpu) emit(x, i);
  x += "  </feature>\n";

  bool has_fpu = false;
  for (size_t i = 0; i < t.count; ++i) has_fpu |= t.regs[i].fpu;
  if (has_fpu) {  // v0..v31 + fpsr/fpcr under the standard FP feature
    x += "  <feature name=\"org.gnu.gdb.aarch64.fpu\">\n";
    for (size_t i = 0; i < t.count; ++i)
      if (t.regs[i].fpu) emit(x, i);
    x += "  </feature>\n";
  }
  x += "</target>\n";
  return x;
}

// lldb prefers to learn registers from qRegisterInfo<n> rather than XML.
std::string GdbStub::register_info(size_t regnum) const {
  const RegTable t = table_for(engine_.abi());
  if (regnum >= t.count) return "E45";  // past the end -> stop querying
  const RegDesc& r = t.regs[regnum];
  size_t offset = 0;
  for (size_t i = 0; i < regnum; ++i) offset += t.regs[i].bits / 8;
  std::string s = "name:";
  s += r.name;
  s += ";bitsize:";
  s += std::to_string(r.bits);
  s += ";offset:";
  s += std::to_string(offset);
  // 128-bit V registers present to lldb as byte vectors; scalars as uint/hex.
  if (r.fpu && r.bits == 128)
    s += ";encoding:vector;format:vector-uint8;set:Floating Point Registers";
  else if (r.fpu)
    s += ";encoding:uint;format:hex;set:Floating Point Registers";
  else
    s += ";encoding:uint;format:hex;set:General Purpose Registers";
  s += ";gcc:";
  s += std::to_string(regnum);
  s += ";dwarf:";
  s += std::to_string(regnum);
  s += ";";
  if (r.generic && (std::strcmp(r.generic, "pc") == 0 ||
                    std::strcmp(r.generic, "sp") == 0 ||
                    std::strcmp(r.generic, "fp") == 0 ||
                    std::strcmp(r.generic, "lr") == 0 ||
                    std::strncmp(r.generic, "arg", 3) == 0)) {
    s += "generic:";
    s += r.generic;
    s += ";";
  }
  return s;
}

// --------------------------------------------------------------- the big switch
void GdbStub::handle_packet(const std::string& pkt, std::string& reply,
                            Resume& resume, bool& is_resume) {
  if (pkt.empty()) {
    reply = "";
    return;
  }
  const char cmd = pkt[0];

  // Ctrl-C mid-serve (shouldn't usually arrive here, but be safe).
  if (cmd == '\x03') {
    send_stop_reply(kSigInt);
    reply = "";
    return;
  }

  switch (cmd) {
    case '?':  // why did we stop
      reply = "S05";
      return;

    case 'g':  // read all registers
      reply = read_all_regs_hex();
      return;
    case 'G':  // write all registers
      write_all_regs_hex(pkt.substr(1));
      reply = "OK";
      return;
    case 'p': {  // read register N
      size_t i = 1;
      const uint64_t n = parse_hex_u64(pkt, i);
      reply = read_one_reg_hex(n);
      return;
    }
    case 'P': {  // write register N=value
      size_t i = 1;
      const uint64_t n = parse_hex_u64(pkt, i);
      if (i < pkt.size() && pkt[i] == '=') ++i;
      write_one_reg_hex(n, pkt.substr(i));
      reply = "OK";
      return;
    }

    case 'm': {  // read memory: m addr,len
      size_t i = 1;
      const uint64_t addr = parse_hex_u64(pkt, i);
      if (i < pkt.size() && pkt[i] == ',') ++i;
      const uint64_t len = parse_hex_u64(pkt, i);
      if (len == 0 || len > 0x100000) {
        reply = "E01";
        return;
      }
      std::vector<uint8_t> buf(len);
      try {
        engine_.read(addr, buf.data(), len);
        reply = bytes_to_hex(buf.data(), len);
      } catch (...) {
        reply = "E01";  // unmapped / fault
      }
      return;
    }
    case 'M': {  // write memory (hex): M addr,len:hex
      size_t i = 1;
      const uint64_t addr = parse_hex_u64(pkt, i);
      if (i < pkt.size() && pkt[i] == ',') ++i;
      const uint64_t len = parse_hex_u64(pkt, i);
      if (i < pkt.size() && pkt[i] == ':') ++i;
      std::vector<uint8_t> buf(len);
      for (uint64_t k = 0; k < len && (i + 1) < pkt.size(); ++k, i += 2)
        buf[k] = static_cast<uint8_t>((unhex_digit(pkt[i]) << 4) |
                                      unhex_digit(pkt[i + 1]));
      try {
        engine_.write(addr, buf.data(), len);
        reply = "OK";
      } catch (...) {
        reply = "E01";
      }
      return;
    }
    case 'X': {  // write memory (binary): X addr,len:<raw bytes>
      size_t i = 1;
      const uint64_t addr = parse_hex_u64(pkt, i);
      if (i < pkt.size() && pkt[i] == ',') ++i;
      const uint64_t len = parse_hex_u64(pkt, i);
      if (i < pkt.size() && pkt[i] == ':') ++i;
      // Un-escape 0x7d-escaped bytes in the binary payload.
      std::vector<uint8_t> buf;
      buf.reserve(len);
      for (; i < pkt.size() && buf.size() < len; ++i) {
        uint8_t b = static_cast<uint8_t>(pkt[i]);
        if (b == 0x7d) {  // escape: next byte XOR 0x20
          if (++i >= pkt.size()) break;
          b = static_cast<uint8_t>(pkt[i]) ^ 0x20;
        }
        buf.push_back(b);
      }
      try {
        if (!buf.empty()) engine_.write(addr, buf.data(), buf.size());
        reply = "OK";
      } catch (...) {
        reply = "E01";
      }
      return;
    }

    case 'c':  // continue [addr]
      is_resume = true;
      resume = Resume::Continue;
      return;
    case 'C':  // continue with signal
      is_resume = true;
      resume = Resume::Continue;
      return;
    case 's':  // single step [addr]
      is_resume = true;
      resume = Resume::Step;
      return;
    case 'S':  // step with signal
      is_resume = true;
      resume = Resume::Step;
      return;

    case 'Z':    // insert breakpoint: Z<type>,addr,kind
    case 'z': {  // remove breakpoint
      if (pkt.size() < 2) {
        reply = "E01";
        return;
      }
      const char type = pkt[1];
      if (type != '0' && type != '1') {  // only sw(0)/hw(1) exec breakpoints
        reply = "";  // watchpoints unsupported -> empty (let client know)
        return;
      }
      size_t i = 3;  // skip "Z0,"
      const uint64_t addr = parse_hex_u64(pkt, i);
      if (cmd == 'Z')
        breakpoints_.insert(addr);
      else
        breakpoints_.erase(addr);
      reply = "OK";
      return;
    }

    case 'H':  // set thread for subsequent ops -> single-threaded, always OK
      reply = "OK";
      return;
    case 'D':  // detach
      is_resume = true;
      resume = Resume::Detach;
      return;
    case 'k':  // kill
      is_resume = true;
      resume = Resume::Kill;
      return;

    case 'q':
      if (pkt.rfind("qSupported", 0) == 0) {
        reply =
            "PacketSize=4000;qXfer:features:read+;QStartNoAckMode+;swbreak+;"
            "hwbreak+;vContSupported+";
        return;
      }
      if (pkt == "qC") {
        reply = "QC1";
        return;
      }
      if (pkt == "qAttached") {
        reply = "1";
        return;
      }
      if (pkt == "qfThreadInfo") {
        reply = "m1";
        return;
      }
      if (pkt == "qsThreadInfo") {
        reply = "l";
        return;
      }
      if (pkt == "qHostInfo") {
        // triple (hex) + pointer size + endianness lets lldb set up the target.
        const bool a64 = engine_.abi() == Abi::Arm64;
        const char* triple =
            a64 ? "aarch64-unknown-linux-android" : "arm-unknown-linux-android";
        std::string t = "triple:";
        t += bytes_to_hex(reinterpret_cast<const uint8_t*>(triple),
                          std::strlen(triple));
        t += ";endian:little;ptrsize:";
        t += a64 ? "8" : "4";
        t += ";";
        reply = t;
        return;
      }
      if (pkt == "qProcessInfo") {
        const bool a64 = engine_.abi() == Abi::Arm64;
        std::string p = "pid:1;endian:little;ptrsize:";
        p += a64 ? "8" : "4";
        p += ";";
        reply = p;
        return;
      }
      if (pkt.rfind("qRegisterInfo", 0) == 0) {
        size_t i = std::strlen("qRegisterInfo");
        const uint64_t n = parse_hex_u64(pkt, i);
        reply = register_info(n);
        return;
      }
      if (pkt.rfind("qXfer:features:read:", 0) == 0) {
        // qXfer:features:read:ANNEX:OFFSET,LENGTH -> chunked target.xml.
        const size_t colon = pkt.find(':', std::strlen("qXfer:features:read:"));
        size_t i = (colon == std::string::npos) ? pkt.size() : colon + 1;
        const uint64_t off = parse_hex_u64(pkt, i);
        if (i < pkt.size() && pkt[i] == ',') ++i;
        const uint64_t len = parse_hex_u64(pkt, i);
        const std::string xml = target_xml();
        if (off >= xml.size()) {
          reply = "l";
          return;
        }
        const uint64_t end = std::min<uint64_t>(off + len, xml.size());
        reply = (end < xml.size() ? "m" : "l") + xml.substr(off, end - off);
        return;
      }
      reply = "";  // unknown q -> empty
      return;

    case 'Q':
      if (pkt == "QStartNoAckMode") {
        reply = "OK";       // acked as normal; serve() drops acks afterward
        arm_no_ack_ = true;
        return;
      }
      reply = "";
      return;

    case 'v':
      if (pkt == "vCont?") {
        reply = "vCont;c;C;s;S";
        return;
      }
      if (pkt.rfind("vCont;", 0) == 0) {
        // First action wins for our single thread: c/C -> continue, s/S -> step.
        const char act = pkt.size() > 6 ? pkt[6] : 'c';
        is_resume = true;
        resume = (act == 's' || act == 'S') ? Resume::Step : Resume::Continue;
        return;
      }
      reply = "";  // unknown v -> empty (e.g. vMustReplyEmpty)
      return;

    default:
      reply = "";  // unrecognized -> empty, per RSP
      return;
  }
}

}  // namespace vardoger
