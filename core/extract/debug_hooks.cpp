// vardoger: generic debug/instrumentation hooks (see
// include/vardoger/debug_hooks.hpp).
//
// These were factored out of unchanged: same
// VARDOGER_* env parsing, same hook ranges, same log format. The bodies carry NO
// packer offsets, every address is either an env value or a DebugHookOptions
// field the driver resolved. Keep them behaviourally identical to the driver
// originals; the classic-VM Tracer (include/vardoger/tracer.hpp) is deliberately
// NOT unified with VARDOGER_ITRACE here (different, intentionally verbose,
// register-dumping trace format).
#include "vardoger/extract/debug_hooks.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include "vardoger/engine/disassembler.hpp"
#include "vardoger/util/rc4.hpp"

namespace vardoger {
namespace {

// VARDOGER_MEMREAD="lo:hi" : log every memory READ whose PC is in [SO+lo, SO+hi]
// (addr + value). Single-steps a native function's struct/cookie dereferences
// to reverse the layout it expects.
uint64_t g_mr_bias = 0, g_mr_lo = 0, g_mr_hi = 0;
uint64_t g_mr_tlo = 0,
         g_mr_thi = 0;  // VARDOGER_MEMREAD_TGT: filter by ACCESSED guest addr
                        // (find who reads a region)
void memread_trace(uc_engine* uc, uc_mem_type, uint64_t addr, int size, int64_t,
                   void*) {
  if (g_mr_thi) {
    if (addr < g_mr_tlo || addr >= g_mr_thi) return;
  }  // target-address mode
  uint64_t pc = 0;
  uc_reg_read(uc, UC_ARM64_REG_PC, &pc);
  const uint64_t off = pc - g_mr_bias;
  if (!g_mr_thi && (off < g_mr_lo || off >= g_mr_hi))
    return;  // PC-range mode (original)
  uint64_t v = 0;
  if (size > 0 && size <= 8) uc_mem_read(uc, addr, &v, size);
  std::fprintf(stderr, "[rd SO+%#llx] [%#llx](%d) = %#llx\n",
               (unsigned long long)off, (unsigned long long)addr, size,
               (unsigned long long)v);
}

// VARDOGER_MEMWRITE_TGT="lo:hi" : capture every WRITE landing in [lo,hi) into a
// buffer, then dump it to /tmp/vardoger_memwrite.bin at exit. Address-scoped (hook
// range = [lo,hi)) so it does NOT fire on the 1.7MB container RC4, used to
// snapshot the small per-class RC4 plaintext written in-place.
uint64_t g_mw_lo = 0, g_mw_hi = 0;
std::vector<uint8_t> g_mw_buf;
void memwrite_capture(uc_engine*, uc_mem_type, uint64_t addr, int size,
                      int64_t value, void*) {
  if (addr < g_mw_lo || addr + (unsigned)size > g_mw_hi) return;
  if (g_mw_buf.size() < g_mw_hi - g_mw_lo)
    g_mw_buf.resize(g_mw_hi - g_mw_lo, 0);
  for (int i = 0; i < size && i < 8; ++i)
    g_mw_buf[addr - g_mw_lo + i] = (uint8_t)(value >> (8 * i));
}

// VARDOGER_TRACEPC="pc[:pc]" : each time execution reaches SO+pc, log a global
// counter + x0..x5. Used to trace interpreter-core entries so the check-fn
// being interpreted (fn index in an arg reg) can be correlated with the APK
// read (VARDOGER_OPEN_LOG) → identify the tamper check-fn.
std::vector<uint64_t> g_tpcs;
uint64_t g_tpc_bias = 0, g_tpc_ctr = 0;
void tracepc_hook(uc_engine* uc, uint64_t addr, uint32_t, void*) {
  const uint64_t off = addr - g_tpc_bias;
  for (uint64_t pc : g_tpcs)
    if (pc == off) {
      uint64_t x[6];
      for (int i = 0; i < 6; ++i) uc_reg_read(uc, UC_ARM64_REG_X0 + i, &x[i]);
      // VARDOGER_TRACEPC_STACK: also dump x30, sp, and [sp+0x38] (the saved-LR
      // slot for the dpt/jiagu stack-canary frames), for tracing
      // return-address divergences that plain PC-tracing can't see.
      char extra[96] = "";
      if (std::getenv("VARDOGER_TRACEPC_STACK")) {
        uint64_t x30 = 0, sp = 0, slot = 0;
        uc_reg_read(uc, UC_ARM64_REG_X30, &x30);
        uc_reg_read(uc, UC_ARM64_REG_SP, &sp);
        uc_mem_read(uc, sp + 0x38, &slot, 8);
        std::snprintf(extra, sizeof(extra),
                      " x30=%#llx sp=%#llx [sp+0x38]=%#llx",
                      (unsigned long long)x30, (unsigned long long)sp,
                      (unsigned long long)slot);
      }
      std::fprintf(stderr,
                   "[trace#%llu SO+%#llx] x0=%#llx x1=%#llx x2=%#llx x3=%#llx "
                   "x4=%#llx x5=%#llx%s\n",
                   (unsigned long long)g_tpc_ctr++, (unsigned long long)off,
                   (unsigned long long)x[0], (unsigned long long)x[1],
                   (unsigned long long)x[2], (unsigned long long)x[3],
                   (unsigned long long)x[4], (unsigned long long)x[5], extra);
    }
}

// VARDOGER_BT="pc" : at SO+pc, walk the x29 frame chain and print SO-relative
// return addresses (the native call path). Reveals the tamper/decrypt call
// structure.
std::vector<uint64_t> g_btpcs;
uint64_t g_bt_bias = 0, g_bt_lo = 0, g_bt_hi = 0, g_bt_ctr = 0;
void bt_hook(uc_engine* uc, uint64_t addr, uint32_t, void*) {
  const uint64_t off = addr - g_bt_bias;
  for (uint64_t pc : g_btpcs)
    if (pc == off) {
      uint64_t fp = 0, lr = 0;
      uc_reg_read(uc, UC_ARM64_REG_X29, &fp);
      uc_reg_read(uc, UC_ARM64_REG_X30, &lr);
      std::fprintf(stderr, "[bt#%llu @SO+%#llx] lr=SO+%#llx",
                   (unsigned long long)g_bt_ctr++, (unsigned long long)off,
                   (unsigned long long)(lr - g_bt_bias));
      for (int i = 0; i < 24 && fp; ++i) {
        uint64_t nfp = 0, nlr = 0;
        if (uc_mem_read(uc, fp, &nfp, 8) || uc_mem_read(uc, fp + 8, &nlr, 8))
          break;
        const uint64_t rel = nlr - g_bt_bias;
        if (rel < g_bt_lo || rel >= g_bt_hi)
          std::fprintf(stderr, " <%#llx>", (unsigned long long)nlr);
        else
          std::fprintf(stderr, " SO+%#llx", (unsigned long long)rel);
        if (nfp <= fp) break;
        fp = nfp;
      }
      std::fprintf(stderr, "\n");
    }
}

// VARDOGER_DEXWRITE : hook ALL memory writes; log whenever the DEX magic ('dex\n'
// = 0x0a786564) or the ODEX magic ('dey\n' = 0x0a796564) is written, with
// writer PC + target addr. Finds the moment/site a DEX materializes even if it
// lands in a region scan_dex skips or gets a rewritten magic afterward.
uint64_t g_dw_pbias = 0;
void dexwrite_hook(uc_engine* uc, uc_mem_type, uint64_t addr, int size,
                   int64_t val, void*) {
  if (size < 4) return;
  const uint32_t lo = uint32_t(val);
  if (lo == 0x0a786564u || lo == 0x0a796564u) {
    uint64_t pc = 0;
    uc_reg_read(uc, UC_ARM64_REG_PC, &pc);
    std::fprintf(stderr,
                 "[dexwrite] %.4s magic -> addr=%#llx  pc=%#llx (SO+%#llx)\n",
                 (const char*)&lo, (unsigned long long)addr,
                 (unsigned long long)pc, (unsigned long long)(pc - g_dw_pbias));
  }
}

// VARDOGER_ADDRWATCH="hexaddr", log every write that lands in [addr, addr+8) +
// the value + writer PC. Finds who populates a specific object slot (e.g.
// interface12's handler-table ptr [obj+0x48]).
uint64_t g_aw_addr = 0, g_aw_pbias = 0;
void addrwatch_hook(uc_engine* uc, uc_mem_type, uint64_t addr, int size,
                    int64_t val, void*) {
  if (addr + (unsigned)size <= g_aw_addr || addr >= g_aw_addr + 8) return;
  uint64_t pc = 0;
  uc_reg_read(uc, UC_ARM64_REG_PC, &pc);
  std::fprintf(
      stderr, "[addrwatch] addr=%#llx size=%d val=%#llx  pc=%#llx (SO+%#llx)\n",
      (unsigned long long)addr, size, (unsigned long long)val,
      (unsigned long long)pc, (unsigned long long)(pc - g_aw_pbias));
}

// VARDOGER_KSA_DUMP=<abs_pc|auto> : at the RC4 KSA, dump the key arg (x0=ptr,
// x1=len) + the key bytes. Captures the body-decrypt RC4 key that the BMPHider
// KDF extracts from the embedded BMP.
uint64_t g_ksa_pc = 0, g_ksa_ctr = 0;
void ksa_dump_hook(uc_engine* uc, uint64_t addr, uint32_t, void*) {
  if (addr != g_ksa_pc) return;
  uint64_t kptr = 0, klen = 0;
  uc_reg_read(uc, UC_ARM64_REG_X0, &kptr);
  uc_reg_read(uc, UC_ARM64_REG_X1, &klen);
  std::fprintf(stderr, "[ksa#%llu] KSA key ptr=%#llx len=%llu bytes=",
               (unsigned long long)g_ksa_ctr++, (unsigned long long)kptr,
               (unsigned long long)klen);
  for (uint64_t i = 0; i < klen && i < 64; ++i) {
    uint8_t b = 0;
    uc_mem_read(uc, kptr + i, &b, 1);
    std::fprintf(stderr, "%02x", b);
  }
  std::fprintf(stderr, "\n");
}

// VARDOGER_RC4_FAST : intercept the emulated DynCryptor RC4 KSA/PRGA with native
// RC4 (util/rc4.hpp), the byte-loop over ~1MB is pathologically slow in
// Unicorn; native is instant. At the function entry we compute the result
// natively, write it to guest memory, and set PC=LR to skip the body.
// KSA(x0=key, x1=keylen, x2=state); PRGA(x0=buf-inplace, x1=len, x2=state).
// State = 0x102 bytes.
uint64_t g_rc4_ksa_pc = 0, g_rc4_prga_pc = 0, g_rc4_ctr = 0;
void rc4_ksa_intercept(uc_engine* uc, uint64_t addr, uint32_t, void*) {
  if (addr != g_rc4_ksa_pc) return;
  uint64_t kptr = 0, klen = 0, state = 0, lr = 0;
  uc_reg_read(uc, UC_ARM64_REG_X0, &kptr);
  uc_reg_read(uc, UC_ARM64_REG_X1, &klen);
  uc_reg_read(uc, UC_ARM64_REG_X2, &state);
  uc_reg_read(uc, UC_ARM64_REG_X30, &lr);
  if (klen == 0 || klen > 4096) return;  // not a KSA call we understand
  std::vector<uint8_t> key(klen);
  uc_mem_read(uc, kptr, key.data(), klen);
  vardoger::util::Rc4 r;
  r.ksa(key.data(), klen);
  uint8_t st[0x102];
  r.save_state(st);
  uc_mem_write(uc, state, st, sizeof(st));
  uc_reg_write(uc, UC_ARM64_REG_PC, &lr);  // skip the emulated loop
  if (std::getenv("VARDOGER_RC4_LOG"))
    std::fprintf(
        stderr, "[rc4] native KSA #%llu key(%llu)=%02x%02x%02x%02x..\n",
        (unsigned long long)g_rc4_ctr++, (unsigned long long)klen, key[0],
        klen > 1 ? key[1] : 0, klen > 2 ? key[2] : 0, klen > 3 ? key[3] : 0);
}
void rc4_prga_intercept(uc_engine* uc, uint64_t addr, uint32_t, void*) {
  if (addr != g_rc4_prga_pc) return;
  uint64_t buf = 0, len = 0, state = 0, lr = 0;
  uc_reg_read(uc, UC_ARM64_REG_X0, &buf);
  uc_reg_read(uc, UC_ARM64_REG_X1, &len);
  uc_reg_read(uc, UC_ARM64_REG_X2, &state);
  uc_reg_read(uc, UC_ARM64_REG_X30, &lr);
  if (len > 0x2000000) return;
  uint8_t st[0x102];
  uc_mem_read(uc, state, st, sizeof(st));
  vardoger::util::Rc4 r;
  r.load_state(st);
  std::vector<uint8_t> data(len);
  if (len) uc_mem_read(uc, buf, data.data(), len);
  r.crypt(data.data(), len);
  if (len) uc_mem_write(uc, buf, data.data(), len);
  r.save_state(st);
  uc_mem_write(uc, state, st, sizeof(st));
  uc_reg_write(uc, UC_ARM64_REG_PC, &lr);
  if (std::getenv("VARDOGER_RC4_LOG"))
    std::fprintf(stderr,
                 "[rc4] native PRGA #%llu len=%llu -> "
                 "out[0:8]=%02x%02x%02x%02x%02x%02x%02x%02x\n",
                 (unsigned long long)g_rc4_ctr, (unsigned long long)len,
                 len > 0 ? data[0] : 0, len > 1 ? data[1] : 0,
                 len > 2 ? data[2] : 0, len > 3 ? data[3] : 0,
                 len > 4 ? data[4] : 0, len > 5 ? data[5] : 0,
                 len > 6 ? data[6] : 0, len > 7 ? data[7] : 0);
  if (const char* dir = std::getenv(
          "VARDOGER_RC4_DUMP")) {  // dump each PRGA output to <dir>/prga_NN.bin
    char path[512];
    std::snprintf(path, sizeof path, "%s/prga_%02llu.bin", dir,
                  (unsigned long long)g_rc4_ctr);
    std::ofstream of(path, std::ios::binary);
    of.write(reinterpret_cast<char*>(data.data()), data.size());
  }
  ++g_rc4_ctr;
}

// VARDOGER_XWATCH="abs[,abs]", Phase-0 cross-module watch: log the first few hits
// of each listed absolute inner-arena address + the caller LR + a global order
// counter. Reveals whether inner init (ctors/ JNI_OnLoad) runs naturally and
// who calls it.
std::vector<uint64_t> g_xw;
std::vector<uint64_t> g_xw_cnt;
uint64_t g_xw_order = 0;
void xwatch_hook(uc_engine* uc, uint64_t addr, uint32_t, void*) {
  for (size_t i = 0; i < g_xw.size(); ++i)
    if (g_xw[i] == addr) {
      if (g_xw_cnt[i] < 4) {
        uint64_t lr = 0;
        uc_reg_read(uc, UC_ARM64_REG_LR, &lr);
        std::fprintf(stderr, "[xwatch #%llu %#llx hit%llu] lr=%#llx\n",
                     (unsigned long long)g_xw_order++, (unsigned long long)addr,
                     (unsigned long long)g_xw_cnt[i], (unsigned long long)lr);
      }
      g_xw_cnt[i]++;
    }
}

// VARDOGER_ITRACE="lo:hi" : single-step-log ABSOLUTE PCs in [lo,hi]. For inner-lib
// natives that live outside the loader trace window. Logs pc + disasm + x0..x5
// (+ optional decode bitpos / wide regs).
uint64_t g_it_lo = 0, g_it_hi = 0;
Disassembler* g_it_dis = nullptr;
void itrace_hook(uc_engine* uc, uint64_t addr, uint32_t, void*) {
  if (addr < g_it_lo || addr >= g_it_hi || !g_it_dis) return;
  uint8_t code[4] = {0};
  uc_mem_read(uc, addr, code, sizeof(code));
  const DecodedInsn di = g_it_dis->one(code, sizeof(code), addr);
  uint64_t x[8];
  for (int i = 0; i < 8; ++i) uc_reg_read(uc, UC_ARM64_REG_X0 + i, &x[i]);
  // VARDOGER_ITRACE_BITPOS: append the classic-VM decode bit-position (from decode
  // state @ x19 =
  // {..., bitcount@0x18, bytepos@0x20}; bitpos = bytepos*8 - bitcount) so each
  // traced insn is tagged with where the reader is in the program -> segments
  // the opcode stream (A3 handler->opcode mapping).
  static const bool bitpos = std::getenv("VARDOGER_ITRACE_BITPOS") != nullptr;
  char bp[48] = "";
  if (bitpos) {
    uint64_t x19 = 0;
    uc_reg_read(uc, UC_ARM64_REG_X19, &x19);
    uint64_t bytepos = 0;
    uint32_t bitcount = 0;
    if (x19) {
      uc_mem_read(uc, x19 + 0x20, &bytepos, 8);
      uc_mem_read(uc, x19 + 0x18, &bitcount, 4);
    }
    std::snprintf(bp, sizeof(bp), " bit=%lld(x19=%#llx)",
                  (long long)(bytepos * 8 - bitcount), (unsigned long long)x19);
  }
  // VARDOGER_ITRACE_XWIDE: also dump the callee-saved + dispatch regs, for
  // reversing C++ vtable / handler-table dispatch and the SDK-Jiagu value-VM
  // (x28=current-program base, x21=object array, x23=cur node,
  // x25/x26=indices). x28 is needed to compare the closure-body capture at
  // 0x1a788.
  static const bool xwide = std::getenv("VARDOGER_ITRACE_XWIDE") != nullptr;
  char xw[256] = "";
  if (xwide) {
    uint64_t x8 = 0, x19 = 0, x20 = 0, x21 = 0, x22 = 0, x23 = 0, x24 = 0,
             x25 = 0, x26 = 0, x27 = 0, x28 = 0, x30 = 0, sp = 0;
    uc_reg_read(uc, UC_ARM64_REG_X8, &x8);
    uc_reg_read(uc, UC_ARM64_REG_X19, &x19);
    uc_reg_read(uc, UC_ARM64_REG_X20, &x20);
    uc_reg_read(uc, UC_ARM64_REG_X21, &x21);
    uc_reg_read(uc, UC_ARM64_REG_X22, &x22);
    uc_reg_read(uc, UC_ARM64_REG_X23, &x23);
    uc_reg_read(uc, UC_ARM64_REG_X24, &x24);
    uc_reg_read(uc, UC_ARM64_REG_X25, &x25);
    uc_reg_read(uc, UC_ARM64_REG_X26, &x26);
    uc_reg_read(uc, UC_ARM64_REG_X27, &x27);
    uc_reg_read(uc, UC_ARM64_REG_X28, &x28);
    uc_reg_read(uc, UC_ARM64_REG_X30, &x30);
    uc_reg_read(uc, UC_ARM64_REG_SP, &sp);
    std::snprintf(
        xw, sizeof(xw),
        " x8=%#llx x19=%#llx x20=%#llx x21=%#llx x22=%#llx x23=%#llx"
        " x24=%#llx x25=%#llx x26=%#llx x27=%#llx x28=%#llx x30=%#llx sp=%#llx",
        (unsigned long long)x8, (unsigned long long)x19,
        (unsigned long long)x20, (unsigned long long)x21,
        (unsigned long long)x22, (unsigned long long)x23,
        (unsigned long long)x24, (unsigned long long)x25,
        (unsigned long long)x26, (unsigned long long)x27,
        (unsigned long long)x28, (unsigned long long)x30,
        (unsigned long long)sp);
  }
  std::fprintf(stderr,
               "[it %#llx] %-8s %-28s x0=%#llx x1=%#llx x2=%#llx x3=%#llx "
               "x4=%#llx%s%s\n",
               (unsigned long long)addr, di.mnemonic.c_str(), di.op_str.c_str(),
               (unsigned long long)x[0], (unsigned long long)x[1],
               (unsigned long long)x[2], (unsigned long long)x[3],
               (unsigned long long)x[4], bp, xw);
}

// VARDOGER_PCTRACE="path" : fast PC-only trace, write each executed SO-relative
// PC (u32 LE, binary) to `path`. No disasm, no reg reads → orders of magnitude
// faster than ITRACE; for whole-run lockstep control-flow diffs against another
// emulator. Flushed periodically so a timeout-kill keeps most of it.
FILE* g_pct_fp = nullptr;
uint64_t g_pct_bias = 0, g_pct_lo = 0, g_pct_hi = 0, g_pct_n = 0;
void pctrace_hook(uc_engine* uc, uint64_t addr, uint32_t, void*) {
  const uint64_t off = addr - g_pct_bias;
  if (off >= g_pct_hi) return;
  const uint32_t v = static_cast<uint32_t>(off);
  std::fwrite(&v, 4, 1, g_pct_fp);
  if ((++g_pct_n & 0xfffff) == 0) std::fflush(g_pct_fp);
}

// File-scope hook handles (mirrors the driver's `static uc_hook` locals).
uc_hook hbt, hmr, htpc, hdw, haw, hksa, hrk, hrp, hit, hxw, hpct;
Disassembler g_itrace_dis(Abi::Arm64);

}  // namespace

void install_debug_hooks(Engine& e, const DebugHookOptions& opt) {
  const uint64_t load_bias = opt.load_bias;

  if (const char* bt = std::getenv("VARDOGER_BT")) {
    g_bt_bias = load_bias;
    g_bt_lo = 0;
    g_bt_hi = 0x257000;
    std::string s = bt, tok;
    for (size_t i = 0; i <= s.size(); ++i) {
      if (i == s.size() || s[i] == ':') {
        if (!tok.empty())
          g_btpcs.push_back(std::strtoull(tok.c_str(), nullptr, 16));
        tok.clear();
      } else
        tok += s[i];
    }
    uc_hook_add(e.raw(), &hbt, UC_HOOK_CODE, reinterpret_cast<void*>(&bt_hook),
                nullptr, load_bias, load_bias + 0x257000);
  }
  if (const char* mw = std::getenv("VARDOGER_MEMWRITE_TGT")) {
    std::sscanf(mw, "%llx:%llx", (unsigned long long*)&g_mw_lo,
                (unsigned long long*)&g_mw_hi);
    static uc_hook hmw;
    uc_hook_add(e.raw(), &hmw, UC_HOOK_MEM_WRITE,
                reinterpret_cast<void*>(&memwrite_capture), nullptr, g_mw_lo,
                g_mw_hi);
    std::atexit([]() {
      if (!g_mw_buf.empty()) {
        std::FILE* f = std::fopen("/tmp/vardoger_memwrite.bin", "wb");
        if (f) {
          std::fwrite(g_mw_buf.data(), 1, g_mw_buf.size(), f);
          std::fclose(f);
          std::fprintf(
              stderr,
              "[memwrite] captured %zu bytes -> /tmp/vardoger_memwrite.bin\n",
              g_mw_buf.size());
        }
      }
    });
  }
  if (const char* mr = std::getenv("VARDOGER_MEMREAD")) {
    g_mr_bias = load_bias;
    std::sscanf(mr, "%llx:%llx", (unsigned long long*)&g_mr_lo,
                (unsigned long long*)&g_mr_hi);
    if (const char* mt =
            std::getenv("VARDOGER_MEMREAD_TGT"))  // filter by ACCESSED guest addr
                                               // (find readers of a region)
      std::sscanf(mt, "%llx:%llx", (unsigned long long*)&g_mr_tlo,
                  (unsigned long long*)&g_mr_thi);
    // When a target address range is given, scope the Unicorn hook to it so the
    // callback fires ONLY on reads of that region, a global (1,0) mem-read
    // hook fires per-read and slows the materialization decrypt loop past the
    // 30s slice.
    const uint64_t hlo = g_mr_thi ? g_mr_tlo : 1, hhi = g_mr_thi ? g_mr_thi : 0;
    uc_hook_add(e.raw(), &hmr, UC_HOOK_MEM_READ,
                reinterpret_cast<void*>(&memread_trace), nullptr, hlo, hhi);
  }
  if (const char* tp = std::getenv("VARDOGER_TRACEPC")) {
    g_tpc_bias = load_bias;
    std::string s = tp, tok;
    for (size_t i = 0; i <= s.size(); ++i) {
      if (i == s.size() || s[i] == ':') {
        if (!tok.empty())
          g_tpcs.push_back(std::strtoull(tok.c_str(), nullptr, 16));
        tok.clear();
      } else
        tok += s[i];
    }
    uc_hook_add(e.raw(), &htpc, UC_HOOK_CODE,
                reinterpret_cast<void*>(&tracepc_hook), nullptr, load_bias,
                load_bias + 0x257000);
  }
  if (std::getenv("VARDOGER_DEXWRITE")) {
    g_dw_pbias = load_bias;
    uc_hook_add(e.raw(), &hdw, UC_HOOK_MEM_WRITE,
                reinterpret_cast<void*>(&dexwrite_hook), nullptr, 1, 0);
    std::fprintf(stderr, "[dexwrite] watching all writes for DEX/ODEX magic\n");
  }
  if (const char* aw = std::getenv("VARDOGER_ADDRWATCH")) {
    g_aw_addr = std::strtoull(aw, nullptr, 16);
    g_aw_pbias = load_bias;
    uc_hook_add(e.raw(), &haw, UC_HOOK_MEM_WRITE,
                reinterpret_cast<void*>(&addrwatch_hook), nullptr, 1, 0);
    std::fprintf(stderr, "[addrwatch] watching writes to %#llx\n",
                 (unsigned long long)g_aw_addr);
  }
  if (const char* kd = std::getenv("VARDOGER_KSA_DUMP")) {
    g_ksa_pc = (std::strcmp(kd, "auto") == 0) ? opt.ksa_pc
                                              : std::strtoull(kd, nullptr, 0);
    if (g_ksa_pc) {
      uc_hook_add(e.raw(), &hksa, UC_HOOK_CODE,
                  reinterpret_cast<void*>(&ksa_dump_hook), nullptr, g_ksa_pc,
                  g_ksa_pc + 4);
      std::fprintf(stderr, "[ksa] dumping RC4 key at %#llx\n",
                   (unsigned long long)g_ksa_pc);
    }
  }
  if (std::getenv("VARDOGER_RC4_FAST") && opt.rc4_ksa_pc && opt.rc4_prga_pc) {
    g_rc4_ksa_pc = opt.rc4_ksa_pc;
    g_rc4_prga_pc = opt.rc4_prga_pc;
    uc_hook_add(e.raw(), &hrk, UC_HOOK_CODE,
                reinterpret_cast<void*>(&rc4_ksa_intercept), nullptr,
                g_rc4_ksa_pc, g_rc4_ksa_pc + 4);
    uc_hook_add(e.raw(), &hrp, UC_HOOK_CODE,
                reinterpret_cast<void*>(&rc4_prga_intercept), nullptr,
                g_rc4_prga_pc, g_rc4_prga_pc + 4);
    std::fprintf(stderr, "[rc4] native intercept ON: KSA@%#llx PRGA@%#llx\n",
                 (unsigned long long)g_rc4_ksa_pc,
                 (unsigned long long)g_rc4_prga_pc);
  }
  if (const char* pt = std::getenv("VARDOGER_PCTRACE")) {
    g_pct_fp = std::fopen(pt, "wb");
    g_pct_bias = load_bias;
    g_pct_hi = std::getenv("VARDOGER_PCTRACE_HI")
                   ? std::strtoull(std::getenv("VARDOGER_PCTRACE_HI"), nullptr, 16)
                   : 0x60000;
    if (g_pct_fp) {
      static char buf[1 << 20];
      std::setvbuf(g_pct_fp, buf, _IOFBF, sizeof(buf));
      uc_hook_add(e.raw(), &hpct, UC_HOOK_CODE,
                  reinterpret_cast<void*>(&pctrace_hook), nullptr, load_bias,
                  load_bias + g_pct_hi);
      std::fprintf(stderr, "[pctrace] fast PC trace -> %s\n", pt);
    }
  }
  if (const char* it = std::getenv("VARDOGER_ITRACE")) {
    std::sscanf(it, "%llx:%llx", (unsigned long long*)&g_it_lo,
                (unsigned long long*)&g_it_hi);
    g_it_dis = &g_itrace_dis;
    uc_hook_add(e.raw(), &hit, UC_HOOK_CODE,
                reinterpret_cast<void*>(&itrace_hook), nullptr, g_it_lo,
                g_it_hi);
    std::fprintf(stderr, "[itrace] tracing %#llx..%#llx\n",
                 (unsigned long long)g_it_lo, (unsigned long long)g_it_hi);
  }
  if (const char* xw = std::getenv("VARDOGER_XWATCH")) {
    std::string s = xw, tok;
    for (size_t i = 0; i <= s.size(); ++i) {
      if (i == s.size() || s[i] == ',') {
        if (!tok.empty()) {
          g_xw.push_back(std::strtoull(tok.c_str(), nullptr, 16));
          g_xw_cnt.push_back(0);
        }
        tok.clear();
      } else
        tok += s[i];
    }
    uc_hook_add(e.raw(), &hxw, UC_HOOK_CODE,
                reinterpret_cast<void*>(&xwatch_hook), nullptr, 0x20000000,
                0x70200000);
    std::fprintf(stderr, "[xwatch] watching %zu inner addrs\n", g_xw.size());
  }
}

}  // namespace vardoger
