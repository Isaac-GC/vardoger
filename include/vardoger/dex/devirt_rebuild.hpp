// vardoger: NATIVE DEX devirtualization rebuilder for the Jiagu SDK unpacker.
//
// Ports the pure-python devirt pipeline from
// (the `_md_*` family +
// `_dex_method_index`) so jiagu_driver `--full-devirt` no longer shells out to
// python. Consumes a driver decode log (==METHOD== / DLV lines), builds a
// per-op -> family classification by aggregating the DLV data across all
// methods (the driver log lacks MICROVM/OPMAP rows, so we reconstruct
// reads/writes/branch from the DLV stream), decodes+sanitizes each method's VM
// bytecode into Dalvik, assembles the code_item, resolves (class,name,sig) ->
// global method_idx per DEX, and relinks via vardoger::DexRebuilder (which clears
// ACC_NATIVE, appends code_items, and fixes the SHA-1 + Adler-32).
//
// Header-only. Correctness-critical: the assembler/encoder/decoder mirror the
// python spec faithfully.
#pragma once

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>

#include "vardoger/dex/rebuilder.hpp"

namespace vardoger {

// ---------------------------------------------------------------------------------------------------
// Result of relinking one DEX.
struct DevirtResult {
  std::string path;  // written DEX path
  size_t built = 0;  // methods relinked in this DEX
  size_t total = 0;  // total method blocks in the log (same across all DEXes)
  size_t skipped =
      0;  // method blocks skipped (cls=?/name=?/class not in any DEX)
  bool sig_ok = false;   // sha1(bytes[32:]) == bytes[12:32]
  bool csum_ok = false;  // adler32(bytes[12:]) == u32@8
};

namespace devirt_detail {

// ---- Dalvik opcode table + formats (port of _MD_OPS)
// ----------------------------------------------
struct MdOp {
  uint16_t op;
  const char* fmt;
};

inline const std::map<std::string, MdOp>& md_ops() {
  static const std::map<std::string, MdOp> M = [] {
    std::map<std::string, MdOp> m = {
        {"nop", {0x00, "10x"}},
        {"move", {0x01, "12x"}},
        {"move/from16", {0x02, "22x"}},
        {"move-wide", {0x04, "12x"}},
        {"move-object", {0x07, "12x"}},
        {"move-object/from16", {0x08, "22x"}},
        {"move-result", {0x0a, "11x"}},
        {"move-result-wide", {0x0b, "11x"}},
        {"move-result-object", {0x0c, "11x"}},
        {"move-exception", {0x0d, "11x"}},
        {"return-void", {0x0e, "10x"}},
        {"return", {0x0f, "11x"}},
        {"return-wide", {0x10, "11x"}},
        {"return-object", {0x11, "11x"}},
        {"const/4", {0x12, "11n"}},
        {"const/16", {0x13, "21s"}},
        {"const", {0x14, "31i"}},
        {"const/high16", {0x15, "21h"}},
        {"const-wide/16", {0x16, "21s"}},
        {"const-wide/32", {0x17, "31i"}},
        {"const-wide/high16", {0x19, "21h"}},
        {"const-string", {0x1a, "21c"}},
        {"const-class", {0x1c, "21c"}},
        {"monitor-enter", {0x1d, "11x"}},
        {"monitor-exit", {0x1e, "11x"}},
        {"check-cast", {0x1f, "21c"}},
        {"instance-of", {0x20, "22c"}},
        {"array-length", {0x21, "12x"}},
        {"new-instance", {0x22, "21c"}},
        {"new-array", {0x23, "22c"}},
        {"throw", {0x27, "11x"}},
        {"goto", {0x28, "10t"}},
        {"goto/16", {0x29, "20t"}},
        {"goto/32", {0x2a, "30t"}},
        {"cmpl-float", {0x2d, "23x"}},
        {"cmpg-float", {0x2e, "23x"}},
        {"cmpl-double", {0x2f, "23x"}},
        {"cmpg-double", {0x30, "23x"}},
        {"cmp-long", {0x31, "23x"}},
        {"if-eq", {0x32, "22t"}},
        {"if-ne", {0x33, "22t"}},
        {"if-lt", {0x34, "22t"}},
        {"if-ge", {0x35, "22t"}},
        {"if-gt", {0x36, "22t"}},
        {"if-le", {0x37, "22t"}},
        {"if-eqz", {0x38, "21t"}},
        {"if-nez", {0x39, "21t"}},
        {"if-ltz", {0x3a, "21t"}},
        {"if-gez", {0x3b, "21t"}},
        {"if-gtz", {0x3c, "21t"}},
        {"if-lez", {0x3d, "21t"}},
        {"aget", {0x44, "23x"}},
        {"aget-wide", {0x45, "23x"}},
        {"aget-object", {0x46, "23x"}},
        {"aget-boolean", {0x47, "23x"}},
        {"aget-byte", {0x48, "23x"}},
        {"aget-char", {0x49, "23x"}},
        {"aget-short", {0x4a, "23x"}},
        {"aput", {0x4b, "23x"}},
        {"aput-wide", {0x4c, "23x"}},
        {"aput-object", {0x4d, "23x"}},
        {"aput-boolean", {0x4e, "23x"}},
        {"aput-byte", {0x4f, "23x"}},
        {"aput-char", {0x50, "23x"}},
        {"aput-short", {0x51, "23x"}},
        {"iget", {0x52, "22c"}},
        {"iget-wide", {0x53, "22c"}},
        {"iget-object", {0x54, "22c"}},
        {"iget-boolean", {0x55, "22c"}},
        {"iget-byte", {0x56, "22c"}},
        {"iget-char", {0x57, "22c"}},
        {"iget-short", {0x58, "22c"}},
        {"iput", {0x59, "22c"}},
        {"iput-wide", {0x5a, "22c"}},
        {"iput-object", {0x5b, "22c"}},
        {"iput-boolean", {0x5c, "22c"}},
        {"iput-byte", {0x5d, "22c"}},
        {"iput-char", {0x5e, "22c"}},
        {"iput-short", {0x5f, "22c"}},
        {"sget", {0x60, "21c"}},
        {"sget-wide", {0x61, "21c"}},
        {"sget-object", {0x62, "21c"}},
        {"sget-boolean", {0x63, "21c"}},
        {"sget-byte", {0x64, "21c"}},
        {"sget-char", {0x65, "21c"}},
        {"sget-short", {0x66, "21c"}},
        {"sput", {0x67, "21c"}},
        {"sput-wide", {0x68, "21c"}},
        {"sput-object", {0x69, "21c"}},
        {"sput-boolean", {0x6a, "21c"}},
        {"sput-byte", {0x6b, "21c"}},
        {"sput-char", {0x6c, "21c"}},
        {"sput-short", {0x6d, "21c"}},
        {"invoke-virtual", {0x6e, "35c"}},
        {"invoke-super", {0x6f, "35c"}},
        {"invoke-direct", {0x70, "35c"}},
        {"invoke-static", {0x71, "35c"}},
        {"invoke-interface", {0x72, "35c"}},
        {"invoke-virtual/range", {0x74, "3rc"}},
        {"invoke-super/range", {0x75, "3rc"}},
        {"invoke-direct/range", {0x76, "3rc"}},
        {"invoke-static/range", {0x77, "3rc"}},
        {"invoke-interface/range", {0x78, "3rc"}},
        {"neg-int", {0x7b, "12x"}},
        {"not-int", {0x7c, "12x"}},
        {"neg-long", {0x7d, "12x"}},
        {"not-long", {0x7e, "12x"}},
        {"neg-float", {0x7f, "12x"}},
        {"neg-double", {0x80, "12x"}},
        {"int-to-long", {0x81, "12x"}},
        {"int-to-float", {0x82, "12x"}},
        {"int-to-double", {0x83, "12x"}},
        {"long-to-int", {0x84, "12x"}},
        {"long-to-float", {0x85, "12x"}},
        {"long-to-double", {0x86, "12x"}},
        {"float-to-int", {0x87, "12x"}},
        {"float-to-long", {0x88, "12x"}},
        {"float-to-double", {0x89, "12x"}},
        {"double-to-int", {0x8a, "12x"}},
        {"double-to-long", {0x8b, "12x"}},
        {"double-to-float", {0x8c, "12x"}},
        {"int-to-byte", {0x8d, "12x"}},
        {"int-to-char", {0x8e, "12x"}},
        {"int-to-short", {0x8f, "12x"}},
    };
    const char* bin[] = {
        "add-int",    "sub-int",   "mul-int",    "div-int",    "rem-int",
        "and-int",    "or-int",    "xor-int",    "shl-int",    "shr-int",
        "ushr-int",   "add-long",  "sub-long",   "mul-long",   "div-long",
        "rem-long",   "and-long",  "or-long",    "xor-long",   "shl-long",
        "shr-long",   "ushr-long", "add-float",  "sub-float",  "mul-float",
        "div-float",  "rem-float", "add-double", "sub-double", "mul-double",
        "div-double", "rem-double"};
    for (int i = 0; i < 32; ++i) {
      m[std::string(bin[i])] = {uint16_t(0x90 + i), "23x"};
      m[std::string(bin[i]) + "/2addr"] = {uint16_t(0xb0 + i), "12x"};
    }
    const char* l16[] = {"add-int", "rsub-int", "mul-int", "div-int",
                         "rem-int", "and-int",  "or-int",  "xor-int"};
    for (int i = 0; i < 8; ++i)
      m[std::string(l16[i]) + "/lit16"] = {uint16_t(0xd0 + i), "22s"};
    const char* l8[] = {"add-int", "rsub-int", "mul-int", "div-int",
                        "rem-int", "and-int",  "or-int",  "xor-int",
                        "shl-int", "shr-int",  "ushr-int"};
    for (int i = 0; i < 11; ++i)
      m[std::string(l8[i]) + "/lit8"] = {uint16_t(0xd8 + i), "22b"};
    return m;
  }();
  return M;
}

inline int md_units(const std::string& fmt) {
  // _MD_UNITS
  if (fmt == "10x" || fmt == "11x" || fmt == "11n" || fmt == "12x" ||
      fmt == "10t")
    return 1;
  if (fmt == "22x" || fmt == "21s" || fmt == "21h" || fmt == "21c" ||
      fmt == "21t" || fmt == "23x" || fmt == "22b" || fmt == "22s" ||
      fmt == "22c" || fmt == "22t" || fmt == "20t")
    return 2;
  if (fmt == "31i" || fmt == "31c" || fmt == "30t" || fmt == "35c" ||
      fmt == "3rc")
    return 3;
  return 1;
}

// A decoded Dalvik instruction: mnemonic + integer operands
// (regs/lits/pool/target). For branch formats the target operand is an INDEX
// into the instruction list (resolved to a unit offset at assemble time),
// mirroring the python (mn, ops) tuples where 10t/20t/30t use ops[0] as an
// index, 21t ops[1], 22t ops[2].
struct DalvikInstr {
  std::string mnem;
  std::vector<int64_t> ops;  // scalar operands
  std::vector<int> regs;     // 35c register list (invoke); empty otherwise
};

inline void put_u16(std::vector<uint8_t>& o, uint16_t v) {
  o.push_back(v & 0xff);
  o.push_back(v >> 8);
}
inline void put_s16(std::vector<uint8_t>& o, int16_t v) {
  uint16_t u = (uint16_t)v;
  o.push_back(u & 0xff);
  o.push_back(u >> 8);
}
inline void put_i32(std::vector<uint8_t>& o, int32_t v) {
  uint32_t u = (uint32_t)v;
  o.push_back(u & 0xff);
  o.push_back((u >> 8) & 0xff);
  o.push_back((u >> 16) & 0xff);
  o.push_back((u >> 24) & 0xff);
}

// Port of _md_encode. `cur` = current instruction's unit offset (for relative
// branch encoding). Ops that use register nibbles/bytes come from ins.ops
// (branch targets already resolved to absolute unit offsets).
inline std::vector<uint8_t> md_encode(const DalvikInstr& ins, int cur) {
  const auto& tbl = md_ops();
  auto it = tbl.find(ins.mnem);
  std::vector<uint8_t> out;
  if (it == tbl.end()) {
    put_u16(out, 0);
    return out;
  }  // unknown -> nop (defensive)
  uint16_t op = it->second.op;
  std::string fmt = it->second.fmt;
  const auto& o = ins.ops;
  auto r = [&](size_t i) -> int64_t { return i < o.size() ? o[i] : 0; };

  if (fmt == "10x") {
    put_u16(out, op);
    return out;
  }
  if (fmt == "11x") {
    put_u16(out, (uint16_t)((r(0) << 8) | op));
    return out;
  }
  if (fmt == "11n" || fmt == "12x") {
    put_u16(out, (uint16_t)(((r(1) & 0xf) << 12) | ((r(0) & 0xf) << 8) | op));
    return out;
  }
  if (fmt == "22x") {
    put_u16(out, (uint16_t)((r(0) << 8) | op));
    put_u16(out, (uint16_t)r(1));
    return out;
  }
  if (fmt == "21s" || fmt == "21h") {
    put_u16(out, (uint16_t)((r(0) << 8) | op));
    put_s16(out, (int16_t)r(1));
    return out;
  }
  if (fmt == "21c") {
    put_u16(out, (uint16_t)((r(0) << 8) | op));
    put_u16(out, (uint16_t)r(1));
    return out;
  }
  if (fmt == "31i") {
    put_u16(out, (uint16_t)((r(0) << 8) | op));
    put_i32(out, (int32_t)r(1));
    return out;
  }
  if (fmt == "23x") {
    put_u16(out, (uint16_t)((r(0) << 8) | op));
    put_u16(out, (uint16_t)((r(2) << 8) | r(1)));
    return out;
  }
  if (fmt == "22b") {
    put_u16(out, (uint16_t)((r(0) << 8) | op));
    put_u16(out, (uint16_t)(((r(2) & 0xff) << 8) | r(1)));
    return out;
  }
  if (fmt == "22s") {
    put_u16(out, (uint16_t)(((r(1) & 0xf) << 12) | ((r(0) & 0xf) << 8) | op));
    put_s16(out, (int16_t)r(2));
    return out;
  }
  if (fmt == "22c") {
    put_u16(out, (uint16_t)(((r(1) & 0xf) << 12) | ((r(0) & 0xf) << 8) | op));
    put_u16(out, (uint16_t)r(2));
    return out;
  }
  if (fmt == "22t") {
    put_u16(out, (uint16_t)(((r(1) & 0xf) << 12) | ((r(0) & 0xf) << 8) | op));
    put_s16(out, (int16_t)(r(2) - cur));
    return out;
  }
  if (fmt == "21t") {
    put_u16(out, (uint16_t)((r(0) << 8) | op));
    put_s16(out, (int16_t)(r(1) - cur));
    return out;
  }
  if (fmt == "10t") {
    put_u16(out, (uint16_t)((((r(0) - cur) & 0xff) << 8) | op));
    return out;
  }
  if (fmt == "20t") {
    put_u16(out, op);
    put_s16(out, (int16_t)(r(0) - cur));
    return out;
  }
  if (fmt == "30t") {
    put_u16(out, op);
    put_i32(out, (int32_t)(r(0) - cur));
    return out;
  }
  if (fmt == "35c") {
    // ops[0] = register list (ins.regs), ops[1] = pool idx
    std::vector<int> rr = ins.regs;
    int A = (int)rr.size();
    rr.resize(5, 0);
    int64_t idx = r(1);
    put_u16(out, (uint16_t)((A << 12) | ((rr[4] & 0xf) << 8) | op));
    put_u16(out, (uint16_t)idx);
    put_u16(out, (uint16_t)(((rr[3] & 0xf) << 12) | ((rr[2] & 0xf) << 8) |
                            ((rr[1] & 0xf) << 4) | (rr[0] & 0xf)));
    return out;
  }
  if (fmt == "3rc") {
    int64_t first = r(0), cnt = r(1), idx = r(2);
    put_u16(out, (uint16_t)((cnt << 8) | op));
    put_u16(out, (uint16_t)idx);
    put_u16(out, (uint16_t)first);
    return out;
  }
  put_u16(out, 0);
  return out;
}

// Port of _md_assemble. Returns the assembled u16 unit stream. Branch operand
// indices (into `instrs`) are resolved to absolute unit offsets first.
inline std::vector<uint16_t> md_assemble(
    const std::vector<DalvikInstr>& instrs) {
  const auto& tbl = md_ops();
  std::vector<int> offs;
  int u = 0;
  for (const auto& in : instrs) {
    offs.push_back(u);
    auto it = tbl.find(in.mnem);
    u += (it == tbl.end()) ? 1 : md_units(it->second.fmt);
  }
  std::vector<uint8_t> raw;
  for (size_t i = 0; i < instrs.size(); ++i) {
    DalvikInstr in = instrs[i];
    auto it = tbl.find(in.mnem);
    std::string fmt = (it == tbl.end()) ? "10x" : std::string(it->second.fmt);
    // Resolve branch target index -> absolute unit offset (bounds-guarded).
    auto resolve = [&](size_t opi) {
      if (opi < in.ops.size()) {
        int64_t idx = in.ops[opi];
        if (idx >= 0 && idx < (int64_t)offs.size()) in.ops[opi] = offs[idx];
      }
    };
    if (fmt == "10t" || fmt == "20t" || fmt == "30t")
      resolve(0);
    else if (fmt == "21t")
      resolve(1);
    else if (fmt == "22t")
      resolve(2);
    std::vector<uint8_t> enc = md_encode(in, offs[i]);
    raw.insert(raw.end(), enc.begin(), enc.end());
  }
  std::vector<uint16_t> units;
  for (size_t i = 0; i + 1 < raw.size(); i += 2)
    units.push_back((uint16_t)(raw[i] | (raw[i + 1] << 8)));
  if (raw.size() & 1)
    units.push_back(
        raw.back());  // shouldn't happen (all formats are u16-aligned)
  return units;
}

// ---- op-family bridge (port of _MD_ALU + _md_to_dalvik)
// --------------------------------------------
inline const std::map<std::string, std::string>& md_alu() {
  static const std::map<std::string, std::string> M = {
      {"add", "add-int"},    {"sub", "sub-int"},    {"mul", "mul-int"},
      {"udiv", "div-int"},   {"sdiv", "div-int"},   {"and", "and-int"},
      {"orr", "or-int"},     {"eor", "xor-int"},    {"lsl", "shl-int"},
      {"lsr", "ushr-int"},   {"asr", "shr-int"},    {"fadd", "add-float"},
      {"fsub", "sub-float"}, {"fmul", "mul-float"}, {"fdiv", "div-float"},
  };
  return M;
}

// A decoded VM instruction (port of the dict built by _md_decode_method).
struct VmInstr {
  uint16_t op = 0;
  std::string family;
  std::vector<int> vregs;
  bool has_pool = false;
  int pool = 0;
  bool has_lit = false;
  int64_t lit = 0;
  bool has_target = false;
  int target = 0;  // index into decoded list
};

inline bool str_contains(const std::string& s, const std::string& sub) {
  return s.find(sub) != std::string::npos;
}
inline std::string fam_base(const std::string& fam) {
  auto slash = fam.find('/');
  return slash == std::string::npos ? fam : fam.substr(0, slash);
}

// Port of _md_to_dalvik. Returns false if it maps to the fall-through nop with
// no operands would still emit, here every branch returns an instruction
// (defaulting to nop). Sets `out`.
inline DalvikInstr md_to_dalvik(const VmInstr& ins) {
  DalvikInstr d;
  const std::string& fam = ins.family;
  const auto& v = ins.vregs;
  std::string base = fam_base(fam);
  const auto& alu = md_alu();

  auto A = alu.find(base);
  if (A != alu.end()) {
    std::string mn = A->second;
    if (str_contains(fam, "/2addr") && v.size() >= 2) {
      d.mnem = mn + "/2addr";
      d.ops = {v[0], v[1]};
      return d;
    }
    if (v.size() >= 3) {
      d.mnem = mn;
      d.ops = {v[0], v[1], v[2]};
      return d;
    }
    if (v.size() >= 2) {
      d.mnem = mn + "/2addr";
      d.ops = {v[0], v[1]};
      return d;
    }
  }
  if (fam == "binary-int" && v.size() >= 3) {
    d.mnem = "add-int";
    d.ops = {v[0], v[1], v[2]};
    return d;
  }
  if (fam == "binary-int" && v.size() == 2) {
    d.mnem = "add-int/2addr";
    d.ops = {v[0], v[1]};
    return d;
  }
  if ((fam == "move/unary" || fam == "move") && v.size() >= 2) {
    d.mnem = "move";
    d.ops = {v[0], v[1]};
    return d;
  }
  if ((fam == "move-result/const" || fam == "move-result") && v.size() >= 1) {
    d.mnem = "move-result";
    d.ops = {v[0]};
    return d;
  }
  if (fam == "const" && v.size() >= 1) {
    int64_t L = ins.has_lit ? ins.lit : 0;
    if (L >= -8 && L <= 7) {
      d.mnem = "const/4";
      d.ops = {v[0], L};
      return d;
    }
    if (L >= -32768 && L <= 32767) {
      d.mnem = "const/16";
      d.ops = {v[0], L};
      return d;
    }
    d.mnem = "const";
    d.ops = {v[0], L};
    return d;
  }
  if (fam == "invoke") {
    d.mnem = "invoke-virtual";
    d.regs = v.empty() ? std::vector<int>{0} : v;
    d.ops = {0, ins.has_pool
                    ? (int64_t)ins.pool
                    : 0};  // ops[0] placeholder (regs used), ops[1]=pool idx
    return d;
  }
  if (fam == "ref-op" || fam == "const/ref") {
    if (v.size() >= 2 && ins.has_pool) {
      d.mnem = "iget-object";
      d.ops = {v[0], v[1], ins.pool};
      return d;
    }
    if (v.size() >= 1 && ins.has_pool) {
      d.mnem = "const-string";
      d.ops = {v[0], ins.pool};
      return d;
    }
    if (v.size() >= 1) {
      d.mnem = "move-object";
      d.ops = {v[0], v.size() > 1 ? v[1] : v[0]};
      return d;
    }
  }
  if (fam == "if-cmp" && v.size() >= 2) {
    d.mnem = "if-eq";
    d.ops = {v[0], v[1], ins.has_target ? (int64_t)ins.target : 0};
    return d;
  }
  if ((fam == "if-testz" || fam == "if-testz/return") && v.size() >= 1) {
    d.mnem = "if-eqz";
    d.ops = {v[0], ins.has_target ? (int64_t)ins.target : 0};
    return d;
  }
  if (base == "wide" || str_contains(fam, "multi-word")) {
    d.mnem = "const-wide/16";
    d.ops = {v.empty() ? 0 : v[0], ins.has_lit ? ins.lit : 0};
    return d;
  }
  if (fam == "nop/goto" || fam == "nop") {
    if (ins.has_target) {
      d.mnem = "goto";
      d.ops = {(int64_t)ins.target};
      return d;
    }
    d.mnem = "nop";
    return d;
  }
  if (fam.rfind("return", 0) == 0) {
    if (v.empty()) {
      d.mnem = "return-void";
      return d;
    }
    d.mnem = "return";
    d.ops = {v[0]};
    return d;
  }
  d.mnem = "nop";
  return d;
}

// ---- decode-log record types
// ----------------------------------------------------------------------- One
// DLV record. `->N` (has_tgt) is the ONLY empirical branch signal.
// r{}/w{}/pool{} are captured when the log carries them (richer logs); the
// driver decode log usually has only p/op/len/raw + optional ->N.
struct RwPair {
  int reg;
  int64_t val;
};
struct RawDlv {
  int p;
  uint16_t op;
  uint32_t raw;
  bool has_tgt;
  int tgt;
  std::vector<RwPair> reads, writes;  // from r{vA=0x..} / w{vC=0x..}
  bool has_pool = false;
  int pool = 0;            // from pool=<n>
  bool has_fetch = false;  // from fetch{..}
};
struct MethodBlock {
  std::string cls;  // slashed internal (no L;)
  std::string name;
  std::string sig;
  std::vector<RawDlv> dlv;
};

// ---- op -> family classification
// ------------------------------------------------------------------- PRIMARY
// source: the engagement-free static decode's `MICROVM op=..` rows
// (reads/writes/alu/branch/ nfetch/worddec/calls per handler). This is the real
// per-handler behavior, no interpreter engagement needed, so bodies come out
// as real instruction mixes, not skeletons. Ports _md_parse_static +
// _md_classify from jiagu_sdk_standalone.py faithfully. The DLV `->N` empirical
// branch signal is UNIONed on top (an op that produced a real branch target is
// treated as a branch even if its MICROVM row missed it). DLV value-fit/arity
// is the fallback ONLY for ops with no MICROVM row.

// A parsed MICROVM row (port of the _md_parse_static dict).
struct MicrovmRow {
  std::vector<int> reads, writes;
  std::vector<std::string> alu;
  int branch = 0, nfetch = 0, worddec = 0;
  std::vector<uint64_t> calls;
};

// Parse the `MICROVM op=(0xNN|0000) r=[..] w=[..] alu=[..] branch=N nfetch=N
// worddec=N calls=[..]` lines (port of _md_parse_static). Returns {op -> row};
// op '0000' maps to 0.
inline std::map<uint16_t, MicrovmRow> md_parse_static(const std::string& text) {
  std::map<uint16_t, MicrovmRow> rows;
  auto ints = [](const std::string& s, int base) {
    std::vector<int64_t> v;
    std::istringstream is(s);
    std::string tok;
    while (is >> tok) v.push_back((int64_t)strtoll(tok.c_str(), nullptr, base));
    return v;
  };
  std::istringstream in(text);
  std::string ln;
  while (std::getline(in, ln)) {
    auto mp = ln.find("MICROVM op=");
    if (mp == std::string::npos) continue;
    // Extract a field by its `key`. If `bracketed`, return the text between the
    // '[' that immediately follows the key and its matching ']'; otherwise
    // return the whitespace-delimited token.
    auto field = [&](const std::string& key, bool bracketed) -> std::string {
      auto p = ln.find(key, mp);
      if (p == std::string::npos) return "";
      p += key.size();
      if (bracketed) {
        if (p >= ln.size() || ln[p] != '[') return "";
        auto rb = ln.find(']', p);
        return ln.substr(
            p + 1, rb == std::string::npos ? std::string::npos : rb - p - 1);
      }
      auto e = ln.find_first_of(" \t", p);
      return ln.substr(p, e == std::string::npos ? std::string::npos : e - p);
    };
    std::string sop = field("op=", false);
    uint16_t op =
        (sop == "0000") ? 0 : (uint16_t)strtoul(sop.c_str(), nullptr, 16);
    MicrovmRow row;
    for (auto x : ints(field("r=", true), 10)) row.reads.push_back((int)x);
    for (auto x : ints(field("w=", true), 10)) row.writes.push_back((int)x);
    {
      std::istringstream is(field("alu=", true));
      std::string t;
      while (is >> t) row.alu.push_back(t);
    }
    row.branch = (int)strtol(field("branch=", false).c_str(), nullptr, 10);
    row.nfetch = (int)strtol(field("nfetch=", false).c_str(), nullptr, 10);
    row.worddec = (int)strtol(field("worddec=", false).c_str(), nullptr, 10);
    for (auto x : ints(field("calls=", true), 16))
      row.calls.push_back((uint64_t)x);
    rows[op] = std::move(row);
  }
  return rows;
}

// Faithful port of _md_classify. Ranks call-targets by across-op frequency to
// find OPF (most common) and INV (2nd), then classifies each op by its
// reads/writes/alu/branch/worddec/calls.
inline std::map<uint16_t, std::string> md_classify(
    const std::map<uint16_t, MicrovmRow>& rows) {
  // freq[c] = # of ops whose call-set contains c (set(calls) per op, as in
  // python).
  std::map<uint64_t, int> freq;
  for (const auto& kv : rows) {
    std::set<uint64_t> uniq(kv.second.calls.begin(), kv.second.calls.end());
    for (auto c : uniq) freq[c]++;
  }
  // ranked = call-targets by descending frequency (most_common). Ties: python
  // most_common keeps first- insertion order among equal counts; we mirror by
  // stable sort on (-count, first-seen order).
  std::vector<std::pair<uint64_t, int>> ranked(freq.begin(), freq.end());
  std::map<uint64_t, int> firstseen;
  int seq = 0;
  for (const auto& kv : rows)
    for (auto c :
         std::set<uint64_t>(kv.second.calls.begin(), kv.second.calls.end()))
      if (!firstseen.count(c)) firstseen[c] = seq++;
  std::stable_sort(ranked.begin(), ranked.end(),
                   [&](const auto& a, const auto& b) {
                     if (a.second != b.second) return a.second > b.second;
                     return firstseen[a.first] < firstseen[b.first];
                   });
  bool has_opf = !ranked.empty();
  uint64_t OPF = has_opf ? ranked[0].first : 0;
  bool has_inv = false;
  uint64_t INV = 0;
  for (const auto& r : ranked)
    if (!has_opf || r.first != OPF) {
      INV = r.first;
      has_inv = true;
      break;
    }

  std::map<uint16_t, std::string> out;
  for (const auto& kv : rows) {
    const MicrovmRow& d = kv.second;
    int nr = (int)d.reads.size(), nw = (int)d.writes.size();
    std::set<uint64_t> calls(d.calls.begin(), d.calls.end());
    if (d.branch) {
      out[kv.first] = (nr >= 2) ? "if-cmp" : "if-testz";
    } else if (has_inv && calls.count(INV))
      out[kv.first] = "invoke";
    else if (!d.alu.empty()) {
      // append /2addr if a write reg is also read (in-place update).
      bool inplace = false;
      for (int w : d.writes)
        for (int r : d.reads)
          if (w == r) inplace = true;
      out[kv.first] = inplace ? (d.alu[0] + "/2addr") : d.alu[0];
    } else if (d.worddec >= 1 && nr == 0 && nw == 0)
      out[kv.first] = "const-wide/switch/fill-array";
    else if (has_opf && calls.count(OPF) && nr == 0 && nw <= 1)
      out[kv.first] = "const/ref";
    else if (nr >= 2 && nw >= 1)
      out[kv.first] = "binary-int";
    else if (nr == 2 && nw == 0)
      out[kv.first] = "if-cmp";
    else if (nr == 1 && nw == 1)
      out[kv.first] = "move/unary";
    else if (nr == 0 && nw == 1)
      out[kv.first] = "move-result/const";
    else if (nr == 1 && nw == 0)
      out[kv.first] = "if-testz/return";
    else if (!calls.empty())
      out[kv.first] = "ref-op";
    else
      out[kv.first] = "nop/goto";
  }
  return out;
}

// Parse the deterministic `OPMAP op=0xNN family=<fam>` rows (the driver's
// VARDOGER_STATIC_OPMAP static classifier). When present these are the
// AUTHORITATIVE per-op family map, they come from static disassembly of the
// interpreter handlers (no execution, no per-app plumbing noise), so they
// override the dynamic MICROVM `md_classify` path entirely.
inline std::map<uint16_t, std::string> parse_opmap(const std::string& text) {
  std::map<uint16_t, std::string> out;
  std::istringstream in(text);
  std::string ln;
  while (std::getline(in, ln)) {
    auto mp = ln.find("OPMAP op=");
    if (mp == std::string::npos) continue;
    auto fp = ln.find("family=", mp);
    if (fp == std::string::npos) continue;
    std::string sop = ln.substr(mp + 9);
    {
      auto sp = sop.find_first_of(" \t");
      if (sp != std::string::npos) sop = sop.substr(0, sp);
    }
    std::string fam = ln.substr(fp + 7);
    {
      auto sp = fam.find_first_of(" \t\r\n");
      if (sp != std::string::npos) fam = fam.substr(0, sp);
    }
    if (fam.empty()) continue;
    uint16_t op = (uint16_t)strtoul(sop.c_str(), nullptr, 16);
    out[op] = fam;
  }
  return out;
}

// Build the op->family map. `microvm_text` = the decode log / opmap.log. If it
// carries deterministic `OPMAP op= family=` rows (VARDOGER_STATIC_OPMAP), those
// are authoritative. Otherwise fall back to the dynamic MICROVM `md_classify`
// path (its rows are the PRIMARY source) + the DLV
// `->N` branch union and value-fit/arity fallback for ops with NO MICROVM row.
inline std::map<uint16_t, std::string> build_op_family(
    const std::vector<RawDlv>& all, const std::string& microvm_text) {
  // PREFER the static OPMAP map when present, authoritative, deterministic,
  // noise-free. The driver withholds OPMAP rows when its own degeneracy guard
  // tripped (leaving only a `# OPMAP-DEGENERATE` comment parse_opmap ignores),
  // so a non-empty opmap here is already vetted. A belt-and-suspenders
  // family-concentration check keeps a collapsed map (>60% one family) from
  // poisoning the rebuild.
  std::map<uint16_t, std::string> opmap = parse_opmap(microvm_text);
  if (!opmap.empty()) {
    std::map<std::string, int> fc;
    for (auto& kv : opmap) fc[kv.second]++;
    int mx = 0;
    for (auto& kv : fc) mx = std::max(mx, kv.second);
    if ((double)mx / (double)opmap.size() > 0.60)
      opmap.clear();  // degenerate -> fall through to dynamic
  }
  if (!opmap.empty()) {
    // Union the empirical DLV `->N` branch signal onto ops the static map left
    // as nop/goto (a real observed branch target is a genuine control-flow op
    // even if the static shape read as a fetch).
    for (const auto& r : all) {
      if (r.op == 0xffff || !r.has_tgt) continue;
      auto it = opmap.find(r.op);
      if (it == opmap.end() || it->second == "nop/goto")
        opmap[r.op] = (r.reads.size() >= 2) ? "if-cmp" : "if-testz";
    }
    return opmap;
  }
  std::map<uint16_t, MicrovmRow> rows = md_parse_static(microvm_text);
  std::map<uint16_t, std::string> out =
      md_classify(rows);  // primary (may be empty if no MICROVM rows)

  // Collect empirical DLV signal per op (branch via ->N + value-fit/arity for
  // the fallback path).
  struct Agg {
    bool branch = false, has_pool = false, has_write = false;
    std::multiset<int> read_counts;
    long n_reads_samples = 0;
    long fit_total = 0, fit_add = 0, fit_sub = 0, fit_and = 0, fit_or = 0,
         fit_xor = 0, rw_move = 0;
  };
  std::map<uint16_t, Agg> A;
  for (const auto& r : all) {
    if (r.op == 0xffff) continue;
    Agg& a = A[r.op];
    if (r.has_tgt) a.branch = true;
    if (r.has_pool || r.has_fetch) a.has_pool = true;
    int nr = (int)r.reads.size(), nw = (int)r.writes.size();
    a.read_counts.insert(nr);
    if (nr) a.n_reads_samples++;
    if (nw) a.has_write = true;
    if (nr >= 2 && nw >= 1) {
      int64_t rA = r.reads[0].val, rB = r.reads[1].val, w = r.writes[0].val;
      a.fit_total++;
      if (w == (int64_t)((uint64_t)rA + (uint64_t)rB)) a.fit_add++;
      if (w == (int64_t)((uint64_t)rA - (uint64_t)rB)) a.fit_sub++;
      if (w == (rA & rB)) a.fit_and++;
      if (w == (rA | rB)) a.fit_or++;
      if (w == (rA ^ rB)) a.fit_xor++;
    }
    if (nr == 1 && nw == 1) a.rw_move++;
  }
  // Union the empirical branch onto the MICROVM map + fill ops with no MICROVM
  // row from the DLV fallback.
  for (const auto& kv : A) {
    const Agg& a = kv.second;
    auto it = out.find(kv.first);
    bool has_row = (it != out.end());
    // Empirical ->N branch override, but ONLY when MICROVM has no CONFIDENT
    // opinion (no row, or it classified the op nop/goto). A confident MICROVM
    // class (arith/invoke/move/const/ref) is authoritative, otherwise a single
    // spurious ->N on a common op flips ALL its instances to if-eq (root cause
    // of the all-if-eq One+Line output; MICROVM's sxth-based branch detect is
    // reliable).
    if (a.branch) {
      bool confident =
          has_row &&
          it->second != "nop/goto";  // MICROVM confidently classified it
      if (!confident) {
        int max_reads = a.read_counts.empty() ? 0 : *a.read_counts.rbegin();
        out[kv.first] = (max_reads >= 2) ? "if-cmp" : "if-testz";
        continue;
      }
    }
    if (has_row) continue;  // MICROVM row already classified this op, keep it.
    // No MICROVM row: DLV value-fit / arity fallback.
    if (a.has_pool) {
      out[kv.first] = a.has_write ? "invoke" : "ref-op";
      continue;
    }
    if (a.fit_total >= 2) {
      auto dom = [&](long c) { return c == a.fit_total; };
      if (dom(a.fit_add))
        out[kv.first] = "add";
      else if (dom(a.fit_sub))
        out[kv.first] = "sub";
      else if (dom(a.fit_and))
        out[kv.first] = "and";
      else if (dom(a.fit_or))
        out[kv.first] = "orr";
      else if (dom(a.fit_xor))
        out[kv.first] = "eor";
      else
        out[kv.first] = "binary-int";
      continue;
    }
    if (a.rw_move > 0)
      out[kv.first] = "move";
    else if (a.has_write)
      out[kv.first] = "const";
    else
      out[kv.first] = "nop/goto";
  }
  return out;
}

// ---- DEX method index (port of _dex_method_index)
// -------------------------------------------------
struct DexIndex {
  // (classDesc, name, sig) -> global method_idx
  std::map<std::tuple<std::string, std::string, std::string>, uint32_t> mid;
  std::map<uint32_t, uint32_t> acc;  // method_idx -> access_flags
  std::set<std::string> classes;     // class descriptors present in this DEX
};

inline uint32_t rd_u32(const std::vector<uint8_t>& d, size_t o) {
  uint32_t v;
  std::memcpy(&v, d.data() + o, 4);
  return v;
}
inline uint16_t rd_u16(const std::vector<uint8_t>& d, size_t o) {
  uint16_t v;
  std::memcpy(&v, d.data() + o, 2);
  return v;
}
inline uint32_t rd_uleb(const std::vector<uint8_t>& d, size_t& p) {
  uint32_t r = 0;
  int s = 0;
  while (p < d.size()) {
    uint8_t b = d[p++];
    r |= uint32_t(b & 0x7f) << s;
    if (!(b & 0x80)) break;
    s += 7;
  }
  return r;
}

// Tiny SHA-1 (DEX signature = SHA-1 over bytes[0x20:]), used only to VERIFY
// the rebuilt DEX.
inline void sha1(const uint8_t* data, size_t len, uint8_t out[20]) {
  uint32_t h[5] = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u,
                   0xC3D2E1F0u};
  auto rol = [](uint32_t v, int c) { return (v << c) | (v >> (32 - c)); };
  auto blk = [&](const uint8_t* p) {
    uint32_t w[80];
    for (int i = 0; i < 16; ++i)
      w[i] = (p[i * 4] << 24) | (p[i * 4 + 1] << 16) | (p[i * 4 + 2] << 8) |
             p[i * 4 + 3];
    for (int i = 16; i < 80; ++i)
      w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (int i = 0; i < 80; ++i) {
      uint32_t f, k;
      if (i < 20) {
        f = (b & c) | (~b & d);
        k = 0x5A827999u;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = 0x6ED9EBA1u;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8F1BBCDCu;
      } else {
        f = b ^ c ^ d;
        k = 0xCA62C1D6u;
      }
      uint32_t t = rol(a, 5) + f + e + k + w[i];
      e = d;
      d = c;
      c = rol(b, 30);
      b = a;
      a = t;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
  };
  std::vector<uint8_t> m(data, data + len);
  uint64_t bits = (uint64_t)len * 8;
  m.push_back(0x80);
  while (m.size() % 64 != 56) m.push_back(0);
  for (int i = 0; i < 8; ++i) m.push_back(uint8_t(bits >> (56 - i * 8)));
  for (size_t i = 0; i < m.size(); i += 64) blk(m.data() + i);
  for (int i = 0; i < 5; ++i) {
    out[i * 4] = h[i] >> 24;
    out[i * 4 + 1] = h[i] >> 16;
    out[i * 4 + 2] = h[i] >> 8;
    out[i * 4 + 3] = h[i];
  }
}

inline DexIndex dex_method_index(const std::vector<uint8_t>& d) {
  DexIndex ix;
  if (d.size() < 0x70) return ix;
  uint32_t sids = rd_u32(d, 0x3c);
  uint32_t tids = rd_u32(d, 0x44);
  uint32_t pids = rd_u32(d, 0x4c);
  uint32_t mids_sz = rd_u32(d, 0x58), mids = rd_u32(d, 0x5c);
  uint32_t cdefs_sz = rd_u32(d, 0x60), cdefs = rd_u32(d, 0x64);

  auto stri = [&](uint32_t i) -> std::string {
    size_t off = rd_u32(d, sids + i * 4);
    (void)rd_uleb(
        d, off);  // string length (utf16 units), we read raw bytes to the NUL
    // MUTF-8 string ends at NUL; read to the terminator.
    std::string s;
    while (off < d.size() && d[off] != 0) {
      s.push_back((char)d[off]);
      ++off;
    }
    return s;
  };
  auto typ = [&](uint32_t i) -> std::string {
    return stri(rd_u32(d, tids + i * 4));
  };
  auto proto_sig = [&](uint32_t pi) -> std::string {
    size_t o = pids + (size_t)pi * 12;
    std::string ret = typ(rd_u32(d, o + 4));
    uint32_t poff = rd_u32(d, o + 8);
    std::string params;
    if (poff) {
      uint32_t n = rd_u32(d, poff);
      for (uint32_t k = 0; k < n; ++k)
        params += typ(rd_u16(d, poff + 4 + k * 2));
    }
    return "(" + params + ")" + ret;
  };
  for (uint32_t i = 0; i < mids_sz; ++i) {
    size_t o = mids + (size_t)i * 8;
    std::string cls = typ(rd_u16(d, o));
    std::string nm = stri(rd_u32(d, o + 4));
    std::string sig = proto_sig(rd_u16(d, o + 2));
    ix.mid[std::make_tuple(cls, nm, sig)] = i;
  }
  for (uint32_t i = 0; i < cdefs_sz; ++i) {
    size_t base = cdefs + (size_t)i * 32;
    ix.classes.insert(typ(rd_u32(d, base)));
    uint32_t cdata = rd_u32(d, base + 24);
    if (!cdata) continue;
    size_t p = cdata;
    uint32_t sf = rd_uleb(d, p), ifld = rd_uleb(d, p), dm = rd_uleb(d, p),
             vm = rd_uleb(d, p);
    for (uint32_t k = 0; k < sf + ifld; ++k) {
      rd_uleb(d, p);
      rd_uleb(d, p);
    }
    for (uint32_t grp = 0; grp < 2; ++grp) {
      uint32_t cnt = grp == 0 ? dm : vm;
      uint32_t midx = 0;
      for (uint32_t k = 0; k < cnt; ++k) {
        uint32_t di = rd_uleb(d, p), a = rd_uleb(d, p);
        rd_uleb(d, p);
        midx += di;
        ix.acc[midx] = a;
      }
    }
  }
  return ix;
}

// ---- decode-log parsing
// ----------------------------------------------------------------------------
inline std::string extract_field(const std::string& line,
                                 const std::string& key) {
  // key like "cls=" ; value is up to next whitespace
  auto pos = line.find(key);
  if (pos == std::string::npos) return "";
  pos += key.size();
  auto end = line.find_first_of(" \t", pos);
  return line.substr(pos,
                     end == std::string::npos ? std::string::npos : end - pos);
}

// Parse a "DLV p=.. op=0x.. len=.. raw=0x.. [ ->N ]" line. Returns false if not
// a DLV line.
inline bool parse_dlv(const std::string& line, RawDlv& out) {
  if (line.rfind("DLV ", 0) != 0) return false;
  std::string sp = extract_field(line, "p=");
  std::string sop = extract_field(line, "op=");
  std::string sraw = extract_field(line, "raw=");
  if (sp.empty() || sop.empty() || sraw.empty()) return false;
  out.p = (int)strtol(sp.c_str(), nullptr, 10);
  out.op = (uint16_t)strtoul(sop.c_str(), nullptr, 16);
  out.raw = (uint32_t)strtoul(sraw.c_str(), nullptr, 16);
  out.has_tgt = false;
  out.tgt = 0;
  out.reads.clear();
  out.writes.clear();
  out.has_pool = false;
  out.pool = 0;
  out.has_fetch = false;
  auto arrow = line.find("->");
  if (arrow != std::string::npos) {
    const char* c = line.c_str() + arrow + 2;
    char* endp = nullptr;
    long t = strtol(c, &endp, 10);
    if (endp != c) {
      out.has_tgt = true;
      out.tgt = (int)t;
    }
  }
  // Optional r{vA=0x.. vB=0x..} / w{vC=0x..}: parse "vN=VAL" pairs inside each
  // group.
  auto parse_grp = [&](char which, std::vector<RwPair>& into) {
    std::string tag = std::string(1, which) + "{";
    auto pos = line.find(tag);
    if (pos == std::string::npos) return;
    auto close = line.find('}', pos);
    if (close == std::string::npos) return;
    std::string body = line.substr(pos + tag.size(), close - pos - tag.size());
    size_t i = 0;
    while ((i = body.find('v', i)) != std::string::npos) {
      size_t eq = body.find('=', i);
      if (eq == std::string::npos) break;
      int reg = (int)strtol(body.c_str() + i + 1, nullptr, 10);
      int64_t val = (int64_t)strtoll(body.c_str() + eq + 1, nullptr, 0);
      into.push_back({reg, val});
      i = eq + 1;
    }
  };
  parse_grp('r', out.reads);
  parse_grp('w', out.writes);
  std::string spool = extract_field(line, "pool=");
  if (!spool.empty()) {
    out.has_pool = true;
    out.pool = (int)strtol(spool.c_str(), nullptr, 0);
  }
  if (line.find("fetch{") != std::string::npos) out.has_fetch = true;
  return true;
}

// ---- _md_decode_method port
// -----------------------------------------------------------------------
inline std::vector<VmInstr> md_decode_method(
    const MethodBlock& blk, const std::map<uint16_t, std::string>& cls) {
  // Collect non-skip (op != 0xffff) DLV rows.
  std::vector<RawDlv> real;
  for (const auto& s : blk.dlv)
    if (s.op != 0xffff) real.push_back(s);
  std::map<int, int> p2i;
  for (size_t i = 0; i < real.size(); ++i) p2i[real[i].p] = (int)i;

  std::vector<VmInstr> dec;
  for (const auto& s : real) {
    auto fit = cls.find(s.op);
    std::string fam = (fit == cls.end()) ? "?" : fit->second;
    uint32_t hi = s.raw >> 8;
    std::string base = fam_base(fam);
    VmInstr d;
    d.op = s.op;
    d.family = fam;
    if (s.has_tgt) {
      auto pit = p2i.find(s.tgt);
      if (pit != p2i.end()) {
        d.has_target = true;
        d.target = pit->second;
      }
    }
    if (fam == "invoke" || str_contains(fam, "ref") || fam == "const/ref") {
      d.has_pool = true;
      d.pool = (int)hi;
      d.vregs = {(int)(hi & 0xf)};
    } else if (md_alu().count(base) || fam == "binary-int") {
      d.vregs = {(int)(hi & 0xf), (int)((hi >> 4) & 0xf),
                 (int)((hi >> 8) & 0xf)};
    } else if (str_contains(fam, "move")) {
      d.vregs = {(int)(hi & 0xf), (int)((hi >> 4) & 0xf)};
    } else if (str_contains(fam, "if-")) {
      d.vregs = {(int)(hi & 0xf), (int)((hi >> 4) & 0xf)};
    } else if (fam == "const") {
      d.vregs = {(int)(hi & 0xf)};
      d.has_lit = true;
      d.lit = (int)(hi >> 4);
    }
    dec.push_back(d);
  }
  // Sanitize branch targets (the do-while fix).
  int n = (int)dec.size();
  for (int i = 0; i < n; ++i) {
    VmInstr& d = dec[i];
    const std::string& fam = d.family;
    bool is_if = str_contains(fam, "if-");
    bool is_goto =
        (fam == "nop/goto" || fam == "nop" || fam == "goto" ||
         (fam.size() >= 4 && fam.compare(fam.size() - 4, 4, "goto") == 0));
    if (!(is_if || is_goto)) continue;
    bool ok = d.has_target && d.target >= 0 && d.target < n && d.target != i;
    if (ok) continue;
    if (is_if && i + 1 < n) {
      d.has_target = true;
      d.target = i + 1;
    }  // fall through
    else {
      d.family = "nop";
      d.has_target = false;
    }  // unresolved goto -> nop
  }
  return dec;
}

// Return descriptor of a sig "(...)<ret>".
inline std::string sig_ret(const std::string& sig) {
  auto close = sig.find(')');
  if (close == std::string::npos || close + 1 >= sig.size()) return "V";
  return sig.substr(close + 1);
}

// A minimal VALID Dalvik body for a return descriptor (port of _minimal_body):
// (regs, insn units). Used to de-nativize matched-but-UNCOVERED protected
// methods (no recovered bytecode) so ART does not reject a native method with
// no implementation, mirrors the python --rebuild-dex stub behavior.
inline std::pair<uint16_t, std::vector<uint16_t>> minimal_body(
    const std::string& ret, uint16_t ins) {
  if (ret == "V") return {std::max<uint16_t>(ins, 1), {0x000e}};  // return-void
  if (ret == "J" || ret == "D")
    return {std::max<uint16_t>(ins, 2),
            {0x0016, 0x0000, 0x0010}};  // const-wide/16 v0,0; return-wide v0
  if (!ret.empty() && (ret[0] == 'L' || ret[0] == '['))
    return {std::max<uint16_t>(ins, 1),
            {0x0012, 0x0011}};  // const/4 v0,0; return-object v0
  return {std::max<uint16_t>(ins, 1),
          {0x0012, 0x000f}};  // const/4 v0,0; return v0
}

// ins = argument register count from the sig (each param 1 reg; J/D = 2; +1 for
// `this` if not static).
inline uint16_t sig_ins(const std::string& sig, bool is_static) {
  auto close = sig.find(')');
  std::string params =
      (sig.size() && sig[0] == '(' && close != std::string::npos)
          ? sig.substr(1, close - 1)
          : "";
  uint16_t n = is_static ? 0 : 1;
  for (size_t i = 0; i < params.size();) {
    char c = params[i];
    if (c == 'L') {
      while (i < params.size() && params[i] != ';') ++i;
      ++i;
      n += 1;
    } else if (c == '[') {
      ++i; /* array: skip dims then one element -> still 1 reg */
      while (i < params.size() && params[i] == '[') ++i;
      if (i < params.size() && params[i] == 'L') {
        while (i < params.size() && params[i] != ';') ++i;
      }
      ++i;
      n += 1;
    } else if (c == 'J' || c == 'D') {
      ++i;
      n += 2;
    } else {
      ++i;
      n += 1;
    }
  }
  return n;
}

}  // namespace devirt_detail

// ---------------------------------------------------------------------------------------------------
// Native devirt rebuilder. Parses the decode log, aggregates the op-map,
// decodes+assembles each method, resolves (cls,name,sig) -> method_idx per DEX
// (matching the DEX that actually holds the class), relinks via DexRebuilder,
// writes each DEX, and verifies sig+checksum.
inline std::vector<DevirtResult> devirt_rebuild(
    const std::string& decode_log, const std::vector<std::string>& dex_paths,
    const std::string& out_dir) {
  using namespace devirt_detail;
  std::vector<DevirtResult> results;

  // 1. Parse the log into method blocks.
  std::ifstream in(decode_log);
  if (!in) {
    std::fprintf(stderr, "    [rebuild] cannot open %s\n", decode_log.c_str());
    return results;
  }
  std::vector<MethodBlock> blocks;
  std::vector<RawDlv>
      all_dlv;  // every DLV record, for build_op_family aggregation
  std::string microvm_text;  // the MICROVM op= rows (primary op->family source)
  {
    std::string line;
    MethodBlock* cur = nullptr;
    bool have = false;
    while (std::getline(in, line)) {
      if (line.find("MICROVM op=") != std::string::npos ||
          line.find("OPMAP op=") != std::string::npos) {
        microvm_text += line;
        microvm_text += '\n';
        continue;
      }
      if (line.rfind("==METHOD==", 0) == 0) {
        std::string cls = extract_field(line, "cls=");
        std::string name = extract_field(line, "name=");
        std::string sig = extract_field(line, "sig=");
        blocks.emplace_back();
        cur = &blocks.back();
        have = true;
        cur->cls = cls;
        cur->name = name;
        cur->sig = sig;
        continue;
      }
      RawDlv dv;
      if (parse_dlv(line, dv)) {
        if (have && cur) cur->dlv.push_back(dv);
        if (dv.op != 0xffff) all_dlv.push_back(dv);
      }
    }
  }
  // The driver writes the 256 MICROVM op-map rows to <out_dir>/opmap.log to
  // keep them off the terminal; the decode.log only carries them under
  // VARDOGER_VERBOSE. Read opmap.log when the log had none.
  if (microvm_text.empty() && !out_dir.empty()) {
    std::ifstream om(out_dir + "/opmap.log");
    std::string l;
    while (std::getline(om, l))
      if (l.find("MICROVM op=") != std::string::npos ||
          l.find("OPMAP op=") != std::string::npos) {
        microvm_text += l;
        microvm_text += '\n';
      }
  }
  const size_t total = blocks.size();

  // 2. Build the op -> family map: MICROVM rows (primary) + empirical ->N
  // branch union + DLV fallback.
  std::map<uint16_t, std::string> opcls =
      build_op_family(all_dlv, microvm_text);

  // 3. Decode + assemble each method's Dalvik body (bucket by class for later
  // DEX assignment).
  struct Decoded {
    std::string cls, name, sig;
    std::vector<uint16_t> units;
    bool covered = false;
  };
  std::vector<Decoded> decoded;
  decoded.reserve(blocks.size());
  for (const auto& blk : blocks) {
    if (blk.cls.empty() || blk.name.empty() || blk.cls == "?" ||
        blk.name == "?") {
      decoded.push_back({});
      continue;
    }
    Decoded dc;
    dc.cls = "L" + blk.cls + ";";
    dc.name = blk.name;
    dc.sig = blk.sig;
    std::vector<VmInstr> vm =
        md_decode_method(blk, opcls);  // empty -> uncovered (all-0xffff DLV)
    if (!vm.empty()) {
      std::vector<DalvikInstr> di;
      di.reserve(vm.size());
      for (const auto& v : vm) di.push_back(md_to_dalvik(v));
      dc.units = md_assemble(di);
      dc.covered = true;
    }
    decoded.push_back(std::move(dc));
  }

  // 4. Per DEX: load, index, relink the methods whose class lives in THIS dex,
  // write + verify.
  size_t rebuilt_running = 0;  // progress across all dexes
  for (const auto& dpath : dex_paths) {
    std::ifstream df(dpath, std::ios::binary);
    if (!df) {
      std::fprintf(stderr, "    [rebuild] cannot open %s\n", dpath.c_str());
      continue;
    }
    std::vector<uint8_t> dex((std::istreambuf_iterator<char>(df)),
                             std::istreambuf_iterator<char>());
    DexIndex ix = dex_method_index(dex);
    DexRebuilder rb(dex);

    size_t built = 0, skipped = 0, real_bodies = 0;
    for (const auto& dc : decoded) {
      if (dc.cls.empty()) {
        ++skipped;
        continue;
      }  // cls=?/name=? block
      if (!ix.classes.count(dc.cls))
        continue;  // class not in this DEX -> a later DEX owns it
      auto it = ix.mid.find(std::make_tuple(dc.cls, dc.name, dc.sig));
      if (it == ix.mid.end()) {
        ++skipped;
        continue;
      }
      uint32_t midx = it->second;
      auto af = ix.acc.find(midx);
      if (af == ix.acc.end() || !(af->second & 0x100)) {
        ++skipped;
        continue;
      }  // not ACC_NATIVE

      bool is_static = (af->second & 0x8) != 0;
      uint16_t ins = sig_ins(dc.sig, is_static);
      std::vector<uint16_t> units;
      uint16_t regs;
      if (dc.covered) {
        // Recovered body. Our encoders only ever emit v0..v15 (nibble-limited
        // operands), so a 16-register frame covers every body, matching
        // python's fixed 16.
        units = dc.units;
        regs = std::max<uint16_t>(16, ins);
        ++real_bodies;
      } else {
        // Matched but UNCOVERED (all-0xffff DLV) -> minimal stub so the method
        // de-nativizes and ART accepts it (mirrors python --rebuild-dex; keeps
        // the DEX loadable).
        auto mb = minimal_body(sig_ret(dc.sig), ins);
        regs = mb.first;
        units = mb.second;
      }
      uint16_t outs = 5;  // invoke-virtual uses up to 5 arg regs
      rb.set_code(midx, DexRebuilder::make_code_item(regs, ins, outs, units));
      ++built;
      ++rebuilt_running;
      std::printf("\r    [rebuild] %zu/%zu methods  built=%zu skip=%zu",
                  rebuilt_running, total, rebuilt_running, skipped);
      std::fflush(stdout);
    }
    (void)real_bodies;

    std::vector<uint8_t> outdex = rb.build();
    DevirtResult res;
    // Write into out_dir under the source basename.
    std::string base = dpath;
    auto slash = base.find_last_of("/\\");
    if (slash != std::string::npos) base = base.substr(slash + 1);
    res.path = out_dir + "/" + base;
    res.total = total;
    res.built =
        rb.patched_methods();  // methods actually de-nativized in the DEX
    res.skipped = skipped;

    if (!outdex.empty()) {
      std::ofstream of(res.path, std::ios::binary);
      of.write((const char*)outdex.data(), (std::streamsize)outdex.size());
      of.close();
      // Verify sha1(bytes[32:]) == bytes[12:32] and adler32(bytes[12:]) ==
      // u32@8.
      if (outdex.size() >= 0x20) {
        uint8_t sig[20];
        devirt_detail::sha1(outdex.data() + 0x20, outdex.size() - 0x20, sig);
        res.sig_ok = std::memcmp(sig, outdex.data() + 0x0c, 20) == 0;
        uint32_t stored;
        std::memcpy(&stored, outdex.data() + 8, 4);
        uint32_t got = (uint32_t)adler32(1L, outdex.data() + 0x0c,
                                         (uInt)(outdex.size() - 0x0c));
        res.csum_ok = (stored == got);
      }
    }
    results.push_back(res);
    (void)built;
  }
  size_t total_skipped = 0;
  for (const auto& r : results) total_skipped += r.skipped;
  std::printf("\r    [rebuild] %zu/%zu methods  built=%zu skip=%zu\n", total,
              total, rebuilt_running, total_skipped);
  return results;
}

}  // namespace vardoger
