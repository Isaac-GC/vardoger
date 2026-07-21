// vardoger: minimal Dalvik interpreter (see include/vardoger/dex/dalvik.hpp).
#include "vardoger/dex/dalvik.hpp"

#include <cstdio>
#include <cstring>

namespace vardoger {
namespace {
inline uint16_t u16(const std::vector<uint8_t>& d, uint32_t off) {
  uint16_t v = 0;
  if (off + 2 <= d.size()) std::memcpy(&v, d.data() + off, 2);
  return v;
}
inline uint32_t u32(const std::vector<uint8_t>& d, uint32_t off) {
  uint32_t v = 0;
  if (off + 4 <= d.size()) std::memcpy(&v, d.data() + off, 4);
  return v;
}
}  // namespace

uint64_t Dalvik::run(const DexFile::Code& code,
                     const std::vector<uint64_t>& args,
                     const std::string& dbg) {
  if (!code.valid || depth_ >= max_depth) return 0;
  ++depth_;
  const auto& d = dex_.bytes();
  std::vector<uint64_t> R(code.registers_size ? code.registers_size : 1, 0);
  // params occupy the last ins_size registers
  for (size_t i = 0; i < args.size() && i < code.ins_size; ++i)
    R[code.registers_size - code.ins_size + i] = args[i];

  const uint32_t base = code.insns_off;
  uint32_t pc = 0;  // in code units (u16)
  uint64_t ret = 0;
  auto at = [&](uint32_t unit) { return base + unit * 2; };
  // integer binop by family index (0=add 1=sub 2=mul 3=div 4=rem 5=and 6=or
  // 7=xor 8=shl 9=shr 10=ushr)
  auto ibin = [](int k, int64_t a, int64_t b) -> uint64_t {
    switch (k) {
      case 0:
        return uint64_t(a + b);
      case 1:
        return uint64_t(a - b);
      case 2:
        return uint64_t(a * b);
      case 3:
        return uint64_t(b ? a / b : 0);
      case 4:
        return uint64_t(b ? a % b : 0);
      case 5:
        return uint64_t(a & b);
      case 6:
        return uint64_t(a | b);
      case 7:
        return uint64_t(a ^ b);
      case 8:
        return uint64_t(a << (b & 63));
      case 9:
        return uint64_t(a >> (b & 63));
      case 10:
        return uint64_t(uint64_t(a) >> (b & 63));
    }
    return 0;
  };
  // lit16/lit8: 0xd0/0xd8 add, (0xd1/0xd9 rsub handled inline),
  // mul,div,rem,and,or,xor[,shl,shr,ushr]
  auto lit16_kind = [](uint8_t op) -> int {
    static const int m[8] = {0, 1, 2, 3, 4, 5, 6, 7};
    return m[op - 0xd0];
  };
  auto lit8_kind = [](uint8_t op) -> int {
    static const int m[11] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    return m[op - 0xd8];
  };

  for (int steps = 0; steps < 200000; ++steps) {
    if (pc >= code.insns_size) break;
    const uint32_t iaddr = at(pc);
    const uint8_t op = d[iaddr] & 0xff;
    const uint8_t b1 = (iaddr + 1 < d.size()) ? d[iaddr + 1] : 0;
    if (trace)
      std::fprintf(stderr, "   [dvk %s pc=%u op=%02x]\n", dbg.c_str(), pc, op);
    switch (op) {
      case 0x00:
        pc += 1;
        break;  // nop
      case 0x01:
        R[b1 & 0xf] = R[b1 >> 4];
        pc += 1;
        break;  // move
      case 0x04:
        R[b1 & 0xf] = R[b1 >> 4];
        pc += 1;
        break;  // move-wide (approx)
      case 0x07:
        R[b1 & 0xf] = R[b1 >> 4];
        pc += 1;
        break;  // move-object
      case 0x0a:
      case 0x0b:
      case 0x0c:
        R[b1] = ret;
        pc += 1;
        break;  // move-result / -wide / -object
      case 0x0e:
        --depth_;
        return 0;  // return-void
      case 0x0f:
      case 0x10:
      case 0x11:
        --depth_;
        return R[b1];  // return / -wide / -object
      case 0x12: {
        int8_t v = int8_t((b1 >> 4) << 4) >> 4;
        R[b1 & 0xf] = uint64_t(int64_t(v));
        pc += 1;
        break;
      }  // const/4
      case 0x13:
        R[b1] = uint64_t(int64_t(int16_t(u16(d, iaddr + 2))));
        pc += 2;
        break;  // const/16
      case 0x14:
        R[b1] = uint64_t(int64_t(int32_t(u32(d, iaddr + 2))));
        pc += 3;
        break;  // const
      case 0x15:
        R[b1] = uint64_t(int64_t(int16_t(u16(d, iaddr + 2))) << 16);
        pc += 2;
        break;  // const/high16
      case 0x1a:
        R[b1] = on_const_string ? on_const_string(u16(d, iaddr + 2)) : 0;
        pc += 2;
        break;  // const-string
      case 0x1b:
        R[b1] = on_const_string ? on_const_string(u32(d, iaddr + 2)) : 0;
        pc += 3;
        break;  // const-string/jumbo
      case 0x1c:
        R[b1] = 0;
        pc += 2;
        break;  // const-class (slot 0; not needed yet)
      case 0x1f:
        pc += 2;
        break;  // check-cast (no-op: types are opaque)
      case 0x22:
        R[b1] = on_new_instance ? on_new_instance(u16(d, iaddr + 2)) : 0;
        pc += 2;
        break;  // new-instance
      case 0x28: {
        int8_t off = int8_t(b1);
        if (!off) {
          --depth_;
          return ret;
        }
        pc += off;
        break;
      }  // goto
      case 0x29: {
        int16_t off = int16_t(u16(d, iaddr + 2));
        pc += off ? off : 2;
        break;
      }  // goto/16
      // if-testz vAA, +BBBB  (0x38 eqz .. 0x3d lez)
      case 0x38:
      case 0x39:
      case 0x3a:
      case 0x3b:
      case 0x3c:
      case 0x3d: {
        int16_t off = int16_t(u16(d, iaddr + 2));
        int64_t a = int64_t(R[b1]);
        bool t = false;
        switch (op) {
          case 0x38:
            t = a == 0;
            break;
          case 0x39:
            t = a != 0;
            break;
          case 0x3a:
            t = a < 0;
            break;
          case 0x3b:
            t = a >= 0;
            break;
          case 0x3c:
            t = a > 0;
            break;
          case 0x3d:
            t = a <= 0;
            break;
        }
        pc += t ? (off ? off : 2) : 2;
        break;
      }
      // if-test vA,vB, +CCCC (0x32 eq .. 0x37 le)
      case 0x32:
      case 0x33:
      case 0x34:
      case 0x35:
      case 0x36:
      case 0x37: {
        int16_t off = int16_t(u16(d, iaddr + 2));
        int64_t a = int64_t(R[b1 & 0xf]), bb = int64_t(R[b1 >> 4]);
        bool t = false;
        switch (op) {
          case 0x32:
            t = a == bb;
            break;
          case 0x33:
            t = a != bb;
            break;
          case 0x34:
            t = a < bb;
            break;
          case 0x35:
            t = a >= bb;
            break;
          case 0x36:
            t = a > bb;
            break;
          case 0x37:
            t = a <= bb;
            break;
        }
        pc += t ? (off ? off : 2) : 2;
        break;
      }
      // ── move variants /from16 (2 units) and /16 (3 units) ──
      case 0x02:
      case 0x05:
      case 0x08:
        R[b1] = R[u16(d, iaddr + 2)];
        pc += 2;
        break;  // move*/from16 vAA, vBBBB
      case 0x03:
      case 0x06:
      case 0x09:
        R[u16(d, iaddr + 2)] = R[u16(d, iaddr + 4)];
        pc += 3;
        break;  // move*/16
      // ── const-wide family ──
      case 0x16:
        R[b1] = uint64_t(int64_t(int16_t(u16(d, iaddr + 2))));
        pc += 2;
        break;  // const-wide/16
      case 0x17:
        R[b1] = uint64_t(int64_t(int32_t(u32(d, iaddr + 2))));
        pc += 3;
        break;  // const-wide/32
      case 0x18: {
        uint64_t v = 0;
        if (iaddr + 10 <= d.size()) std::memcpy(&v, d.data() + iaddr + 2, 8);
        R[b1] = v;
        pc += 5;
        break;
      }  // const-wide
      case 0x19:
        R[b1] = uint64_t(int64_t(int16_t(u16(d, iaddr + 2))) << 48);
        pc += 2;
        break;  // const-wide/high16
      // ── monitor (no-op), instance-of, array-length, new-array ──
      case 0x1d:
      case 0x1e:
        pc += 1;
        break;  // monitor-enter/exit
      case 0x20:
        R[b1 & 0xf] = 1;
        pc += 2;
        break;  // instance-of (best-effort true)
      case 0x21:
        R[b1 & 0xf] = on_array_length
                          ? uint64_t(uint32_t(on_array_length(R[b1 >> 4])))
                          : 0;
        pc += 1;
        break;  // array-length
      case 0x23:
        R[b1 & 0xf] = on_new_array
                          ? on_new_array(u16(d, iaddr + 2), int32_t(R[b1 >> 4]))
                          : 0;
        pc += 2;
        break;  // new-array
      case 0x24:
        pc += 3;
        break;  // filled-new-array (result via move-result; leave ret)
      case 0x25:
        pc += 3;
        break;  // filled-new-array/range
      case 0x26:
        pc += 3;
        break;  // fill-array-data
      case 0x27:
        --depth_;
        return ret;  // throw: abort method
      case 0x2a: {
        int32_t off = int32_t(u32(d, iaddr + 2));
        pc += off ? off : 3;
        break;
      }  // goto/32
      case 0x2b:
      case 0x2c:
        pc += 3;
        break;  // packed/sparse-switch: fall through (approx)
      case 0x2d:
      case 0x2e:
      case 0x2f:
      case 0x30:
      case 0x31:  // cmp*/cmpl/cmpg (2 units): result 0
        R[b1] = 0;
        pc += 2;
        break;
      // ── aget* (0x44..0x4a) / aput* (0x4b..0x51): 23x vAA,vBB,vCC ──
      case 0x44:
      case 0x45:
      case 0x46:
      case 0x47:
      case 0x48:
      case 0x49:
      case 0x4a: {
        uint16_t bc = u16(d, iaddr + 2);
        uint8_t arr = bc & 0xff, idx = bc >> 8;
        R[b1] = on_aget ? on_aget(R[arr], int32_t(R[idx])) : 0;
        pc += 2;
        break;
      }
      case 0x4b:
      case 0x4c:
      case 0x4d:
      case 0x4e:
      case 0x4f:
      case 0x50:
      case 0x51: {
        uint16_t bc = u16(d, iaddr + 2);
        uint8_t arr = bc & 0xff, idx = bc >> 8;
        if (on_aput) on_aput(R[arr], int32_t(R[idx]), R[b1]);
        pc += 2;
        break;
      }
      // sget* vAA, field@BBBB (0x60..0x66); sput* (0x67..0x6d)
      case 0x60:
      case 0x61:
      case 0x62:
      case 0x63:
      case 0x64:
      case 0x65:
      case 0x66:
        R[b1] = on_sget ? on_sget(u16(d, iaddr + 2)) : 0;
        pc += 2;
        break;
      case 0x67:
      case 0x68:
      case 0x69:
      case 0x6a:
      case 0x6b:
      case 0x6c:
      case 0x6d:
        if (on_sput) on_sput(u16(d, iaddr + 2), R[b1]);
        pc += 2;
        break;
      // iget* vA,vB, field@CCCC (0x52..0x58); iput* (0x59..0x5f)
      case 0x52:
      case 0x53:
      case 0x54:
      case 0x55:
      case 0x56:
      case 0x57:
      case 0x58:
        R[b1 & 0xf] = on_iget ? on_iget(R[b1 >> 4], u16(d, iaddr + 2)) : 0;
        pc += 2;
        break;
      case 0x59:
      case 0x5a:
      case 0x5b:
      case 0x5c:
      case 0x5d:
      case 0x5e:
      case 0x5f:
        if (on_iput) on_iput(R[b1 >> 4], u16(d, iaddr + 2), R[b1 & 0xf]);
        pc += 2;
        break;
      // invoke-{virtual,super,direct,static,interface} (35c)
      case 0x6e:
      case 0x6f:
      case 0x70:
      case 0x71:
      case 0x72: {
        const uint8_t A = b1 >> 4;  // arg count
        const uint16_t midx = u16(d, iaddr + 2);
        const uint16_t regs = u16(d, iaddr + 4);  // C,D,E,F nibbles
        const uint8_t G = b1 & 0xf;
        uint8_t rv[5] = {uint8_t(regs & 0xf), uint8_t((regs >> 4) & 0xf),
                         uint8_t((regs >> 8) & 0xf),
                         uint8_t((regs >> 12) & 0xf), G};
        std::vector<uint64_t> a;
        for (int i = 0; i < A; ++i) a.push_back(R[rv[i]]);
        static const InvokeKind k[] = {InvokeKind::Virtual, InvokeKind::Super,
                                       InvokeKind::Direct, InvokeKind::Static,
                                       InvokeKind::Interface};
        ret = on_invoke ? on_invoke(k[op - 0x6e], midx, a) : 0;
        pc += 3;
        break;
      }
      // invoke-*/range (3rc)
      case 0x74:
      case 0x75:
      case 0x76:
      case 0x77:
      case 0x78: {
        const uint8_t A = b1;  // arg count
        const uint16_t midx = u16(d, iaddr + 2);
        const uint16_t cReg = u16(d, iaddr + 4);
        std::vector<uint64_t> a;
        for (int i = 0; i < A && (cReg + i) < R.size(); ++i)
          a.push_back(R[cReg + i]);
        static const InvokeKind k[] = {InvokeKind::Virtual, InvokeKind::Super,
                                       InvokeKind::Direct, InvokeKind::Static,
                                       InvokeKind::Interface};
        ret = on_invoke ? on_invoke(k[op - 0x74], midx, a) : 0;
        pc += 3;
        break;
      }
      // ── unop vA,vB (0x7b..0x8f, 12x) ──
      case 0x7b:
        R[b1 & 0xf] = uint64_t(-int64_t(int32_t(R[b1 >> 4])));
        pc += 1;
        break;  // neg-int
      case 0x7c:
        R[b1 & 0xf] = uint64_t(~int64_t(int32_t(R[b1 >> 4])));
        pc += 1;
        break;  // not-int
      case 0x7d:
        R[b1 & 0xf] = uint64_t(-int64_t(R[b1 >> 4]));
        pc += 1;
        break;  // neg-long
      case 0x7e:
        R[b1 & 0xf] = ~R[b1 >> 4];
        pc += 1;
        break;  // not-long
      case 0x81:
        R[b1 & 0xf] = uint64_t(int64_t(int32_t(R[b1 >> 4])));
        pc += 1;
        break;  // int-to-long
      case 0x84:
        R[b1 & 0xf] = uint64_t(int64_t(int32_t(R[b1 >> 4])));
        pc += 1;
        break;  // long-to-int
      case 0x8d:
        R[b1 & 0xf] = uint64_t(int64_t(int8_t(R[b1 >> 4])));
        pc += 1;
        break;  // int-to-byte
      case 0x8e:
        R[b1 & 0xf] = uint64_t(uint16_t(R[b1 >> 4]));
        pc += 1;
        break;  // int-to-char
      case 0x8f:
        R[b1 & 0xf] = uint64_t(int64_t(int16_t(R[b1 >> 4])));
        pc += 1;
        break;  // int-to-short
      case 0x7f:
      case 0x80:
      case 0x82:
      case 0x83:
      case 0x85:
      case 0x86:
      case 0x87:
      case 0x88:
      case 0x89:
      case 0x8a:
      case 0x8b:
      case 0x8c:
        R[b1 & 0xf] = R[b1 >> 4];
        pc += 1;
        break;  // other conversions: passthrough
      // ── binop vAA,vBB,vCC (0x90..0xaf, 23x) ──
      case 0x90:
      case 0x91:
      case 0x92:
      case 0x93:
      case 0x94:
      case 0x95:
      case 0x96:
      case 0x97:
      case 0x98:
      case 0x99:
      case 0x9a:
      case 0x9b:
      case 0x9c:
      case 0x9d:
      case 0x9e:
      case 0x9f:
      case 0xa0:
      case 0xa1:
      case 0xa2:
      case 0xa3:
      case 0xa4:
      case 0xa5:
      case 0xa6:
      case 0xa7:
      case 0xa8:
      case 0xa9:
      case 0xaa:
      case 0xab:
      case 0xac:
      case 0xad:
      case 0xae:
      case 0xaf: {
        uint16_t bc = u16(d, iaddr + 2);
        uint8_t rb = bc & 0xff, rc = bc >> 8;
        int kind = (op < 0x9b)   ? (op - 0x90)
                   : (op < 0xa6) ? (op - 0x9b)
                                 : (op - 0xa6);
        R[b1] = ibin(kind, int64_t(R[rb]), int64_t(R[rc]));
        pc += 2;
        break;
      }
      // ── binop/2addr vA,vB (0xb0..0xcf, 12x) ──
      case 0xb0:
      case 0xb1:
      case 0xb2:
      case 0xb3:
      case 0xb4:
      case 0xb5:
      case 0xb6:
      case 0xb7:
      case 0xb8:
      case 0xb9:
      case 0xba:
      case 0xbb:
      case 0xbc:
      case 0xbd:
      case 0xbe:
      case 0xbf:
      case 0xc0:
      case 0xc1:
      case 0xc2:
      case 0xc3:
      case 0xc4:
      case 0xc5:
      case 0xc6:
      case 0xc7:
      case 0xc8:
      case 0xc9:
      case 0xca:
      case 0xcb:
      case 0xcc:
      case 0xcd:
      case 0xce:
      case 0xcf: {
        int kind = (op < 0xbb)   ? (op - 0xb0)
                   : (op < 0xc6) ? (op - 0xbb)
                                 : (op - 0xc6);
        R[b1 & 0xf] = ibin(kind, int64_t(R[b1 & 0xf]), int64_t(R[b1 >> 4]));
        pc += 1;
        break;
      }
      // ── binop/lit16 vA,vB,#+CCCC (0xd0..0xd7, 22s) ──
      case 0xd0:
      case 0xd1:
      case 0xd2:
      case 0xd3:
      case 0xd4:
      case 0xd5:
      case 0xd6:
      case 0xd7: {
        int64_t lit = int16_t(u16(d, iaddr + 2));
        int64_t x = int64_t(int32_t(R[b1 >> 4]));
        int64_t r = (op == 0xd1) ? (lit - x) : ibin(lit16_kind(op), x, lit);
        R[b1 & 0xf] = r;
        pc += 2;
        break;
      }
      // ── binop/lit8 vAA,vBB,#+CC (0xd8..0xe2, 22b) ──
      case 0xd8:
      case 0xd9:
      case 0xda:
      case 0xdb:
      case 0xdc:
      case 0xdd:
      case 0xde:
      case 0xdf:
      case 0xe0:
      case 0xe1:
      case 0xe2: {
        uint16_t bc = u16(d, iaddr + 2);
        uint8_t rb = bc & 0xff;
        int64_t lit = int8_t(bc >> 8);
        int64_t x = int64_t(int32_t(R[rb]));
        int64_t r = (op == 0xd9) ? (lit - x) : ibin(lit8_kind(op), x, lit);
        R[b1] = r;
        pc += 2;
        break;
      }
      default:
        std::fprintf(stderr, "   [dvk] unsupported opcode 0x%02x @pc=%u (%s)\n",
                     op, pc, dbg.c_str());
        --depth_;
        return ret;
    }
  }
  --depth_;
  return ret;
}

}  // namespace vardoger
