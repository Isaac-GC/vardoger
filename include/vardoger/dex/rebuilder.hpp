// vardoger: DEX code rebuilder (de-nativize / relink recovered method bytecode
// into a DEX).
//
// Reusable across EXTRACTION-based packers (360 Jiagu SDK, and any packer that
// marks methods native/abstract and recovers their code_items at runtime).
// Strategy = APPEND-AND-REPOINT, so no existing offsets shift: recovered
// code_items and rebuilt class_data blocks are appended at EOF, and only the
// affected class_def.class_data_off pointers are repointed. For each recovered
// method the ACC_NATIVE flag is cleared and code_off is set. Header
// file_size/data_size, SHA-1 signature and Adler-32 checksum are recomputed.
// ART is lenient about the trailing appended region.
//
// Header-only (part of the core public API): any core module or sample driver
// may include it; the only external dependency is zlib's adler32 (already
// linked into vardoger_core), plus a tiny inline SHA-1.
#pragma once

#include <zlib.h>

#include <cstdint>
#include <cstring>
#include <map>
#include <vector>

namespace vardoger {

class DexRebuilder {
 public:
  explicit DexRebuilder(std::vector<uint8_t> dex) : d_(std::move(dex)) {}

  // Provide a recovered code_item for the method with this GLOBAL method_idx.
  // `code_item` is raw DEX code_item bytes: u16 registers_size, ins_size,
  // outs_size, tries_size; u32 debug_info_off, insns_size; u16[insns_size]
  // insns; (+ optional tries/handlers). Debug offset is typically 0.
  void set_code(uint32_t method_idx, std::vector<uint8_t> code_item) {
    recovered_[method_idx] = std::move(code_item);
  }
  bool has(uint32_t method_idx) const {
    return recovered_.count(method_idx) != 0;
  }
  size_t provided() const { return recovered_.size(); }

  size_t patched_methods() const { return patched_methods_; }
  size_t patched_classes() const { return patched_classes_; }
  const char* error() const { return err_; }

  // Convenience: assemble a code_item from a header + raw insns (units). tries
  // omitted.
  static std::vector<uint8_t> make_code_item(
      uint16_t regs, uint16_t ins, uint16_t outs,
      const std::vector<uint16_t>& insns) {
    std::vector<uint8_t> ci(16);
    std::memcpy(ci.data() + 0, &regs, 2);
    std::memcpy(ci.data() + 2, &ins, 2);
    std::memcpy(ci.data() + 4, &outs, 2);
    uint16_t tries = 0;
    std::memcpy(ci.data() + 6, &tries, 2);
    uint32_t dbg = 0;
    std::memcpy(ci.data() + 8, &dbg, 4);
    uint32_t isz = (uint32_t)insns.size();
    std::memcpy(ci.data() + 12, &isz, 4);
    for (uint16_t u : insns) {
      ci.push_back(u & 0xff);
      ci.push_back(u >> 8);
    }
    return ci;
  }

  // Build the relinked DEX. Returns the new bytes (empty on parse failure, see
  // error()).
  std::vector<uint8_t> build() {
    patched_methods_ = 0;
    patched_classes_ = 0;
    if (d_.size() < 0x70 || std::memcmp(d_.data(), "dex\n", 4) != 0) {
      err_ = "not a DEX";
      return {};
    }
    const uint32_t cd_size = rd32(0x60);  // class_defs_size
    const uint32_t cd_off = rd32(0x64);   // class_defs_off
    if (cd_off + (uint64_t)cd_size * 32 > d_.size()) {
      err_ = "bad class_defs";
      return {};
    }

    std::vector<uint8_t> tail;
    auto align4 = [&] {
      while ((d_.size() + tail.size()) % 4) tail.push_back(0);
    };

    // 1. append recovered code_items; remember their new file offsets by
    // method_idx.
    std::map<uint32_t, uint32_t> new_code_off;
    for (auto& kv : recovered_) {
      align4();
      new_code_off[kv.first] = (uint32_t)(d_.size() + tail.size());
      tail.insert(tail.end(), kv.second.begin(), kv.second.end());
    }
    // 2. per class_def: rebuild class_data (clear ACC_NATIVE + set code_off for
    // recovered methods),
    //    append it, repoint class_def.class_data_off.
    for (uint32_t i = 0; i < cd_size; ++i) {
      const size_t cdef = cd_off + (size_t)i * 32;
      const uint32_t cdo = rd32(cdef + 24);
      if (!cdo || cdo >= d_.size()) continue;
      size_t p = cdo;
      const uint32_t sf = uleb(p), sfld = uleb(p), dm = uleb(p), vm = uleb(p);
      std::vector<uint8_t> blk;
      wuleb(blk, sf);
      wuleb(blk, sfld);
      wuleb(blk, dm);
      wuleb(blk, vm);
      bool changed = false;
      auto copy_fields = [&](uint32_t n) {
        for (uint32_t k = 0; k < n; ++k) {
          uint32_t a = uleb(p), b = uleb(p);
          wuleb(blk, a);
          wuleb(blk, b);
        }
      };
      copy_fields(sf);
      copy_fields(sfld);
      for (uint32_t grp = 0; grp < 2; ++grp) {
        const uint32_t count = grp == 0 ? dm : vm;
        uint32_t midx = 0;
        for (uint32_t k = 0; k < count; ++k) {
          uint32_t diff = uleb(p), acc = uleb(p), coff = uleb(p);
          midx += diff;
          auto it = new_code_off.find(midx);
          if (it != new_code_off.end() && (acc & kAccNative)) {
            acc &= ~kAccNative;
            coff = it->second;
            changed = true;
            ++patched_methods_;
          }
          wuleb(blk, diff);
          wuleb(blk, acc);
          wuleb(blk, coff);
        }
      }
      if (changed) {
        align4();
        const uint32_t nbo = (uint32_t)(d_.size() + tail.size());
        tail.insert(tail.end(), blk.begin(), blk.end());
        wr32(cdef + 24, nbo);
        ++patched_classes_;
      }
    }
    // 3. splice + fix header: file_size, data_size, SHA-1 (bytes[0x20:]),
    // Adler-32 (bytes[0x0c:]).
    d_.insert(d_.end(), tail.begin(), tail.end());
    wr32(0x20, (uint32_t)d_.size());
    wr32(0x68, (uint32_t)(d_.size() - rd32(0x6c)));
    uint8_t sig[20];
    sha1(d_.data() + 0x20, d_.size() - 0x20, sig);
    std::memcpy(d_.data() + 0x0c, sig, 20);
    wr32(0x08,
         (uint32_t)adler32(1L, d_.data() + 0x0c, (uInt)(d_.size() - 0x0c)));
    return d_;
  }

 private:
  static constexpr uint32_t kAccNative = 0x100;
  std::vector<uint8_t> d_;
  std::map<uint32_t, std::vector<uint8_t>> recovered_;
  size_t patched_methods_ = 0, patched_classes_ = 0;
  const char* err_ = "";

  uint32_t rd32(size_t off) const {
    uint32_t v;
    std::memcpy(&v, d_.data() + off, 4);
    return v;
  }
  void wr32(size_t off, uint32_t v) { std::memcpy(d_.data() + off, &v, 4); }
  uint32_t uleb(size_t& p) const {
    uint32_t r = 0;
    int s = 0;
    while (p < d_.size()) {
      uint8_t x = d_[p++];
      r |= uint32_t(x & 0x7f) << s;
      if (!(x & 0x80)) break;
      s += 7;
    }
    return r;
  }
  static void wuleb(std::vector<uint8_t>& o, uint32_t v) {
    do {
      uint8_t x = v & 0x7f;
      v >>= 7;
      if (v) x |= 0x80;
      o.push_back(x);
    } while (v);
  }

  // tiny SHA-1 (DEX signature = SHA-1 over bytes[0x20:]).
  static void sha1(const uint8_t* data, size_t len, uint8_t out[20]) {
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
};

}  // namespace vardoger
