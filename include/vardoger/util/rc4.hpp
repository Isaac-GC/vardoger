// vardoger: standard RC4 (utility).
//
// The classic Jiagu DynCryptor uses STANDARD, UNMODIFIED RC4 (verified by
// disassembly: identity S-box init 00..ff, then the textbook KSA `j += S[i] +
// key[i%keylen]; swap`, and the textbook PRGA `i++; j += S[i]; swap; out = in ^
// S[(S[i]+S[j])&0xff]`). Emulating that byte-loop through Unicorn over ~1MB is
// pathologically slow; this native implementation lets the driver INTERCEPT the
// emulated KSA/PRGA and run them at native speed (see jiagu_driver
// VARDOGER_RC4_FAST).
//
// State layout matches the guest DynCryptor state: 256-byte S-box, then
// i@+0x100, j@+0x101 (bytes).
#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

namespace vardoger::util {

struct Rc4 {
  uint8_t S[256];
  uint8_t i = 0, j = 0;

  // Key Scheduling Algorithm, standard RC4 (identity S-box + key mix).
  void ksa(const uint8_t* key, size_t keylen) {
    for (int k = 0; k < 256; ++k) S[k] = static_cast<uint8_t>(k);
    uint8_t jj = 0;
    for (int k = 0; k < 256; ++k) {
      jj = static_cast<uint8_t>(jj + S[k] + (keylen ? key[k % keylen] : 0));
      uint8_t t = S[k];
      S[k] = S[jj];
      S[jj] = t;
    }
    i = j = 0;
  }

  // PRGA, decrypt/encrypt `n` bytes of `buf` in place (XOR with the
  // keystream). Streaming: i/j persist across calls (matches the guest's
  // stateful DynCryptor).
  void crypt(uint8_t* buf, size_t n) {
    for (size_t k = 0; k < n; ++k) {
      i = static_cast<uint8_t>(i + 1);
      j = static_cast<uint8_t>(j + S[i]);
      uint8_t t = S[i];
      S[i] = S[j];
      S[j] = t;
      buf[k] ^= S[static_cast<uint8_t>(S[i] + S[j])];
    }
  }

  // Serialize/deserialize the 0x102-byte guest state (S-box + i@0x100 +
  // j@0x101).
  void load_state(const uint8_t* g) {
    for (int k = 0; k < 256; ++k) S[k] = g[k];
    i = g[0x100];
    j = g[0x101];
  }
  void save_state(uint8_t* g) const {
    for (int k = 0; k < 256; ++k) g[k] = S[k];
    g[0x100] = i;
    g[0x101] = j;
  }
};

// One-shot convenience: RC4(key) over data (fresh state).
inline std::vector<uint8_t> rc4(const uint8_t* key, size_t keylen,
                                const uint8_t* data, size_t n) {
  Rc4 r;
  r.ksa(key, keylen);
  std::vector<uint8_t> out(data, data + n);
  r.crypt(out.data(), out.size());
  return out;
}

}  // namespace vardoger::util
