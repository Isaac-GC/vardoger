// vardoger: DEX & string extraction.
//
// The payload-capture layer. Walks the scannable guest regions (heap/mmap/lib),
// detects decrypted DEX/CDEX by magic + header validation, and harvests
// strings. Provenance comes from the Memory region map (region_of/describe).
//
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "vardoger/engine/engine.hpp"
#include "vardoger/engine/memory.hpp"

namespace vardoger {

struct FoundDex {
  uint64_t addr = 0;           // guest address where it was found
  std::string region;          // provenance label
  std::string version;         // "035".."039" or "cdex"
  std::vector<uint8_t> bytes;  // the dumped file_size bytes
};

struct FoundString {
  uint64_t addr = 0;    // guest address of the run's first byte
  std::string text;     // the printable-ASCII run
  std::string region;   // provenance label (which mapping it lives in)
};

class Extractor {
 public:
  Extractor(Engine& engine, Memory& mem) : e_(engine), mem_(mem) {}

  // Scan every scannable region for DEX/CDEX and dump each (file_size bytes).
  std::vector<FoundDex> scan_dex();
  // Printable ASCII runs of >= min_len from the scannable regions (deduped).
  std::vector<std::string> harvest_strings(size_t min_len = 5);

  // Search guest memory for printable strings, keeping their location. Every
  // printable-ASCII run of >= min_len in a scannable region is returned with its
  // guest address and the mapping it lives in; if `needle` is non-empty, only
  // runs that contain it (as a substring) are kept. Unlike harvest_strings this
  // is NOT deduped and preserves addresses, so you can grep decrypted memory for
  // a marker (a class name, URL, license string) and jump straight to it.
  std::vector<FoundString> search_strings(const std::string& needle = "",
                                          size_t min_len = 4);

  // Active-trigger sink: hand it bytes (a filled byte[], a ClassLoader ctor
  // arg). If they look like a DEX, it's recorded in captured(). Wire as the
  // JavaRuntime bytes-observer. Returns true if a DEX was captured.
  bool observe(const std::vector<uint8_t>& bytes, const std::string& src);
  const std::vector<FoundDex>& captured() const { return captured_; }

  // True if `p` (with `avail` bytes) begins a valid DEX/CDEX header.
  static bool is_dex(const uint8_t* p, size_t avail, uint32_t& size,
                     std::string& version);

  // Write dex/*.dex, strings.txt and manifest.txt under outdir.
  void write_artifacts(const std::string& outdir,
                       const std::vector<FoundDex>& dexes,
                       const std::vector<std::string>& strings) const;

 private:
  bool scannable(Memory::Kind k) const;

  Engine& e_;
  Memory& mem_;
  std::vector<FoundDex> captured_;  // from observe() (active triggers)
};

}  // namespace vardoger
