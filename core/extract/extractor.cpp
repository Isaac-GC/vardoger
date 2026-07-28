#include "vardoger/extract/extractor.hpp"

#include <sys/stat.h>

#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <set>

namespace vardoger {

namespace {
// Recursive mkdir (mkdir -p) via POSIX, avoiding <filesystem>, whose
// create_directories/path are gated to macOS 10.15+ and would break wheels
// built against an older -mmacosx-version-min (cibuildwheel's x86_64 default).
void mkdir_p(const std::string& path) {
  std::string cur;
  for (size_t i = 0; i <= path.size(); ++i) {
    if (i == path.size() || path[i] == '/') {
      if (!cur.empty()) ::mkdir(cur.c_str(), 0755);  // ignore EEXIST/errors
      if (i < path.size()) cur.push_back('/');
    } else {
      cur.push_back(path[i]);
    }
  }
}

uint32_t rd32(const uint8_t* p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) |
         (static_cast<uint32_t>(p[3]) << 24);
}

std::string sanitize(const std::string& s) {
  std::string out;
  for (char c : s)
    out.push_back((std::isalnum(static_cast<unsigned char>(c))) ? c : '_');
  return out;
}
}  // namespace

// Detect a DEX/ODEX/CDEX header. Validates header_size + endian_tag to keep
// false positives down (encrypted blobs sometimes contain the magic by chance).
bool Extractor::is_dex(const uint8_t* p, size_t avail, uint32_t& size,
                       std::string& version) {
  if (avail < 0x70) return false;
  if (std::memcmp(p, "dex\n", 4) == 0 && p[7] == 0 && p[4] == '0' &&
      p[5] == '3' && p[6] >= '5' && p[6] <= '9') {
    const uint32_t fsz = rd32(p + 0x20), hsz = rd32(p + 0x24),
                   endian = rd32(p + 0x28);
    if (hsz != 0x70 || endian != 0x12345678) return false;
    if (fsz < 0x70 || fsz > avail) return false;
    size = fsz;
    version = std::string("03") + static_cast<char>(p[6]);
    return true;
  }
  if (std::memcmp(p, "cdex", 4) == 0) {
    const uint32_t fsz = rd32(p + 0x20);
    if (fsz < 0x70 || fsz > avail) return false;
    size = fsz;
    version = "cdex";
    return true;
  }
  return false;
}

bool Extractor::observe(const std::vector<uint8_t>& bytes,
                        const std::string& src) {
  uint32_t size = 0;
  std::string ver;
  if (!is_dex(bytes.data(), bytes.size(), size, ver)) return false;
  FoundDex d;
  d.region = src;
  d.version = ver;
  d.bytes.assign(bytes.begin(), bytes.begin() + size);
  std::fprintf(stderr, "[extractor] DEX (%s) captured via %s, %u bytes\n",
               ver.c_str(), src.c_str(), size);
  captured_.push_back(std::move(d));
  return true;
}

bool Extractor::scannable(Memory::Kind k) const {
  switch (k) {
    case Memory::Kind::Heap:
    case Memory::Kind::Mmap:
    case Memory::Kind::Lib:
    case Memory::Kind::Other:
      return true;
    default:
      return false;  // skip trampoline/java/tls/kuser/stack/fini
  }
}

std::vector<FoundDex> Extractor::scan_dex() {
  std::vector<FoundDex> out;
  for (const Memory::Region& r : mem_.regions()) {
    if (!scannable(r.kind)) continue;
    std::vector<uint8_t> buf(r.size);
    e_.read(r.base, buf.data(), r.size);

    for (size_t off = 0; off + 0x70 <= buf.size();) {
      uint32_t size = 0;
      std::string ver;
      if (is_dex(&buf[off], buf.size() - off, size, ver)) {
        FoundDex d;
        d.addr = r.base + off;
        d.region = r.label;
        d.version = ver;
        d.bytes.assign(buf.begin() + off, buf.begin() + off + size);
        out.push_back(std::move(d));
        std::fprintf(stderr, "[extractor] DEX (%s) @ %s+0x%zx, %u bytes\n",
                     ver.c_str(), r.label.c_str(), off, size);
        off += size;  // skip past this dex
      } else {
        off += 4;  // dex headers are 4-aligned
      }
    }
  }
  return out;
}

std::vector<std::string> Extractor::harvest_strings(size_t min_len) {
  std::set<std::string> uniq;
  for (const Memory::Region& r : mem_.regions()) {
    if (!scannable(r.kind)) continue;
    std::vector<uint8_t> buf(r.size);
    e_.read(r.base, buf.data(), r.size);

    std::string run;
    for (uint8_t c : buf) {
      if (c >= 0x20 && c <= 0x7e) {
        run.push_back(static_cast<char>(c));
      } else {
        if (run.size() >= min_len) uniq.insert(run);
        run.clear();
      }
    }
    if (run.size() >= min_len) uniq.insert(run);
  }
  return {uniq.begin(), uniq.end()};
}

std::vector<FoundString> Extractor::search_strings(const std::string& needle,
                                                   size_t min_len) {
  std::vector<FoundString> out;
  for (const Memory::Region& r : mem_.regions()) {
    if (!scannable(r.kind)) continue;
    std::vector<uint8_t> buf(r.size);
    e_.read(r.base, buf.data(), r.size);

    size_t start = 0;      // offset where the current run began
    std::string run;
    auto flush = [&](size_t end_off) {
      if (run.size() >= min_len &&
          (needle.empty() || run.find(needle) != std::string::npos))
        out.push_back({r.base + start, run, r.label});
      run.clear();
      (void)end_off;
    };
    for (size_t i = 0; i < buf.size(); ++i) {
      const uint8_t c = buf[i];
      if (c >= 0x20 && c <= 0x7e) {
        if (run.empty()) start = i;
        run.push_back(static_cast<char>(c));
      } else {
        flush(i);
      }
    }
    flush(buf.size());
  }
  return out;
}

void Extractor::write_artifacts(const std::string& outdir,
                                const std::vector<FoundDex>& dexes,
                                const std::vector<std::string>& strings) const {
  mkdir_p(outdir + "/dex");

  std::ofstream manifest(outdir + "/manifest.txt");
  int n = 0;
  for (const FoundDex& d : dexes) {
    char name[256];
    std::snprintf(name, sizeof(name), "%s/dex/%04d_%s_0x%llx.dex",
                  outdir.c_str(), ++n, sanitize(d.region).c_str(),
                  static_cast<unsigned long long>(d.addr));
    std::ofstream f(name, std::ios::binary);
    f.write(reinterpret_cast<const char*>(d.bytes.data()),
            static_cast<std::streamsize>(d.bytes.size()));
    manifest << name << "  version=" << d.version << "  addr=0x" << std::hex
             << d.addr << std::dec << "  size=" << d.bytes.size()
             << "  region=" << d.region << "\n";
  }

  std::ofstream sf(outdir + "/strings.txt");
  for (const std::string& s : strings) sf << s << "\n";
}

}  // namespace vardoger
