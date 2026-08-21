// vardoger: minimal ART class-loading substrate (task #12, "real ART" tier).
//
// Models just enough of ART's DEX/class-loading that packers coupled to real
// ART fire their lazy decrypt: a GUEST-MEMORY `art::DexFile` struct (so native
// code reading mCookie -> DexFile* -> begin_/size_ gets real DEX bytes), the
// `DexFile.mCookie` long[] cookie, and the BaseDexClassLoader -> DexPathList ->
// Element[] -> DexFile object graph. Layouts target API 31 (Android 12) arm64;
// grow/tune per the fields packers actually read. See
//
//
// This is the reusable substrate the whole ART-coupled packer family needs
// (classic Jiagu / Bangcle / Legu ...). It does NOT reimplement
// ClassLinker/GC/JIT, only the DEX-load surface.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace vardoger {

class Engine;
class Memory;
class JavaRuntime;

class ArtRuntime {
 public:
  ArtRuntime(Engine& e, Memory& mem, JavaRuntime& jrt)
      : e_(e), mem_(mem), jrt_(jrt) {}

  // A DEX materialized in guest memory as an ART DexFile.
  struct Dex {
    uint64_t bytes_addr = 0;  // guest addr of the raw DEX bytes
    uint64_t bytes_len = 0;
    uint64_t struct_addr =
        0;  // guest addr of the art::DexFile struct (begin_/size_/...)
    uint64_t cookie_arr =
        0;  // jlong[]{0, struct_addr} handle (DexFile.mCookie)
    uint64_t dexfile_obj =
        0;  // java dalvik/system/DexFile object with mCookie set
    std::vector<std::string>
        class_names;  // binary names ("com/foo/Bar") from our DEX parser
  };

  // Load DEX bytes into guest memory + build the art::DexFile struct + cookie +
  // java DexFile object. Native code that walks mCookie -> DexFile* reads
  // begin_ (=bytes_addr) and size_ (=len).
  Dex register_dex(const std::vector<uint8_t>& bytes,
                   const std::string& location = "classes.dex");

  // Build BaseDexClassLoader -> DexPathList -> Element[] -> DexFile{mCookie}
  // over the given DEXes. Returns the ClassLoader object handle (usable as the
  // app classloader).
  uint64_t build_classloader(const std::vector<Dex>& dexes,
                             uint64_t parent = 0);

  // Register the ART DEX-load host methods (openInMemoryDexFile /
  // openDexFileNative / defineClassNative / InMemoryDexClassLoader) on the
  // JavaRuntime, routed through the substrate: extract bytes (byte[] or direct
  // ByteBuffer) -> register_dex -> notify_bytes capture -> return a valid
  // DexFile/cookie so a decrypt-ON-DEFINE packer keeps loading (class N ->
  // decrypt class N+1).
  void install();

  // Extract DEX bytes from a byte[] or a direct ByteBuffer handle (empty if
  // neither / not a DEX).
  std::vector<uint8_t> extract_dex_bytes(uint64_t handle) const;

  // Read back begin_/size_ from a Dex's struct (validation / sanity).
  uint64_t dex_begin(const Dex& d) const;
  uint64_t dex_size(const Dex& d) const;

  const std::vector<Dex>& dexes() const { return dexes_; }

  // art::DexFile field offsets (API 31 arm64). Tunable if a packer reads a
  // different layout.
  struct Layout {
    uint32_t begin = 0x00, size = 0x08, data_begin = 0x10, data_size = 0x18,
             location = 0x20, checksum = 0x38;
  };
  Layout layout;

 private:
  Engine& e_;
  Memory& mem_;
  JavaRuntime& jrt_;
  std::vector<Dex> dexes_;
};

}  // namespace vardoger
