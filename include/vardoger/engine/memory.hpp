// vardoger: virtual memory manager.
//
// Unicorn gives raw uc_mem_* with no allocator and no metadata. This layer adds
// bump allocators for the mmap/lib areas, a stack, and a tagged region map so
// region_of()/describe() always answer "what is this pointer". The extractor
// later scans these regions.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "vardoger/engine/address_space.hpp"
#include "vardoger/engine/engine.hpp"

namespace vardoger {

class Memory {
 public:
  enum class Kind {
    Lib,
    Stack,
    Heap,
    Mmap,
    Trampoline,
    Java,
    Tls,
    Kuser,
    Fini,
    Other
  };

  struct Region {
    uint64_t base = 0;
    uint64_t size = 0;
    uint32_t prot = 0;  // UC_PROT_* (approximate after sub-range protect)
    Kind kind = Kind::Other;
    std::string label;
    bool watched = false;  // extractor write-watch flag (set later)
  };

  explicit Memory(Engine& engine) : engine_(engine) {}

  // Map at a specific address (page-aligned out/up). Throws on overlap.
  uint64_t map_fixed(uint64_t addr, size_t len, uint32_t prot, Kind kind,
                     std::string label);
  // Bump-allocate from the mmap area; page-aligned.
  uint64_t mmap_alloc(size_t len, uint32_t prot,
                      std::string label = "anon mmap");
  // Bump-allocate a LARGE libc-malloc request from the dedicated big-malloc
  // region (kBigMallocBase), so it never perturbs the packer's mmap-region
  // layout. Falls back to mmap_alloc if the region is exhausted (would cross
  // into kMmapBase). Page-aligned.
  uint64_t big_alloc(size_t len, uint32_t prot,
                     std::string label = "malloc-big");
  // Reserve+map a span in the library area for one .so; returns its base.
  uint64_t map_lib(size_t total, uint32_t prot, std::string label);
  // Map the guest stack, set SP near the top, and return the initial SP.
  uint64_t setup_stack(size_t len = kStackSize);
  // Map a TLS block, set the thread pointer (TPIDR_EL0 / CP15 c13), seed the
  // bionic self-pointer + stack guard. Returns the TLS base. Bionic reads this
  // very early (stack guard, errno), call before running init_array.
  uint64_t setup_tls();
  // Bump-allocate from the heap region (maps it on first use). Backs malloc.
  uint64_t heap_alloc(size_t len, size_t align = 16);
  // Bump-allocate from the Java region (maps it on first use). Holds the
  // JavaVM/JNIEnv vtables and fake-object backing.
  uint64_t java_alloc(size_t len, size_t align = 16);

  void protect(uint64_t addr, size_t len, uint32_t prot);
  void unmap(uint64_t addr, size_t len);

  uint64_t heap_used() const { return heap_next_ ? heap_next_ - kHeapBase : 0; }
  uint64_t mmap_used() const { return mmap_next_ - kMmapBase; }
  bool is_mapped(uint64_t addr) const { return region_of(addr) != nullptr; }
  const Region* region_of(uint64_t addr) const;
  const std::vector<Region>& regions() const { return regions_; }
  std::string describe(uint64_t addr) const;  // "label+0xNN [Kind]"
  Engine& engine() { return engine_; }        // guest-memory read/write access

  static const char* kind_name(Kind k);

 private:
  void insert_region(Region r);  // keep regions_ sorted by base

  Engine& engine_;
  std::vector<Region> regions_;  // sorted by base
  uint64_t lib_next_ = kLibBase;
  uint64_t mmap_next_ = kMmapBase;
  uint64_t big_next_ = kBigMallocBase;  // dedicated large-malloc region
  uint64_t heap_next_ = 0;              // 0 until the heap is first mapped
  uint64_t heap_end_ = 0;
  uint64_t java_next_ = 0;  // 0 until the Java region is first mapped
  uint64_t java_end_ = 0;
};

}  // namespace vardoger
