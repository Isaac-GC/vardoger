#include "vardoger/engine/memory.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>

namespace vardoger {

const char* Memory::kind_name(Kind k) {
  switch (k) {
    case Kind::Lib:
      return "Lib";
    case Kind::Stack:
      return "Stack";
    case Kind::Heap:
      return "Heap";
    case Kind::Mmap:
      return "Mmap";
    case Kind::Trampoline:
      return "Trampoline";
    case Kind::Java:
      return "Java";
    case Kind::Tls:
      return "Tls";
    case Kind::Kuser:
      return "Kuser";
    case Kind::Fini:
      return "Fini";
    case Kind::Other:
      return "Other";
  }
  return "?";
}

void Memory::insert_region(Region r) {
  auto it = std::upper_bound(
      regions_.begin(), regions_.end(), r,
      [](const Region& a, const Region& b) { return a.base < b.base; });
  regions_.insert(it, std::move(r));
}

uint64_t Memory::map_fixed(uint64_t addr, size_t len, uint32_t prot, Kind kind,
                           std::string label) {
  const uint64_t base = page_align_down(addr);
  const uint64_t end = page_align_up(addr + len);
  const uint64_t size = end - base;

  for (const Region& r : regions_) {
    const bool overlaps = base < r.base + r.size && r.base < end;
    if (overlaps)
      throw std::runtime_error("map_fixed: [" + label +
                               "] overlaps existing region [" + r.label + "]");
  }
  engine_.map(base, size, prot);
  insert_region({base, size, prot, kind, std::move(label), false});
  return base;
}

uint64_t Memory::mmap_alloc(size_t len, uint32_t prot, std::string label) {
  if (len > (1ull << 32))
    throw std::runtime_error(
        "mmap_alloc: absurd len (bogus/mis-resolved call)");  // bogus mmap
                                                              // guard
  const uint64_t size =
      page_align_up(len ? len : 1);  // never map 0 bytes (UC_ERR_ARG)
  // Find a free gap of `size` starting at mmap_next_, skipping any
  // already-mapped regions (a bump cursor can collide after a
  // MAP_FIXED/self-decompress mapped into the mmap band -> UC_ERR_MAP).
  uint64_t base = mmap_next_;
  for (int tries = 0; tries < 4096; ++tries) {
    bool clash = false;
    for (const Region& r : regions_)
      if (base < r.base + r.size && r.base < base + size) {
        base = r.base + r.size;
        clash = true;
        break;
      }
    if (!clash) break;
  }
  engine_.map(base, size, prot);
  insert_region({base, size, prot, Kind::Mmap, std::move(label), false});
  mmap_next_ = base + size;
  return base;
}

uint64_t Memory::big_alloc(size_t len, uint32_t prot, std::string label) {
  const uint64_t size = page_align_up(len ? len : 1);
  if (big_next_ + size >
      kMmapBase)  // region exhausted -> use the general mmap area
    return mmap_alloc(len, prot, std::move(label));
  const uint64_t base = big_next_;
  engine_.map(base, size, prot);
  insert_region({base, size, prot, Kind::Mmap, std::move(label), false});
  big_next_ = base + size;
  return base;
}

uint64_t Memory::map_lib(size_t total, uint32_t prot, std::string label) {
  // 64-bit libs are placed high (kLibBase64) from the Memory ctor; 32-bit stay
  // at kLibBase. (Realistic ASLR-range base defeats a packer's dladdr/
  // dl_iterate_phdr low-address "tool-injected" check.)
  const uint64_t base = lib_next_;
  const uint64_t size = page_align_up(total);
  engine_.map(base, size, prot);
  insert_region({base, size, prot, Kind::Lib, std::move(label), false});
  lib_next_ = base + size + kPageSize;  // one-page guard gap between libs
  return base;
}

uint64_t Memory::setup_stack(size_t len) {
  const uint64_t size = page_align_up(len);
  const uint64_t base = kStackTop - size;
  engine_.map(base, size, UC_PROT_READ | UC_PROT_WRITE);
  insert_region(
      {base, size, UC_PROT_READ | UC_PROT_WRITE, Kind::Stack, "stack", false});
  const uint64_t sp =
      (kStackTop - 16) & ~uint64_t(15);  // 16-byte aligned, small redzone
  engine_.write_reg(Reg::Sp, sp);
  return sp;
}

uint64_t Memory::setup_tls() {
  engine_.map(kTlsBase, kTlsSize, UC_PROT_READ | UC_PROT_WRITE);
  insert_region({kTlsBase, kTlsSize, UC_PROT_READ | UC_PROT_WRITE, Kind::Tls,
                 "tls", false});
  // bionic AArch64 TLS slots (8 bytes each): [0]=self, [5]=stack guard.
  engine_.write_t<uint64_t>(kTlsBase + 0x00, kTlsBase);  // TLS_SLOT_SELF
  engine_.write_t<uint64_t>(kTlsBase + 0x28,
                            0x1122334455667788ull);  // TLS_SLOT_STACK_GUARD
  if (engine_.abi() == Abi::Arm64)
    engine_.write_uc_reg(UC_ARM64_REG_TPIDR_EL0, kTlsBase);
  else
    engine_.write_uc_reg(UC_ARM_REG_C13_C0_3, kTlsBase);  // TPIDRURO
  return kTlsBase;
}

uint64_t Memory::heap_alloc(size_t len, size_t align) {
  if (heap_next_ == 0) {  // map the heap region on first use
    engine_.map(kHeapBase, kHeapSize, UC_PROT_READ | UC_PROT_WRITE);
    insert_region({kHeapBase, kHeapSize, UC_PROT_READ | UC_PROT_WRITE,
                   Kind::Heap, "heap", false});
    heap_next_ = kHeapBase;
    heap_end_ = kHeapBase + kHeapSize;
  }
  const uint64_t p =
      (heap_next_ + (align - 1)) & ~static_cast<uint64_t>(align - 1);
  if (p + len > heap_end_) {  // never throw from a malloc stub (it runs inside
    return 0;                 // uc_emu_start), return null like a real OOM.
  }
  // Round the consumed footprint up to a size class and add a small inter-chunk
  // gap, so adjacent allocations don't touch (a real allocator's chunk headers
  // / size-class rounding leave slack; a tightly-packed bump heap lets a benign
  // +N-byte write clobber the next obj).
  static const bool tight =
      std::getenv("VARDOGER_HEAP_TIGHT") != nullptr;  // bisect toggle
  if (tight) {
    heap_next_ = p + len;
  } else {
    const uint64_t footprint =
        (len + 0x1f) & ~uint64_t(0x1f);  // round up to 32
    heap_next_ = p + footprint + 16;     // + 16-byte guard gap
  }
  if (std::getenv("VARDOGER_HEAP_LOG"))
    std::fprintf(stderr, "[halloc] size=%#zx lr=%#llx -> %#llx\n", len,
                 (unsigned long long)engine_.read_reg(Reg::Lr),
                 (unsigned long long)p);
  return p;
}

uint64_t Memory::java_alloc(size_t len, size_t align) {
  if (java_next_ == 0) {  // map the Java region on first use
    engine_.map(kJavaBase, kJavaSize, UC_PROT_READ | UC_PROT_WRITE);
    insert_region({kJavaBase, kJavaSize, UC_PROT_READ | UC_PROT_WRITE,
                   Kind::Java, "java", false});
    java_next_ = kJavaBase;
    java_end_ = kJavaBase + kJavaSize;
  }
  const uint64_t p =
      (java_next_ + (align - 1)) & ~static_cast<uint64_t>(align - 1);
  if (p + len > java_end_) throw std::runtime_error("java region exhausted");
  java_next_ = p + len;
  return p;
}

void Memory::protect(uint64_t addr, size_t len, uint32_t prot) {
  const uint64_t base = page_align_down(addr);
  const uint64_t size = page_align_up(addr + len) - base;
  // Tolerant page-by-page: packers mprotect ranges whose tail was never
  // materialized (the arm32 self-decrypt mprotects across a freshly-decrypted
  // mmap). Map the unmapped pages instead of aborting on UC_ERR_NOMEM -
  // otherwise the loader dies before .text is even readable.
  bool hole = false;
  for (uint64_t p = base; p < base + size; p += 0x1000)
    if (!is_mapped(p)) {
      hole = true;
      break;
    }
  if (!hole) {
    engine_.protect(base, size, prot);
  } else {
    for (uint64_t p = base; p < base + size; p += 0x1000) {
      if (is_mapped(p))
        engine_.protect(p, 0x1000, prot);
      else
        map_fixed(p, 0x1000, prot ? prot : (UC_PROT_READ | UC_PROT_WRITE),
                  Kind::Other, "mprotect-fill");
    }
  }
  // If the request exactly covers a tracked region, keep its prot accurate.
  for (Region& r : regions_)
    if (r.base == base && r.size == size) {
      r.prot = prot;
      break;
    }
}

void Memory::unmap(uint64_t addr, size_t len) {
  const uint64_t base = page_align_down(addr);
  const uint64_t size = page_align_up(addr + len) - base;
  engine_.unmap(base, size);
  regions_.erase(std::remove_if(regions_.begin(), regions_.end(),
                                [&](const Region& r) {
                                  return r.base == base && r.size == size;
                                }),
                 regions_.end());
}

const Memory::Region* Memory::region_of(uint64_t addr) const {
  for (const Region& r : regions_)
    if (addr >= r.base && addr < r.base + r.size) return &r;
  return nullptr;
}

std::string Memory::describe(uint64_t addr) const {
  char buf[288];
  const Region* r = region_of(addr);
  if (!r) {
    std::snprintf(buf, sizeof(buf), "0x%llx [unmapped]",
                  static_cast<unsigned long long>(addr));
    return buf;
  }
  std::snprintf(buf, sizeof(buf), "%s+0x%llx [%s]", r->label.c_str(),
                static_cast<unsigned long long>(addr - r->base),
                kind_name(r->kind));
  return buf;
}

}  // namespace vardoger
