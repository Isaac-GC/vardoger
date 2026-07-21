// vardoger: the fixed guest virtual address-space layout.
//
// Pick a layout once and never deviate: half of all emulation debugging is
// "which region is this pointer in".
// All bases are < 4 GiB so the same layout serves arm64 and arm32.
#pragma once

#include <cstdint>

namespace vardoger {

inline constexpr uint64_t kPageSize =
    0x1000;  // 4 KiB guest pages (bionic assumption)

inline constexpr uint64_t kLibBase = 0x12000000;  // loaded libraries grow up
inline constexpr uint64_t kFiniPage =
    0x1FFF0000;  // magic "return-to-here" sentinel
inline constexpr uint64_t kTrampolineBase = 0x20000000;  // SVC #n stubs
inline constexpr uint64_t kTrampolineSize = 0x00010000;
inline constexpr uint64_t kJavaBase =
    0x30000000;  // JavaVM/JNIEnv/fake-object backing
inline constexpr uint64_t kJavaSize =
    0x04000000;  // 64 MiB (shadow objects live here)
inline constexpr uint64_t kHeapBase = 0x40000000;  // malloc/brk arena
inline constexpr uint64_t kHeapSize = 0x08000000;  // 128 MiB (packers mmap big)
inline constexpr uint64_t kTlsBase = 0x50000000;   // thread-local storage block
inline constexpr uint64_t kTlsSize = 0x00010000;   // 64 KiB (bionic TLS grows)
// Large libc malloc/calloc/realloc requests (>= 4 MiB) get their OWN region
// here, NOT the packer's mmap region. Real allocators mmap large allocs;
// routing them into kMmapBase would interleave with the packer's own mmap()s
// and shift fixed-layout data (e.g. Jiagu's VM-body arena at 0x70000000). A
// dedicated region keeps the mmap region's layout byte-identical to a
// bump-heap-only run.
inline constexpr uint64_t kBigMallocBase =
    0x54000000;  // grows up to kMmapBase (~448 MiB)
inline constexpr uint64_t kMmapBase = 0x70000000;  // anonymous + file mmap
inline constexpr uint64_t kStackTop = 0xC0000000;  // stack grows down from here
inline constexpr uint64_t kStackSize = 0x00800000;  // 8 MiB

constexpr uint64_t page_align_down(uint64_t a) { return a & ~(kPageSize - 1); }
constexpr uint64_t page_align_up(uint64_t a) {
  return (a + kPageSize - 1) & ~(kPageSize - 1);
}

}  // namespace vardoger
