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

// Real arm64 Android maps shared libraries HIGH under ASLR, in
// 0x70_0000_0000-0x7f_ffff_ffff. kLibBase's compact 0x12000000 is itself an
// anti-analysis tell: a packer that sanity-checks its own load address via
// dladdr()/dl_iterate_phdr() reads a low address as tool-injected — and it is
// INCONSISTENT with the synthetic system libs we report high in
// /proc/self/maps (linker64/libc at 0x7b...), which is a louder giveaway still.
// 64-bit ABIs therefore place the library band here; 32-bit ABIs (arm32/x86)
// must stay under 4 GiB and keep using kLibBase.
inline constexpr uint64_t kLibBase64 = 0x7000000000ull;

constexpr uint64_t page_align_down(uint64_t a) { return a & ~(kPageSize - 1); }
constexpr uint64_t page_align_up(uint64_t a) {
  return (a + kPageSize - 1) & ~(kPageSize - 1);
}

}  // namespace vardoger
