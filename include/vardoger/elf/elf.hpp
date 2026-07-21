// vardoger: self-contained ELF view.
//
// The NDK's third_party/elf.h is just a wrapper around <linux/elf.h> + bionic
// <bits/*> headers, which don't exist on a macOS host, so it can't compile
// here. This header defines exactly the ELF32/64 structs and constants the
// loader needs, host-OS-independent, in namespace vardoger::elf. See
//
#pragma once

#include <cstdint>

namespace vardoger::elf {

// ---- e_ident ----
inline constexpr int EI_NIDENT = 16;
inline constexpr int EI_CLASS = 4;
inline constexpr int EI_DATA = 5;
inline constexpr unsigned char ELFCLASS32 = 1, ELFCLASS64 = 2;
inline constexpr unsigned char ELFDATA2LSB = 1;

// ---- e_type / e_machine ----
inline constexpr uint16_t ET_DYN = 3;
inline constexpr uint16_t EM_ARM = 40;
inline constexpr uint16_t EM_AARCH64 = 183;

// ---- program header types / flags ----
inline constexpr uint32_t PT_LOAD = 1;
inline constexpr uint32_t PT_DYNAMIC = 2;
inline constexpr uint32_t PT_TLS = 7;
inline constexpr uint32_t PF_X = 1, PF_W = 2, PF_R = 4;

// ---- dynamic tags ----
inline constexpr int64_t DT_NULL = 0, DT_NEEDED = 1, DT_PLTRELSZ = 2,
                         DT_PLTGOT = 3, DT_HASH = 4, DT_STRTAB = 5,
                         DT_SYMTAB = 6, DT_RELA = 7, DT_RELASZ = 8,
                         DT_RELAENT = 9, DT_STRSZ = 10, DT_SYMENT = 11,
                         DT_INIT = 12, DT_FINI = 13, DT_SONAME = 14,
                         DT_REL = 17, DT_RELSZ = 18, DT_RELENT = 19,
                         DT_PLTREL = 20, DT_JMPREL = 23, DT_INIT_ARRAY = 25,
                         DT_FINI_ARRAY = 26, DT_INIT_ARRAYSZ = 27,
                         DT_FINI_ARRAYSZ = 28, DT_FLAGS = 30,
                         DT_GNU_HASH = 0x6ffffef5, DT_FLAGS_1 = 0x6ffffffb;

// ---- symbol table ----
inline constexpr uint16_t SHN_UNDEF = 0;
constexpr unsigned char ST_BIND(unsigned char info) { return info >> 4; }
constexpr unsigned char ST_TYPE(unsigned char info) { return info & 0xf; }

// ---- relocation types (AArch64) ----
inline constexpr uint32_t R_AARCH64_ABS64 = 257;
inline constexpr uint32_t R_AARCH64_GLOB_DAT = 1025;
inline constexpr uint32_t R_AARCH64_JUMP_SLOT = 1026;
inline constexpr uint32_t R_AARCH64_RELATIVE = 1027;
// ---- relocation types (ARM) ----
inline constexpr uint32_t R_ARM_ABS32 = 2;
inline constexpr uint32_t R_ARM_GLOB_DAT = 21;
inline constexpr uint32_t R_ARM_JUMP_SLOT = 22;
inline constexpr uint32_t R_ARM_RELATIVE = 23;

// r_info field decoding differs by class.
constexpr uint32_t R64_SYM(uint64_t i) {
  return static_cast<uint32_t>(i >> 32);
}
constexpr uint32_t R64_TYPE(uint64_t i) {
  return static_cast<uint32_t>(i & 0xffffffff);
}
constexpr uint32_t R32_SYM(uint32_t i) { return i >> 8; }
constexpr uint32_t R32_TYPE(uint32_t i) { return i & 0xff; }

// ---------------------------------------------------------------- structures
// -- Field order matches the on-disk layout exactly (note: 32- and 64-bit
// Phdr/Sym order their fields DIFFERENTLY). All read via memcpy, so no packing
// needed, these layouts already have no internal padding (asserted below).

struct Elf64_Ehdr {
  unsigned char e_ident[EI_NIDENT];
  uint16_t e_type, e_machine;
  uint32_t e_version;
  uint64_t e_entry, e_phoff, e_shoff;
  uint32_t e_flags;
  uint16_t e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
};
struct Elf32_Ehdr {
  unsigned char e_ident[EI_NIDENT];
  uint16_t e_type, e_machine;
  uint32_t e_version, e_entry, e_phoff, e_shoff, e_flags;
  uint16_t e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
};

struct Elf64_Phdr {
  uint32_t p_type, p_flags;
  uint64_t p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align;
};
struct Elf32_Phdr {
  uint32_t p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags,
      p_align;
};

struct Elf64_Dyn {
  int64_t d_tag;
  uint64_t d_val;
};
struct Elf32_Dyn {
  int32_t d_tag;
  uint32_t d_val;
};

struct Elf64_Sym {
  uint32_t st_name;
  unsigned char st_info, st_other;
  uint16_t st_shndx;
  uint64_t st_value, st_size;
};
struct Elf32_Sym {
  uint32_t st_name, st_value, st_size;
  unsigned char st_info, st_other;
  uint16_t st_shndx;
};

struct Elf64_Rel {
  uint64_t r_offset, r_info;
};
struct Elf32_Rel {
  uint32_t r_offset, r_info;
};
struct Elf64_Rela {
  uint64_t r_offset, r_info;
  int64_t r_addend;
};
struct Elf32_Rela {
  uint32_t r_offset, r_info;
  int32_t r_addend;
};

static_assert(sizeof(Elf64_Ehdr) == 64);
static_assert(sizeof(Elf32_Ehdr) == 52);
static_assert(sizeof(Elf64_Phdr) == 56);
static_assert(sizeof(Elf32_Phdr) == 32);
static_assert(sizeof(Elf64_Dyn) == 16);
static_assert(sizeof(Elf32_Dyn) == 8);
static_assert(sizeof(Elf64_Sym) == 24);
static_assert(sizeof(Elf32_Sym) == 16);
static_assert(sizeof(Elf64_Rela) == 24);
static_assert(sizeof(Elf32_Rela) == 12);

}  // namespace vardoger::elf
