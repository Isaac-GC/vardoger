#include "vardoger/elf/elf_loader.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <stdexcept>
#include <type_traits>

#include "vardoger/elf/elf.hpp"
#include "vardoger/engine/address_space.hpp"

namespace vardoger {

namespace {

template <class T>
T read_at(const std::vector<uint8_t>& data, size_t off) {
  if (off + sizeof(T) > data.size())
    throw std::runtime_error("ELF: read past end of file");
  T v{};
  std::memcpy(&v, data.data() + off, sizeof(T));
  return v;
}

uint32_t pf_to_uc(uint32_t pf) {
  uint32_t prot = 0;
  if (pf & elf::PF_R) prot |= UC_PROT_READ;
  if (pf & elf::PF_W) prot |= UC_PROT_WRITE;
  if (pf & elf::PF_X) prot |= UC_PROT_EXEC;
  return prot;
}

// Number of dynamic symbols, derived from the GNU hash table (used when a
// binary has DT_GNU_HASH but no DT_HASH). Walks the longest bucket chain to the
// terminator (low bit set). ptr_size selects the bloom word width.
uint64_t gnu_hash_nsyms(Engine& e, uint64_t gh, size_t ptr_size) {
  const uint32_t nbuckets = e.read_t<uint32_t>(gh + 0);
  const uint32_t symoffset = e.read_t<uint32_t>(gh + 4);
  const uint32_t bloom_size = e.read_t<uint32_t>(gh + 8);
  const uint64_t buckets =
      gh + 16 + static_cast<uint64_t>(bloom_size) * ptr_size;
  uint32_t last = 0;
  for (uint32_t i = 0; i < nbuckets; ++i)
    last = std::max(last,
                    e.read_t<uint32_t>(buckets + static_cast<uint64_t>(i) * 4));
  if (last < symoffset) return symoffset;  // empty / all-undefined
  const uint64_t chain = buckets + static_cast<uint64_t>(nbuckets) * 4;
  uint32_t idx = last;
  for (;;) {
    const uint32_t h =
        e.read_t<uint32_t>(chain + static_cast<uint64_t>(idx - symoffset) * 4);
    if (h & 1u) break;  // chain terminator
    ++idx;
  }
  return static_cast<uint64_t>(idx) + 1;
}

}  // namespace

SoInfo ElfLoader::load(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) throw std::runtime_error("ELF: cannot open " + path);
  std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)),
                            std::istreambuf_iterator<char>());
  // name = basename of path
  auto slash = path.find_last_of("/\\");
  return load_bytes(std::move(data),
                    slash == std::string::npos ? path : path.substr(slash + 1));
}

SoInfo ElfLoader::load_bytes(std::vector<uint8_t> data, std::string name) {
  if (data.size() < elf::EI_NIDENT || std::memcmp(data.data(),
                                                  "\x7f"
                                                  "ELF",
                                                  4) != 0)
    throw std::runtime_error("ELF: bad magic in " + name);
  if (data[elf::EI_DATA] != elf::ELFDATA2LSB)
    throw std::runtime_error("ELF: not little-endian: " + name);

  const unsigned char klass = data[elf::EI_CLASS];
  if (klass == elf::ELFCLASS64) return load_impl<true>(data, name);
  if (klass == elf::ELFCLASS32) return load_impl<false>(data, name);
  throw std::runtime_error("ELF: unknown class in " + name);
}

template <bool Is64>
SoInfo ElfLoader::load_impl(const std::vector<uint8_t>& data,
                            const std::string& name) {
  using Ehdr = std::conditional_t<Is64, elf::Elf64_Ehdr, elf::Elf32_Ehdr>;
  using Phdr = std::conditional_t<Is64, elf::Elf64_Phdr, elf::Elf32_Phdr>;
  using Dyn = std::conditional_t<Is64, elf::Elf64_Dyn, elf::Elf32_Dyn>;
  using Sym = std::conditional_t<Is64, elf::Elf64_Sym, elf::Elf32_Sym>;
  using Shdr = std::conditional_t<Is64, elf::Elf64_Shdr, elf::Elf32_Shdr>;
  using Rel = std::conditional_t<Is64, elf::Elf64_Rel, elf::Elf32_Rel>;
  using Rela = std::conditional_t<Is64, elf::Elf64_Rela, elf::Elf32_Rela>;
  using Addr = std::conditional_t<Is64, uint64_t, uint32_t>;

  SoInfo so;
  so.name = name;
  so.is64 = Is64;

  const Ehdr eh = read_at<Ehdr>(data, 0);
  if (eh.e_type != elf::ET_DYN)
    std::fprintf(stderr, "[loader] %s: warning, e_type=%u (expected ET_DYN)\n",
                 name.c_str(), eh.e_type);
  const uint16_t want_machine = engine_.abi() == Abi::Arm64   ? elf::EM_AARCH64
                               : engine_.abi() == Abi::Arm32  ? elf::EM_ARM
                               : engine_.abi() == Abi::X86_64 ? elf::EM_X86_64
                                                              : elf::EM_386;
  if (eh.e_machine != want_machine)
    std::fprintf(stderr, "[loader] %s: warning, e_machine=%u (expected %u)\n",
                 name.c_str(), eh.e_machine, want_machine);

  // --- pass 1: scan program headers ---
  uint64_t min_vaddr = ~0ull, max_vaddr = 0, dyn_vaddr = 0;
  std::vector<Phdr> loads;
  for (uint16_t i = 0; i < eh.e_phnum; ++i) {
    const Phdr ph = read_at<Phdr>(
        data, eh.e_phoff + static_cast<size_t>(i) * eh.e_phentsize);
    if (ph.p_type == elf::PT_LOAD) {
      loads.push_back(ph);
      min_vaddr = std::min<uint64_t>(min_vaddr, page_align_down(ph.p_vaddr));
      max_vaddr =
          std::max<uint64_t>(max_vaddr, page_align_up(ph.p_vaddr + ph.p_memsz));
    } else if (ph.p_type == elf::PT_DYNAMIC) {
      dyn_vaddr = ph.p_vaddr;
    } else if (ph.p_type == elf::PT_TLS) {
      std::fprintf(
          stderr, "[loader] %s: has PT_TLS (filesz=%llu) - TLS setup is TODO\n",
          name.c_str(), static_cast<unsigned long long>(ph.p_filesz));
    }
  }
  if (loads.empty()) throw std::runtime_error("ELF: no PT_LOAD in " + name);

  // --- map the whole span once, then write each segment's bytes ---
  const uint64_t span = max_vaddr - min_vaddr;
  so.base = mem_.map_lib(span, UC_PROT_ALL, name);
  so.size = page_align_up(span);
  so.load_bias = so.base - min_vaddr;
  for (const Phdr& ph : loads)
    engine_.write(so.load_bias + ph.p_vaddr, data.data() + ph.p_offset,
                  ph.p_filesz);
  // (memsz - filesz is BSS; freshly-mapped Unicorn pages are already zero.)

  // --- parse the dynamic section (read from guest memory now that it's loaded)
  // ---
  uint64_t strtab = 0, symtab = 0, rela = 0, relasz = 0, jmprel = 0,
           pltrelsz = 0;
  uint64_t rel = 0, relsz = 0;
  uint64_t relr = 0, relrsz = 0;                  // RELR compressed relatives
  uint64_t android_rela = 0, android_relasz = 0;  // Android packed RELA
  int64_t pltrel = 0;
  uint64_t init_array = 0, init_arraysz = 0;
  uint64_t preinit_array = 0, preinit_arraysz = 0;
  uint64_t fini_array = 0, fini_arraysz = 0;
  uint64_t hash = 0, gnu_hash = 0;
  std::vector<uint64_t> needed_offsets;

  if (dyn_vaddr) {
    for (uint64_t a = so.load_bias + dyn_vaddr;; a += sizeof(Dyn)) {
      const Dyn d = engine_.read_t<Dyn>(a);
      if (d.d_tag == elf::DT_NULL) break;
      switch (d.d_tag) {
        case elf::DT_STRTAB:
          strtab = so.load_bias + d.d_val;
          break;
        case elf::DT_SYMTAB:
          symtab = so.load_bias + d.d_val;
          break;
        case elf::DT_RELA:
          rela = so.load_bias + d.d_val;
          break;
        case elf::DT_RELASZ:
          relasz = d.d_val;
          break;
        case elf::DT_REL:
          rel = so.load_bias + d.d_val;
          break;
        case elf::DT_RELSZ:
          relsz = d.d_val;
          break;
        case elf::DT_JMPREL:
          jmprel = so.load_bias + d.d_val;
          break;
        case elf::DT_PLTRELSZ:
          pltrelsz = d.d_val;
          break;
        case elf::DT_PLTREL:
          pltrel = static_cast<int64_t>(d.d_val);
          break;
        case elf::DT_INIT:
          so.init = so.load_bias + d.d_val;
          break;
        case elf::DT_INIT_ARRAY:
          init_array = so.load_bias + d.d_val;
          break;
        case elf::DT_INIT_ARRAYSZ:
          init_arraysz = d.d_val;
          break;
        case elf::DT_PREINIT_ARRAY:
          preinit_array = so.load_bias + d.d_val;
          break;
        case elf::DT_PREINIT_ARRAYSZ:
          preinit_arraysz = d.d_val;
          break;
        case elf::DT_FINI_ARRAY:
          fini_array = so.load_bias + d.d_val;
          break;
        case elf::DT_FINI_ARRAYSZ:
          fini_arraysz = d.d_val;
          break;
        case elf::DT_FINI:
          so.fini = so.load_bias + d.d_val;
          break;
        case elf::DT_HASH:
          hash = so.load_bias + d.d_val;
          break;
        case elf::DT_GNU_HASH:
          gnu_hash = so.load_bias + d.d_val;
          break;
        case elf::DT_RELR:
          relr = so.load_bias + d.d_val;
          break;
        case elf::DT_RELRSZ:
          relrsz = d.d_val;
          break;
        case elf::DT_ANDROID_RELA:
          android_rela = so.load_bias + d.d_val;
          break;
        case elf::DT_ANDROID_RELASZ:
          android_relasz = d.d_val;
          break;
        case elf::DT_NEEDED:
          needed_offsets.push_back(d.d_val);
          break;
        default:
          break;
      }
    }
  }

  // resolve DT_NEEDED names
  for (uint64_t off : needed_offsets)
    so.needed.push_back(engine_.read_cstr(strtab + off));

  // symbol helpers
  auto sym_at = [&](uint32_t idx) {
    return engine_.read_t<Sym>(symtab +
                               static_cast<uint64_t>(idx) * sizeof(Sym));
  };
  auto resolve_sym = [&](uint32_t idx) -> uint64_t {
    const Sym s = sym_at(idx);
    if (s.st_shndx == elf::SHN_UNDEF) {
      const std::string nm = engine_.read_cstr(strtab + s.st_name);
      const uint64_t addr = resolve_import_ ? resolve_import_(nm) : 0;
      if (!addr)
        std::fprintf(stderr, "[loader] %s: unresolved import '%s'\n",
                     name.c_str(), nm.c_str());
      return addr;
    }
    return so.load_bias + s.st_value;
  };

  // Relocation type numbers are architecture-specific, so derive them from this
  // file's e_machine instead of hardcoding ARM. The *shapes* are shared: RELA
  // targets (arm64/x86_64) write bias+addend / sym / sym+addend, and REL targets
  // (arm32/i386) fold the addend in from the existing slot contents.
  struct RelocKinds { uint32_t relative, glob_dat, jump_slot, abs; };
  const RelocKinds rk =
      eh.e_machine == elf::EM_AARCH64
          ? RelocKinds{elf::R_AARCH64_RELATIVE, elf::R_AARCH64_GLOB_DAT,
                       elf::R_AARCH64_JUMP_SLOT, elf::R_AARCH64_ABS64}
      : eh.e_machine == elf::EM_X86_64
          ? RelocKinds{elf::R_X86_64_RELATIVE, elf::R_X86_64_GLOB_DAT,
                       elf::R_X86_64_JUMP_SLOT, elf::R_X86_64_64}
      : eh.e_machine == elf::EM_386
          ? RelocKinds{elf::R_386_RELATIVE, elf::R_386_GLOB_DAT,
                       elf::R_386_JMP_SLOT, elf::R_386_32}
          : RelocKinds{elf::R_ARM_RELATIVE, elf::R_ARM_GLOB_DAT,
                       elf::R_ARM_JUMP_SLOT, elf::R_ARM_ABS32};

  // --- apply relocations ---
  auto apply_rela = [&](uint64_t table, uint64_t bytes) {
    for (uint64_t o = 0; o + sizeof(Rela) <= bytes; o += sizeof(Rela)) {
      const Rela r = engine_.read_t<Rela>(table + o);
      const uint32_t type =
          Is64 ? elf::R64_TYPE(r.r_info) : elf::R32_TYPE(r.r_info);
      const uint32_t sym =
          Is64 ? elf::R64_SYM(r.r_info) : elf::R32_SYM(r.r_info);
      const uint64_t where = so.load_bias + r.r_offset;
      if (type == rk.relative)
        engine_.write_t<Addr>(where,
                              static_cast<Addr>(so.load_bias + r.r_addend));
      else if (type == rk.glob_dat || type == rk.jump_slot)
        engine_.write_t<Addr>(where, static_cast<Addr>(resolve_sym(sym)));
      else if (type == rk.abs)
        engine_.write_t<Addr>(where,
                              static_cast<Addr>(resolve_sym(sym) + r.r_addend));
      else
        std::fprintf(stderr, "[loader] %s: unknown RELA type %u\n",
                     name.c_str(), type);
    }
  };
  auto apply_rel = [&](uint64_t table,
                       uint64_t bytes) {  // arm32: addend is in the slot
    for (uint64_t o = 0; o + sizeof(Rel) <= bytes; o += sizeof(Rel)) {
      const Rel r = engine_.read_t<Rel>(table + o);
      const uint32_t type = elf::R32_TYPE(r.r_info);
      const uint32_t sym = elf::R32_SYM(r.r_info);
      const uint64_t where = so.load_bias + r.r_offset;
      const Addr cur = engine_.read_t<Addr>(where);
      if (type == rk.relative)
        engine_.write_t<Addr>(where, static_cast<Addr>(cur + so.load_bias));
      else if (type == rk.glob_dat || type == rk.jump_slot)
        engine_.write_t<Addr>(where, static_cast<Addr>(resolve_sym(sym)));
      else if (type == rk.abs)
        engine_.write_t<Addr>(where, static_cast<Addr>(cur + resolve_sym(sym)));
      else
        std::fprintf(stderr, "[loader] %s: unknown REL type %u\n", name.c_str(),
                     type);
    }
  };

  // RELR: compressed R_*_RELATIVE stream. An even entry (bit0==0) is an
  // address; the slot there is biased. Following odd entries (bit0==1) are
  // bitmaps: bit i (i>=1) biases the slot at addr + i*wordsize; after a bitmap,
  // addr advances by 63*wordsize. Applies only to 64-bit here (arm64/x86_64).
  auto apply_relr = [&](uint64_t table, uint64_t bytes) {
    const uint64_t wsz = sizeof(Addr);
    uint64_t where = 0;
    for (uint64_t o = 0; o + sizeof(Addr) <= bytes; o += sizeof(Addr)) {
      const uint64_t entry = engine_.read_t<Addr>(table + o);
      if ((entry & 1) == 0) {
        where = so.load_bias + entry;
        engine_.write_t<Addr>(
            where, static_cast<Addr>(engine_.read_t<Addr>(where) + so.load_bias));
        where += wsz;
      } else {
        uint64_t bits = entry >> 1;
        for (uint64_t i = 0; bits; ++i, bits >>= 1) {
          if (bits & 1) {
            const uint64_t w = where + i * wsz;
            engine_.write_t<Addr>(
                w, static_cast<Addr>(engine_.read_t<Addr>(w) + so.load_bias));
          }
        }
        where += 63 * wsz;
      }
    }
  };
  // Android packed RELA ("APS2"): magic 'A','P','S','2' then a SLEB128 stream of
  // grouped relocations. Decodes to a flat list of {r_offset, r_info, r_addend}
  // which we feed through the same RELA handling.
  auto apply_android_rela = [&](uint64_t table, uint64_t bytes) {
    std::vector<uint8_t> buf(bytes);
    engine_.read(table, buf.data(), bytes);
    size_t p = 0;
    if (bytes < 4 || buf[0] != 'A' || buf[1] != 'P' || buf[2] != 'S' ||
        buf[3] != '2') {
      std::fprintf(stderr,
                   "[loader] %s: bad ANDROID_RELA magic (table=%#llx bytes=%llu "
                   "got=%02x%02x%02x%02x)\n",
                   name.c_str(), (unsigned long long)table,
                   (unsigned long long)bytes, bytes > 0 ? buf[0] : 0,
                   bytes > 1 ? buf[1] : 0, bytes > 2 ? buf[2] : 0,
                   bytes > 3 ? buf[3] : 0);
      return;
    }
    p = 4;
    auto sleb = [&]() -> int64_t {
      int64_t result = 0;
      int shift = 0;
      uint8_t b;
      do {
        b = buf[p++];
        result |= (int64_t)(b & 0x7f) << shift;
        shift += 7;
      } while (b & 0x80);
      if (shift < 64 && (b & 0x40)) result |= -((int64_t)1 << shift);
      return result;
    };
    int64_t reloc_count = sleb();
    int64_t reloc_offset = sleb();
    int64_t addend = 0;
    const int64_t GROUPED_BY_INFO = 1, GROUPED_BY_DELTA = 2,
                  GROUPED_BY_ADDEND = 4, GROUP_HAS_ADDEND = 8;
    int64_t done = 0;
    while (done < reloc_count && p < bytes) {
      int64_t group_size = sleb();
      int64_t group_flags = sleb();
      int64_t group_delta = 0;
      if (group_flags & GROUPED_BY_DELTA) group_delta = sleb();
      int64_t group_info = 0;
      if (group_flags & GROUPED_BY_INFO) group_info = sleb();
      const bool has_addend = group_flags & GROUP_HAS_ADDEND;
      if ((group_flags & GROUPED_BY_ADDEND) && has_addend) addend += sleb();
      for (int64_t i = 0; i < group_size; ++i) {
        reloc_offset += (group_flags & GROUPED_BY_DELTA) ? group_delta : sleb();
        const int64_t info = (group_flags & GROUPED_BY_INFO) ? group_info : sleb();
        if (has_addend && !(group_flags & GROUPED_BY_ADDEND)) addend += sleb();
        const int64_t this_addend = has_addend ? addend : 0;
        // apply like a single RELA entry
        const uint32_t type =
            Is64 ? elf::R64_TYPE(info) : elf::R32_TYPE(info);
        const uint32_t symi = Is64 ? elf::R64_SYM(info) : elf::R32_SYM(info);
        const uint64_t where = so.load_bias + reloc_offset;
        if (type == rk.relative)
          engine_.write_t<Addr>(
              where, static_cast<Addr>(so.load_bias + this_addend));
        else if (type == rk.glob_dat || type == rk.jump_slot)
          engine_.write_t<Addr>(where, static_cast<Addr>(resolve_sym(symi)));
        else if (type == rk.abs)
          engine_.write_t<Addr>(
              where, static_cast<Addr>(resolve_sym(symi) + this_addend));
      }
      done += group_size;
      if (!has_addend) addend = 0;
    }
  };

  if constexpr (Is64) {
    if (rela) apply_rela(rela, relasz);
    if (android_rela) apply_android_rela(android_rela, android_relasz);
    if (relr) apply_relr(relr, relrsz);
    if (jmprel) apply_rela(jmprel, pltrelsz);  // arm64 PLT relocs are RELA
  } else {
    if (rel) apply_rel(rel, relsz);
    if (jmprel) {  // PLT relocs follow DT_PLTREL
      if (pltrel == elf::DT_RELA)
        apply_rela(jmprel, pltrelsz);
      else
        apply_rel(jmprel, pltrelsz);
    }
  }

  // --- exports: walk dynsym; the symbol count comes from the hash table.
  // (.dynstr does NOT always follow.dynsym,.gnu.hash/.hash can sit between
  // them, so (strtab - symtab)/syment over-counts and reads junk entries.) ---
  if (symtab) {
    uint64_t nsyms = 0;
    if (hash)
      nsyms = engine_.read_t<uint32_t>(hash + 4);  // nchain
    else if (gnu_hash)
      nsyms = gnu_hash_nsyms(engine_, gnu_hash, sizeof(Addr));
    else if (strtab > symtab)
      nsyms = (strtab - symtab) / sizeof(Sym);  // last-resort heuristic
    for (uint64_t i = 1; i < nsyms; ++i) {      // index 0 is the null symbol
      const Sym s = sym_at(static_cast<uint32_t>(i));
      if (s.st_shndx == elf::SHN_UNDEF || s.st_name == 0) continue;
      const std::string nm = engine_.read_cstr(strtab + s.st_name);
      if (!nm.empty()) so.exports[nm] = so.load_bias + s.st_value;
    }
  }
  so.jni_onload = so.lookup("JNI_OnLoad");

  // --- collect init_array entries ---
  // Some packers (e.g. Virbox) strip the R_AARCH64_RELATIVE relocs that
  // normally bias .init_array slots and rely on their custom loader/_init to
  // fix them up. Our snapshot then sees raw link-time file offsets (<
  // load_bias). A correctly-relocated slot always holds an address >=
  // load_bias, so biasing only sub-bias-but-in-span values is a no-op for
  // normal SOs and recovers the real entry for the stripped-reloc case.
  for (uint64_t o = 0; o + sizeof(Addr) <= preinit_arraysz; o += sizeof(Addr)) {
    Addr fn = engine_.read_t<Addr>(preinit_array + o);
    if (fn != 0 && fn != static_cast<Addr>(-1)) {
      if (fn < so.load_bias && fn < so.size)
        fn += so.load_bias;  // unrelocated file offset
      so.preinit_array.push_back(fn);
    }
  }

  for (uint64_t o = 0; o + sizeof(Addr) <= init_arraysz; o += sizeof(Addr)) {
    Addr fn = engine_.read_t<Addr>(init_array + o);
    if (fn != 0 && fn != static_cast<Addr>(-1)) {
      if (fn < so.load_bias && fn < so.size)
        fn += so.load_bias;  // unrelocated file offset
      so.init_array.push_back(fn);
    }
  }

  for (uint64_t o = 0; o + sizeof(Addr) <= fini_arraysz; o += sizeof(Addr)) {
    Addr fn = engine_.read_t<Addr>(fini_array + o);
    if (fn != 0 && fn != static_cast<Addr>(-1)) {
      if (fn < so.load_bias && fn < so.size)
        fn += so.load_bias;  // unrelocated file offset
      so.fini_array.push_back(fn);
    }
  }

  // --- tighten per-segment protections to the real p_flags ---
  for (const Phdr& ph : loads) {
    const uint64_t seg = page_align_down(so.load_bias + ph.p_vaddr);
    const uint64_t end = page_align_up(so.load_bias + ph.p_vaddr + ph.p_memsz);
    engine_.protect(seg, end - seg, pf_to_uc(ph.p_flags));
  }

  // --- section headers (optional: often stripped in packed libs) ---
  // These let a driver reach a NON-STANDARD section a packer inserted (e.g. a
  // custom ".post_init" pointer table) and invoke it explicitly, since the
  // linker only ever runs the standard preinit/init/fini arrays.
  if (eh.e_shoff && eh.e_shnum && eh.e_shstrndx < eh.e_shnum &&
      eh.e_shoff + static_cast<uint64_t>(eh.e_shnum) * sizeof(Shdr) <= data.size()) {
    const Shdr shstr = read_at<Shdr>(data, eh.e_shoff + static_cast<uint64_t>(eh.e_shstrndx) * sizeof(Shdr));
    for (uint16_t i = 0; i < eh.e_shnum; ++i) {
      const Shdr sh = read_at<Shdr>(data, eh.e_shoff + static_cast<uint64_t>(i) * sizeof(Shdr));
      const uint64_t nameoff = shstr.sh_offset + sh.sh_name;
      if (nameoff >= data.size()) continue;
      std::string nm(reinterpret_cast<const char*>(data.data()) + nameoff);
      if (nm.empty()) continue;
      // sh_addr is 0 for non-allocated sections; bias the allocated ones.
      so.sections[nm] = SoInfo::Section{
          sh.sh_addr ? so.load_bias + sh.sh_addr : 0, sh.sh_size};
    }
  }

  std::fprintf(
      stderr,
      "[loader] %s: base=0x%llx bias=0x%llx span=0x%llx exports=%zu needed=%zu "
      "init_array=%zu JNI_OnLoad=0x%llx\n",
      name.c_str(), (unsigned long long)so.base,
      (unsigned long long)so.load_bias, (unsigned long long)span,
      so.exports.size(), so.needed.size(), so.init_array.size(),
      (unsigned long long)so.jni_onload);
  return so;
}

void ElfLoader::run_init(const SoInfo& so) {
  // Bionic's order: .preinit_array, then DT_INIT, then .init_array. Each entry
  // receives (argc, argv, envp); pass plausible empties.
  for (uint64_t fn : so.preinit_array) engine_.call(fn, {0, 0, 0}, kFiniPage);
  if (so.init) engine_.call(so.init, {0, 0, 0}, kFiniPage);
  for (uint64_t fn : so.init_array) engine_.call(fn, {0, 0, 0}, kFiniPage);
}

size_t ElfLoader::run_section_array(const SoInfo& so,
                                    const std::string& section) {
  const SoInfo::Section sec = so.section(section);
  if (!sec.addr || !sec.size) return 0;
  const int psz = engine_.pointer_size();
  size_t called = 0;
  for (uint64_t o = 0; o + psz <= sec.size; o += psz) {
    const uint64_t fn = psz == 8 ? engine_.read_t<uint64_t>(sec.addr + o)
                                 : engine_.read_t<uint32_t>(sec.addr + o);
    // Skip the empty/terminator slots the toolchain leaves behind.
    if (!fn || fn == ~uint64_t(0) || fn == 0xffffffffu) continue;
    engine_.call(fn, {0, 0, 0}, kFiniPage);
    ++called;
  }
  return called;
}

uint64_t ElfLoader::call_section(const SoInfo& so, const std::string& section) {
  const SoInfo::Section sec = so.section(section);
  if (!sec.addr) return 0;
  return engine_.call(sec.addr, {0, 0, 0}, kFiniPage);
}

void ElfLoader::run_fini(const SoInfo& so) {
  // Destructors run in the mirror order: .fini_array backwards, then DT_FINI.
  for (auto it = so.fini_array.rbegin(); it != so.fini_array.rend(); ++it)
    engine_.call(*it, {0, 0, 0}, kFiniPage);
  if (so.fini) engine_.call(so.fini, {0, 0, 0}, kFiniPage);
}

// Explicit instantiations so both paths compile in this TU.
template SoInfo ElfLoader::load_impl<true>(const std::vector<uint8_t>&,
                                           const std::string&);
template SoInfo ElfLoader::load_impl<false>(const std::vector<uint8_t>&,
                                            const std::string&);

}  // namespace vardoger
