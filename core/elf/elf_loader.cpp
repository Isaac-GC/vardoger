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
  int64_t pltrel = 0;
  uint64_t init_array = 0, init_arraysz = 0;
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
        case elf::DT_HASH:
          hash = so.load_bias + d.d_val;
          break;
        case elf::DT_GNU_HASH:
          gnu_hash = so.load_bias + d.d_val;
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

  if constexpr (Is64) {
    if (rela) apply_rela(rela, relasz);
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
  for (uint64_t o = 0; o + sizeof(Addr) <= init_arraysz; o += sizeof(Addr)) {
    Addr fn = engine_.read_t<Addr>(init_array + o);
    if (fn != 0 && fn != static_cast<Addr>(-1)) {
      if (fn < so.load_bias && fn < so.size)
        fn += so.load_bias;  // unrelocated file offset
      so.init_array.push_back(fn);
    }
  }

  // --- tighten per-segment protections to the real p_flags ---
  for (const Phdr& ph : loads) {
    const uint64_t seg = page_align_down(so.load_bias + ph.p_vaddr);
    const uint64_t end = page_align_up(so.load_bias + ph.p_vaddr + ph.p_memsz);
    engine_.protect(seg, end - seg, pf_to_uc(ph.p_flags));
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
  // init functions receive (argc, argv, envp); pass plausible empties.
  if (so.init) engine_.call(so.init, {0, 0, 0}, kFiniPage);
  for (uint64_t fn : so.init_array) engine_.call(fn, {0, 0, 0}, kFiniPage);
}

// Explicit instantiations so both paths compile in this TU.
template SoInfo ElfLoader::load_impl<true>(const std::vector<uint8_t>&,
                                           const std::string&);
template SoInfo ElfLoader::load_impl<false>(const std::vector<uint8_t>&,
                                            const std::string&);

}  // namespace vardoger
