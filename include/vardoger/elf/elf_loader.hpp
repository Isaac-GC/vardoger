// vardoger: ELF loader.
//
// Maps an Android .so into guest memory the way the bionic linker would (minus
// the parts we fake): parse, map PT_LOAD, apply relocations, resolve imports to
// trampolines, expose exports, run init_array.
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "vardoger/engine/engine.hpp"
#include "vardoger/engine/memory.hpp"

namespace vardoger {

struct SoInfo {
  std::string name;
  bool is64 = true;
  uint64_t load_bias = 0;   // add to a vaddr to get its guest address
  uint64_t base = 0;        // start of the mapped span
  uint64_t size = 0;        // mapped span length
  uint64_t jni_onload = 0;  // resolved address of JNI_OnLoad, or 0
  uint64_t init = 0;        // DT_INIT, or 0
  uint64_t fini = 0;        // DT_FINI, or 0
  // Constructors/destructors, in the order the bionic linker uses them:
  // preinit_array -> DT_INIT -> init_array on load, and
  // fini_array (REVERSE order) -> DT_FINI on unload.
  std::vector<uint64_t> preinit_array;
  std::vector<uint64_t> init_array;
  std::vector<uint64_t> fini_array;
  std::vector<std::string> needed;  // DT_NEEDED dependency names
  std::map<std::string, uint64_t>
      exports;  // exported symbol name -> guest address
  // Named sections (from the section headers, when not stripped), so a driver
  // can reach a NON-STANDARD one a packer inserted — e.g. a custom ".post_init"
  // holding extra constructor pointers that the linker never runs for you.
  struct Section {
    uint64_t addr = 0;  // guest address (0 if the section isn't allocated)
    uint64_t size = 0;
  };
  std::map<std::string, Section> sections;
  Section section(const std::string& n) const {
    auto it = sections.find(n);
    return it == sections.end() ? Section{} : it->second;
  }

  uint64_t lookup(const std::string& sym) const {
    auto it = exports.find(sym);
    return it == exports.end() ? 0 : it->second;
  }
};

class ElfLoader {
 public:
  // Resolves an undefined (imported) symbol name to a guest address (a stub
  // trampoline). Return 0 to leave it unresolved (logged).
  using ImportResolver = std::function<uint64_t(const std::string& name)>;

  ElfLoader(Engine& engine, Memory& mem) : engine_(engine), mem_(mem) {}

  void set_import_resolver(ImportResolver r) { resolve_import_ = std::move(r); }

  SoInfo load(const std::string& path);
  SoInfo load_bytes(std::vector<uint8_t> data, std::string name);

  // Run DT_INIT then each DT_INIT_ARRAY entry (where packers self-decrypt).
  void run_init(const SoInfo& so);
  // Run the destructors (fini_array in reverse, then DT_FINI). Packers
  // sometimes hide cleanup/anti-analysis work here.
  void run_fini(const SoInfo& so);
  // Treat a section's contents as an array of function pointers and call each
  // (like .init_array). For packer-inserted sections such as ".post_init" that
  // the linker doesn't know about. Returns how many entries were called.
  // Entries of 0/-1 are skipped, and each is called with (argc, argv, envp)=0.
  size_t run_section_array(const SoInfo& so, const std::string& section);
  // Call a section's start address as a function (for a section that IS code
  // rather than a pointer table). Returns the guest return value.
  uint64_t call_section(const SoInfo& so, const std::string& section);

 private:
  template <bool Is64>
  SoInfo load_impl(const std::vector<uint8_t>& data, const std::string& name);

  Engine& engine_;
  Memory& mem_;
  ImportResolver resolve_import_;
};

}  // namespace vardoger
