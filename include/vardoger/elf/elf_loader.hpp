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
  std::vector<uint64_t> init_array;
  std::vector<std::string> needed;  // DT_NEEDED dependency names
  std::map<std::string, uint64_t>
      exports;  // exported symbol name -> guest address

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

 private:
  template <bool Is64>
  SoInfo load_impl(const std::vector<uint8_t>& data, const std::string& name);

  Engine& engine_;
  Memory& mem_;
  ImportResolver resolve_import_;
};

}  // namespace vardoger
