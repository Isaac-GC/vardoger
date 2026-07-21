// vardoger: minimal DEX parser (doc 09 / M5, phase 1 of the ART class-resolution
// runtime).
//
// Parses just enough of a DEX to enumerate classes/superclasses/methods and
// locate class_defs, the input to a class-resolution loop that drives a
// packer's lazy per-class decrypt. NOT a conformant reader: header + string_ids
// + type_ids + method_ids + proto_ids + class_defs + class_data (uleb128). Grow
// on demand.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace vardoger {

class DexFile {
 public:
  struct Method {
    std::string cls;   // defining class descriptor, e.g. "Lcom/foo/Bar;"
    std::string name;  // method name
    std::string
        sig;  // shorty/proto descriptor, e.g. "(Landroid/app/Application;)V"
    uint32_t access = 0;
    uint32_t code_off = 0;  // code_item offset (0 = abstract/native)
  };
  struct ClassDef {
    std::string descriptor;  // "Lcom/foo/Bar;"
    std::string superclass;  // "Ljava/lang/Object;" ("" if NO_INDEX)
    uint32_t access = 0;
    uint32_t class_data_off = 0;
    std::vector<Method> direct_methods;
    std::vector<Method> virtual_methods;
  };

  DexFile() = default;
  explicit DexFile(std::vector<uint8_t> data) { parse(std::move(data)); }

  bool parse(std::vector<uint8_t> data);
  bool valid() const { return valid_; }
  const std::string& error() const { return err_; }

  size_t num_classes() const { return classes_.size(); }
  const std::vector<ClassDef>& classes() const { return classes_; }
  const std::vector<uint8_t>& bytes() const { return d_; }

  // code_item for a method (by its code_off from ClassDef::Method). 16-bit code
  // units.
  struct Code {
    uint16_t registers_size = 0, ins_size = 0, outs_size = 0;
    uint32_t insns_off = 0;   // file offset of the u16 instruction stream
    uint32_t insns_size = 0;  // number of u16 code units
    bool valid = false;
  };
  Code code_at(uint32_t code_off) const;
  // method_id accessor: {class, name, shorty} by global method index.
  Method method_at(uint32_t method_idx) const;
  // field_id accessor: {defining class desc, name, type desc} by global field
  // index.
  struct Field {
    std::string cls, name, type;
  };
  Field field_at(uint32_t field_idx) const;

  // Type/string accessors (bounds-checked; return "" on out-of-range).
  std::string string_at(uint32_t idx) const;  // string_ids[idx] -> MUTF-8
  std::string type_at(uint32_t idx) const;    // type_ids[idx] -> descriptor
  // Java binary name <-> descriptor helpers: "Lcom/foo/Bar;" <-> "com.foo.Bar".
  static std::string descriptor_to_binary(const std::string& desc);
  static std::string binary_to_descriptor(const std::string& bin);

 private:
  void parse_class_data(ClassDef& c) const;
  Method decode_method(uint32_t& method_idx_acc, uint32_t& p, uint32_t& access,
                       uint32_t& code_off) const;

  std::vector<uint8_t> d_;
  bool valid_ = false;
  std::string err_;
  // table offsets/counts from the header
  uint32_t string_ids_off_ = 0, string_ids_size_ = 0;
  uint32_t type_ids_off_ = 0, type_ids_size_ = 0;
  uint32_t proto_ids_off_ = 0, proto_ids_size_ = 0;
  uint32_t field_ids_off_ = 0, field_ids_size_ = 0;
  uint32_t method_ids_off_ = 0, method_ids_size_ = 0;
  uint32_t class_defs_off_ = 0, class_defs_size_ = 0;
  std::vector<ClassDef> classes_;
};

}  // namespace vardoger
