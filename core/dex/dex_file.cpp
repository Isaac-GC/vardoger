// vardoger: minimal DEX parser (see include/vardoger/dex/dex_file.hpp).
#include "vardoger/dex/dex_file.hpp"

#include <cstring>

namespace vardoger {
namespace {
constexpr uint32_t kNoIndex = 0xffffffffu;

inline uint32_t rd32(const std::vector<uint8_t>& d, size_t o) {
  if (o + 4 > d.size()) return 0;
  uint32_t v;
  std::memcpy(&v, d.data() + o, 4);
  return v;
}
// uleb128 read at *p (advances p). Bounded by d.size().
inline uint32_t uleb(const std::vector<uint8_t>& d, uint32_t& p) {
  uint32_t result = 0;
  int shift = 0;
  for (int i = 0; i < 5 && p < d.size(); ++i) {
    uint8_t b = d[p++];
    result |= uint32_t(b & 0x7f) << shift;
    if (!(b & 0x80)) break;
    shift += 7;
  }
  return result;
}
}  // namespace

DexFile::Code DexFile::code_at(uint32_t code_off) const {
  Code c;
  if (!code_off || code_off + 16 > d_.size()) return c;
  std::memcpy(&c.registers_size, d_.data() + code_off + 0, 2);
  std::memcpy(&c.ins_size, d_.data() + code_off + 2, 2);
  std::memcpy(&c.outs_size, d_.data() + code_off + 4, 2);
  // +6 tries_size(u16), +8 debug_info_off(u32), +12 insns_size(u32), +16
  // insns[]
  std::memcpy(&c.insns_size, d_.data() + code_off + 12, 4);
  c.insns_off = code_off + 16;
  c.valid = (c.insns_off + size_t(c.insns_size) * 2 <= d_.size());
  return c;
}

DexFile::Method DexFile::method_at(uint32_t method_idx) const {
  Method m;
  if (method_idx >= method_ids_size_) return m;
  size_t mo = method_ids_off_ + size_t(method_idx) * 8;
  uint16_t cls_idx = 0, proto_idx = 0;
  uint32_t name_idx = 0;
  if (mo + 8 <= d_.size()) {
    std::memcpy(&cls_idx, d_.data() + mo, 2);
    std::memcpy(&proto_idx, d_.data() + mo + 2, 2);
    std::memcpy(&name_idx, d_.data() + mo + 4, 4);
  }
  m.cls = type_at(cls_idx);
  m.name = string_at(name_idx);
  if (proto_idx < proto_ids_size_)
    m.sig = string_at(rd32(d_, proto_ids_off_ + size_t(proto_idx) * 12));
  return m;
}

DexFile::Field DexFile::field_at(uint32_t field_idx) const {
  Field f;
  if (field_idx >= field_ids_size_) return f;
  size_t fo = field_ids_off_ + size_t(field_idx) * 8;
  uint16_t cls_idx = 0, type_idx = 0;
  uint32_t name_idx = 0;
  if (fo + 8 <= d_.size()) {
    std::memcpy(&cls_idx, d_.data() + fo, 2);
    std::memcpy(&type_idx, d_.data() + fo + 2, 2);
    std::memcpy(&name_idx, d_.data() + fo + 4, 4);
  }
  f.cls = type_at(cls_idx);
  f.type = type_at(type_idx);
  f.name = string_at(name_idx);
  return f;
}

std::string DexFile::string_at(uint32_t idx) const {
  if (idx >= string_ids_size_) return {};
  uint32_t data_off = rd32(d_, string_ids_off_ + idx * 4);
  if (data_off >= d_.size()) return {};
  uint32_t p = data_off;
  uint32_t len = uleb(
      d_, p);  // char count (MUTF-8); byte length is until NUL, read raw bytes
  (void)len;
  std::string s;
  while (p < d_.size() && d_[p]) s += char(d_[p++]);
  return s;
}

std::string DexFile::type_at(uint32_t idx) const {
  if (idx == kNoIndex || idx >= type_ids_size_) return {};
  return string_at(rd32(d_, type_ids_off_ + idx * 4));
}

std::string DexFile::descriptor_to_binary(const std::string& desc) {
  if (desc.size() >= 2 && desc.front() == 'L' && desc.back() == ';') {
    std::string s = desc.substr(1, desc.size() - 2);
    for (char& c : s)
      if (c == '/') c = '.';
    return s;
  }
  return desc;
}
std::string DexFile::binary_to_descriptor(const std::string& bin) {
  if (!bin.empty() && bin.find('/') == std::string::npos &&
      bin.find('.') != std::string::npos) {
    std::string s = bin;
    for (char& c : s)
      if (c == '.') c = '/';
    return "L" + s + ";";
  }
  if (!bin.empty() && bin.front() != 'L') return "L" + bin + ";";
  return bin;
}

DexFile::Method DexFile::decode_method(uint32_t& method_idx_acc, uint32_t& p,
                                       uint32_t& access,
                                       uint32_t& code_off) const {
  method_idx_acc += uleb(d_, p);  // method_idx_diff
  access = uleb(d_, p);
  code_off = uleb(d_, p);
  Method m;
  m.access = access;
  m.code_off = code_off;
  // method_id: {u16 class_idx, u16 proto_idx, u32 name_idx}
  if (method_idx_acc < method_ids_size_) {
    size_t mo = method_ids_off_ + size_t(method_idx_acc) * 8;
    uint16_t cls_idx = 0, proto_idx = 0;
    uint32_t name_idx = 0;
    if (mo + 8 <= d_.size()) {
      std::memcpy(&cls_idx, d_.data() + mo, 2);
      std::memcpy(&proto_idx, d_.data() + mo + 2, 2);
      std::memcpy(&name_idx, d_.data() + mo + 4, 4);
    }
    m.cls = type_at(cls_idx);
    m.name = string_at(name_idx);
    // proto shorty (string) for a light signature
    if (proto_idx < proto_ids_size_) {
      uint32_t shorty_idx =
          rd32(d_, proto_ids_off_ +
                       size_t(proto_idx) * 12);  // proto_id[0]=shorty_idx
      m.sig = string_at(shorty_idx);
    }
  }
  return m;
}

void DexFile::parse_class_data(ClassDef& c) const {
  if (!c.class_data_off || c.class_data_off >= d_.size()) return;
  uint32_t p = c.class_data_off;
  uint32_t static_fields = uleb(d_, p);
  uint32_t instance_fields = uleb(d_, p);
  uint32_t direct_methods = uleb(d_, p);
  uint32_t virtual_methods = uleb(d_, p);
  // skip fields: each = {field_idx_diff uleb, access uleb}
  for (uint32_t i = 0; i < static_fields + instance_fields; ++i) {
    uleb(d_, p);
    uleb(d_, p);
  }
  uint32_t midx = 0, acc = 0, coff = 0;
  for (uint32_t i = 0; i < direct_methods; ++i)
    c.direct_methods.push_back(decode_method(midx, p, acc, coff));
  midx = 0;
  for (uint32_t i = 0; i < virtual_methods; ++i)
    c.virtual_methods.push_back(decode_method(midx, p, acc, coff));
}

bool DexFile::parse(std::vector<uint8_t> data) {
  d_ = std::move(data);
  valid_ = false;
  err_.clear();
  classes_.clear();
  if (d_.size() < 0x70 || std::memcmp(d_.data(), "dex\n", 4) != 0) {
    err_ = "bad magic/too small";
    return false;
  }
  string_ids_size_ = rd32(d_, 0x38);
  string_ids_off_ = rd32(d_, 0x3c);
  type_ids_size_ = rd32(d_, 0x40);
  type_ids_off_ = rd32(d_, 0x44);
  proto_ids_size_ = rd32(d_, 0x48);
  proto_ids_off_ = rd32(d_, 0x4c);
  field_ids_size_ = rd32(d_, 0x50);
  field_ids_off_ = rd32(d_, 0x54);
  method_ids_size_ = rd32(d_, 0x58);
  method_ids_off_ = rd32(d_, 0x5c);
  class_defs_size_ = rd32(d_, 0x60);
  class_defs_off_ = rd32(d_, 0x64);
  // sanity
  if (class_defs_off_ + size_t(class_defs_size_) * 32 > d_.size()) {
    err_ = "class_defs OOB";
    return false;
  }
  classes_.reserve(class_defs_size_);
  for (uint32_t i = 0; i < class_defs_size_; ++i) {
    size_t o = class_defs_off_ + size_t(i) * 32;
    ClassDef c;
    c.descriptor = type_at(rd32(d_, o + 0));
    c.access = rd32(d_, o + 4);
    c.superclass = type_at(rd32(d_, o + 8));
    c.class_data_off = rd32(d_, o + 24);
    parse_class_data(c);
    classes_.push_back(std::move(c));
  }
  valid_ = true;
  return true;
}

}  // namespace vardoger
