#include "vardoger/jni/java_runtime.hpp"

#include <cstdio>

namespace vardoger {

namespace {
constexpr size_t kShadowSize =
    0x80;  // per-object guest shadow (zeroed); room for
           // native code that reads object fields up to +0x78
// ART-ish object layout the shadow mimics (compressed refs, 4-byte fields):
//   +0x0 class ref   +0x4 monitor   +0x8 (array) length   ... +0xc.. fields
constexpr uint64_t kClassOff = 0x00;
constexpr uint64_t kLengthOff = 0x08;
}  // namespace

uint64_t JavaRuntime::alloc(Record r) {
  // The shadow is a real guest address; native code may dereference it. The
  // Java region is freshly-mapped zero, so unset fields read 0 (no fault).
  const uint64_t addr = mem_.java_alloc(kShadowSize);
  handles_.emplace(addr, std::move(r));
  return addr;
}
JavaRuntime::Record* JavaRuntime::get(uint64_t h) {
  auto it = handles_.find(h);
  return it == handles_.end() ? nullptr : &it->second;
}
const JavaRuntime::Record* JavaRuntime::get(uint64_t h) const {
  auto it = handles_.find(h);
  return it == handles_.end() ? nullptr : &it->second;
}

uint64_t JavaRuntime::find_class(const std::string& name) {
  auto it = class_by_name_.find(name);
  if (it != class_by_name_.end()) return it->second;
  Record r;
  r.kind = Record::Class;
  r.name = name;
  const uint64_t h = alloc(std::move(r));
  class_by_name_[name] = h;
  e_.write_t<uint32_t>(
      h + 0, static_cast<uint32_t>(h));  // class-of-class = self (valid ptr)
  return h;
}

void JavaRuntime::set_superclass(const std::string& cls,
                                 const std::string& super) {
  if (!cls.empty() && !super.empty() && cls != super) superclass_[cls] = super;
}

std::string JavaRuntime::superclass_of(const std::string& cls) const {
  auto it = superclass_.find(cls);
  return it == superclass_.end() ? std::string() : it->second;
}

bool JavaRuntime::is_subclass(const std::string& sub,
                              const std::string& sup) const {
  if (sub == sup || sup == "java/lang/Object") return true;
  std::string c = sub;
  for (int i = 0; i < 64 && !c.empty(); ++i) {  // bounded chain walk
    if (c == sup) return true;
    auto it = superclass_.find(c);
    if (it == superclass_.end()) break;
    c = it->second;
  }
  return false;
}

void JavaRuntime::register_android_hierarchy() {
  // The common Android chain packers probe (Application is-a ContextWrapper
  // is-a Context).
  set_superclass("android/content/ContextWrapper", "android/content/Context");
  set_superclass("android/app/Application", "android/content/ContextWrapper");
  set_superclass("android/app/Service", "android/content/ContextWrapper");
  set_superclass("android/app/Activity", "android/content/ContextWrapper");
  set_superclass("dalvik/system/BaseDexClassLoader", "java/lang/ClassLoader");
  set_superclass("dalvik/system/PathClassLoader",
                 "dalvik/system/BaseDexClassLoader");
  set_superclass("dalvik/system/DexClassLoader",
                 "dalvik/system/BaseDexClassLoader");
  // Packer stub apps subclass Application; register the known ones.
  set_superclass("com/stub/StubApp", "android/app/Application");
}

uint64_t JavaRuntime::get_method_id(uint64_t clazz, const std::string& name,
                                    const std::string& sig, bool is_static) {
  const std::string owner = class_name(clazz);
  const std::string key =
      owner + "|" + (is_static ? "S" : "v") + "M|" + name + "|" + sig;
  auto it = member_cache_.find(key);
  if (it != member_cache_.end()) return it->second;
  Record r;
  r.kind = Record::Method;
  r.name = name;
  r.sig = sig;
  r.owner = owner;
  r.is_static = is_static;
  const uint64_t h = alloc(std::move(r));
  member_cache_[key] = h;
  return h;
}

uint64_t JavaRuntime::get_field_id(uint64_t clazz, const std::string& name,
                                   const std::string& sig, bool is_static) {
  const std::string owner = class_name(clazz);
  const std::string key =
      owner + "|" + (is_static ? "S" : "v") + "F|" + name + "|" + sig;
  auto it = member_cache_.find(key);
  if (it != member_cache_.end()) return it->second;
  Record r;
  r.kind = Record::Field;
  r.name = name;
  r.sig = sig;
  r.owner = owner;
  r.is_static = is_static;
  const uint64_t h = alloc(std::move(r));
  member_cache_[key] = h;
  return h;
}

void JavaRuntime::register_native(uint64_t clazz, const std::string& name,
                                  const std::string& sig, uint64_t fn) {
  const uint64_t mid = get_method_id(clazz, name, sig, /*is_static=*/false);
  get(mid)->native_fn = fn;
  registered_.push_back({class_name(clazz), name, sig, fn});
}

uint64_t JavaRuntime::new_object(const std::string& cls) {
  Record r;
  r.kind = Record::Object;
  r.owner = cls;
  const uint64_t h = alloc(std::move(r));
  e_.write_t<uint32_t>(h + kClassOff,
                       static_cast<uint32_t>(find_class(cls)));  // class ref
  return h;
}

uint64_t JavaRuntime::new_string_utf(const std::string& s) {
  Record r;
  r.kind = Record::String;
  r.utf8 = s;
  const uint64_t h = alloc(std::move(r));
  e_.write_t<uint32_t>(h + kClassOff,
                       static_cast<uint32_t>(find_class("java/lang/String")));
  return h;
}

uint64_t JavaRuntime::new_byte_array(std::vector<uint8_t> bytes) {
  const size_t n = bytes.size();
  Record r;
  r.kind = Record::ByteArray;
  r.bytes = std::move(bytes);
  const uint64_t h = alloc(std::move(r));
  e_.write_t<uint32_t>(h + kClassOff, static_cast<uint32_t>(find_class("[B")));
  e_.write_t<uint32_t>(h + kLengthOff,
                       static_cast<uint32_t>(n));  // ART array length slot
  return h;
}
uint64_t JavaRuntime::new_byte_array(size_t len) {
  Record r;
  r.kind = Record::ByteArray;
  r.bytes.assign(len, 0);
  const uint64_t h = alloc(std::move(r));
  e_.write_t<uint32_t>(h + kClassOff, static_cast<uint32_t>(find_class("[B")));
  e_.write_t<uint32_t>(h + kLengthOff, static_cast<uint32_t>(len));
  return h;
}
uint64_t JavaRuntime::new_object_array(std::vector<uint64_t> elems) {
  const size_t n = elems.size();
  Record r;
  r.kind = Record::ObjectArray;
  r.elems = std::move(elems);
  const uint64_t h = alloc(std::move(r));
  e_.write_t<uint32_t>(
      h + kClassOff, static_cast<uint32_t>(find_class("[Ljava/lang/Object;")));
  e_.write_t<uint32_t>(h + kLengthOff, static_cast<uint32_t>(n));
  return h;
}
std::vector<uint8_t>* JavaRuntime::bytes_ptr(uint64_t arr) {
  Record* r = get(arr);
  return (r && r->kind == Record::ByteArray) ? &r->bytes : nullptr;
}
const std::vector<uint8_t>* JavaRuntime::bytes_view(uint64_t arr) const {
  const Record* r = get(arr);
  return (r && r->kind == Record::ByteArray) ? &r->bytes : nullptr;
}
size_t JavaRuntime::array_length(uint64_t arr) const {
  const Record* r = get(arr);
  if (!r) return 0;
  if (r->kind == Record::ByteArray) return r->bytes.size();
  if (r->kind == Record::ObjectArray) return r->elems.size();
  return 0;
}
uint64_t JavaRuntime::object_array_element(uint64_t arr, size_t i) const {
  const Record* r = get(arr);
  if (r && r->kind == Record::ObjectArray && i < r->elems.size())
    return r->elems[i];
  return 0;
}
void JavaRuntime::set_object_array_element(uint64_t arr, size_t i,
                                           uint64_t val) {
  Record* r = get(arr);
  if (r && r->kind == Record::ObjectArray && i < r->elems.size())
    r->elems[i] = val;
}

uint64_t JavaRuntime::class_of(uint64_t obj) const {
  const Record* r = get(obj);
  if (!r) return 0;
  if (r->kind == Record::Object) {
    auto it = class_by_name_.find(r->owner);
    return it == class_by_name_.end() ? 0 : it->second;
  }
  if (r->kind == Record::String) {
    auto it = class_by_name_.find("java/lang/String");
    return it == class_by_name_.end() ? 0 : it->second;
  }
  return 0;
}

void JavaRuntime::set_field(uint64_t obj, const std::string& name, DvmValue v) {
  if (Record* r = get(obj)) r->fields[name] = v;
}
DvmValue JavaRuntime::get_field(uint64_t obj, const std::string& name) const {
  const Record* r = get(obj);
  if (r) {
    auto it = r->fields.find(name);
    if (it != r->fields.end()) return it->second;
  }
  // Fallback: a per-field default (the bytecode often reads framework fields
  // like Context.mPackageInfo off objects we didn't construct, one default
  // serves them all).
  auto d = field_defaults_.find(name);
  return d == field_defaults_.end() ? DvmValue::V() : d->second;
}
void JavaRuntime::set_static(const std::string& cls, const std::string& name,
                             DvmValue v) {
  static_fields_[skey(cls, name)] = v;
}
DvmValue JavaRuntime::get_static(const std::string& cls,
                                 const std::string& name) const {
  auto it = static_fields_.find(skey(cls, name));
  return it == static_fields_.end() ? DvmValue::V() : it->second;
}

void JavaRuntime::register_method(const std::string& name, HostMethod fn) {
  host_methods_[name] = std::move(fn);
}
DvmValue JavaRuntime::call_method(uint64_t mid, uint64_t self,
                                  const std::vector<DvmValue>& args) {
  const Record* mr = get(mid);
  const std::string name =
      (mr && mr->kind == Record::Method) ? mr->name : std::string{};
  const std::string owner =
      (mr && mr->kind == Record::Method) ? mr->owner : std::string{};
  // Class-qualified dispatch first ("owner#name") so ambiguous names
  // (<init>/valueOf/append) route by declaring class; then fall back to by-name
  // (unique framework methods).
  if (!owner.empty()) {
    auto qit = host_methods_.find(owner + "#" + name);
    if (qit != host_methods_.end()) return qit->second(*this, self, args);
  }
  auto it = host_methods_.find(name);
  if (it == host_methods_.end()) {
    std::fprintf(stderr, "[java] no host impl for method '%s%s%s' (mid=%llu)\n",
                 owner.c_str(), owner.empty() ? "" : "#", name.c_str(),
                 static_cast<unsigned long long>(mid));
    return DvmValue::V();
  }
  return it->second(*this, self, args);
}

std::string JavaRuntime::class_name(uint64_t h) const {
  const Record* r = get(h);
  return (r && r->kind == Record::Class) ? r->name : std::string{};
}
const std::string* JavaRuntime::string_of(uint64_t h) const {
  const Record* r = get(h);
  return (r && r->kind == Record::String) ? &r->utf8 : nullptr;
}
std::string JavaRuntime::method_name(uint64_t mid) const {
  const Record* r = get(mid);
  return (r && r->kind == Record::Method) ? r->name : std::string{};
}
std::string JavaRuntime::method_sig(uint64_t mid) const {
  const Record* r = get(mid);
  return (r && r->kind == Record::Method) ? r->sig : std::string{};
}
std::string JavaRuntime::field_name(uint64_t fid) const {
  const Record* r = get(fid);
  return (r && r->kind == Record::Field) ? r->name : std::string{};
}
std::string JavaRuntime::field_owner(uint64_t fid) const {
  const Record* r = get(fid);
  return (r && r->kind == Record::Field) ? r->owner : std::string{};
}

uint64_t JavaRuntime::lookup_native(const std::string& cls,
                                    const std::string& name) const {
  for (const Native& n : registered_)
    if (n.cls == cls && n.name == name) return n.fn;
  // Fallback: match by method name alone when it is unique among registered
  // natives. Packers often RegisterNatives with a jclass whose name we never
  // recorded (obtained via a cached ref rather than our FindClass), leaving
  // n.cls empty; the obfuscated method names are globally unique, so a lone
  // name match is safe and lets drivers still resolve the fn.
  uint64_t hit = 0;
  int count = 0;
  for (const Native& n : registered_)
    if (n.name == name) {
      hit = n.fn;
      ++count;
    }
  return count == 1 ? hit : 0;
}

}  // namespace vardoger
