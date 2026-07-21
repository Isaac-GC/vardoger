// vardoger: minimal host-side Java runtime model.
//
// The JNI bridge delegates here. A jobject/jclass/jstring/jmethodID/jfieldID
// exposed to the guest is an opaque integer *handle* into this table; the guest
// only passes them back to JNI functions. M3 added classes/methods/strings +
// RegisterNatives capture; M4 adds objects, instance/static fields, and
// host-impl method dispatch, enough to fake the Android Context graph
//.
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#include "vardoger/engine/engine.hpp"
#include "vardoger/engine/memory.hpp"

namespace vardoger {

// A Java value as seen at the JNI boundary. Object handles index this runtime;
// primitives are widened into i (int/long/bool/byte/char/short) or d
// (float/double).
struct DvmValue {
  enum Kind { Void, Int, Double, Object } kind = Void;
  int64_t i = 0;
  double d = 0;
  uint64_t obj = 0;

  static DvmValue V() { return {}; }
  static DvmValue I(int64_t x) {
    DvmValue r;
    r.kind = Int;
    r.i = x;
    return r;
  }
  static DvmValue D(double x) {
    DvmValue r;
    r.kind = Double;
    r.d = x;
    return r;
  }
  static DvmValue O(uint64_t h) {
    DvmValue r;
    r.kind = Object;
    r.obj = h;
    return r;
  }
};

class JavaRuntime {
 public:
  // (runtime, receiver-handle, args) -> return value. Implements one Java
  // method.
  using HostMethod = std::function<DvmValue(JavaRuntime&, uint64_t,
                                            const std::vector<DvmValue>&)>;
  // Notified whenever bytes are committed to a byte[] / passed to a ClassLoader
  // ctor, the extractor uses this to capture DEX that never touches guest
  // memory.
  using BytesObserver =
      std::function<void(const std::vector<uint8_t>&, const std::string& src)>;

  struct Native {
    std::string cls, name, sig;
    uint64_t fn;
  };

  // Handles are real guest addresses (shadow objects), so native code can
  // dereference a jobject like an ART object without faulting.
  JavaRuntime(Engine& engine, Memory& mem) : e_(engine), mem_(mem) {}

  // --- classes / members ---
  uint64_t find_class(const std::string& name);
  // --- class hierarchy (for IsInstanceOf/IsAssignableFrom/GetSuperclass) ---
  // vardoger's class model is otherwise flat; register superclass edges so
  // packers that gate on `app instanceof ContextWrapper` etc. take the right
  // branch. register_android_hierarchy() seeds the common Android chain.
  // is_subclass(sub, sup) walks the chain (by class name).
  void set_superclass(const std::string& cls, const std::string& super);
  std::string superclass_of(const std::string& cls) const;
  bool is_subclass(const std::string& sub, const std::string& sup) const;
  void register_android_hierarchy();
  uint64_t get_method_id(uint64_t clazz, const std::string& name,
                         const std::string& sig, bool is_static);
  uint64_t get_field_id(uint64_t clazz, const std::string& name,
                        const std::string& sig, bool is_static);
  void register_native(uint64_t clazz, const std::string& name,
                       const std::string& sig, uint64_t fn);

  // --- objects / strings / arrays ---
  uint64_t new_object(const std::string& cls);
  uint64_t new_string_utf(const std::string& s);
  uint64_t new_byte_array(std::vector<uint8_t> bytes);
  uint64_t new_byte_array(size_t len);  // zero-filled
  uint64_t new_object_array(std::vector<uint64_t> elems);
  uint64_t class_of(uint64_t obj) const;  // -> jclass handle, or 0

  std::vector<uint8_t>* bytes_ptr(uint64_t arr);  // mutable byte[] backing
  const std::vector<uint8_t>* bytes_view(uint64_t arr) const;
  size_t array_length(uint64_t arr) const;
  uint64_t object_array_element(uint64_t arr, size_t i) const;
  void set_object_array_element(uint64_t arr, size_t i, uint64_t val);

  // --- byte capture (DEX-in-byte[] trigger) ---
  void set_bytes_observer(BytesObserver o) { bytes_observer_ = std::move(o); }
  void notify_bytes(const std::vector<uint8_t>& b,
                    const std::string& src) const {
    if (bytes_observer_) bytes_observer_(b, src);
  }

  // --- fields ---
  void set_field(uint64_t obj, const std::string& name, DvmValue v);
  DvmValue get_field(uint64_t obj, const std::string& name) const;
  // Default value returned by get_field when an instance lacks the field, lets
  // a driver answer framework field reads (Context.mPackageInfo, ...) off any
  // object.
  void set_field_default(const std::string& name, DvmValue v) {
    field_defaults_[name] = v;
  }
  void set_static(const std::string& cls, const std::string& name, DvmValue v);
  DvmValue get_static(const std::string& cls, const std::string& name) const;

  // --- method dispatch ---
  void register_method(const std::string& name,
                       HostMethod fn);  // keyed by method name
  DvmValue call_method(uint64_t mid, uint64_t self,
                       const std::vector<DvmValue>& args);

  // --- accessors used by the JNI bridge ---
  std::string class_name(uint64_t handle) const;
  const std::string* string_of(uint64_t handle) const;
  std::string method_name(uint64_t mid) const;
  std::string method_sig(uint64_t mid) const;
  std::string field_name(uint64_t fid) const;
  std::string field_owner(uint64_t fid) const;

  const std::vector<Native>& registered() const { return registered_; }
  uint64_t lookup_native(const std::string& cls, const std::string& name) const;

  // --- pending JNI exception (minimal propagation) ---
  // A host method (e.g. a synthetic loadClass that "can't find" a class) can
  // raise a pending exception; the JNI bridge's
  // ExceptionCheck/ExceptionOccurred report it and ExceptionClear clears it.
  // Faithful to the "probe a class, catch ClassNotFoundException, then
  // decrypt+define it" pattern packers use. Default 0 = no exception, so
  // ExceptionCheck stays 0 (unchanged behavior) unless a handler sets it.
  void set_pending_exception(uint64_t exc) { pending_exc_ = exc; }
  uint64_t pending_exception() const { return pending_exc_; }
  void clear_pending_exception() { pending_exc_ = 0; }

 private:
  uint64_t pending_exc_ = 0;

  struct Record {
    enum Kind {
      Class,
      Method,
      Field,
      String,
      Object,
      ByteArray,
      ObjectArray
    } kind;
    std::string name, sig, owner, utf8;
    bool is_static = false;
    uint64_t native_fn = 0;
    std::map<std::string, DvmValue> fields;  // instance fields (Object records)
    std::vector<uint8_t> bytes;              // ByteArray
    std::vector<uint64_t> elems;             // ObjectArray
  };
  uint64_t alloc(Record r);  // allocates a guest shadow, returns its address
  Record* get(uint64_t h);
  const Record* get(uint64_t h) const;
  static std::string skey(const std::string& cls, const std::string& name) {
    return cls + "\x1f" + name;
  }

  Engine& e_;
  Memory& mem_;
  std::unordered_map<uint64_t, Record>
      handles_;  // keyed by shadow address (0 == null)
  std::unordered_map<std::string, uint64_t> class_by_name_;
  std::unordered_map<std::string, std::string>
      superclass_;  // class name -> superclass name
  std::unordered_map<std::string, uint64_t> member_cache_;
  std::unordered_map<std::string, DvmValue>
      static_fields_;  // "cls\x1fname" -> value
  std::unordered_map<std::string, DvmValue>
      field_defaults_;  // field name -> fallback value
  std::unordered_map<std::string, HostMethod>
      host_methods_;  // method name -> impl
  std::vector<Native> registered_;
  BytesObserver bytes_observer_;
};

}  // namespace vardoger
