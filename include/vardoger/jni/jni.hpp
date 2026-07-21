// vardoger: JNI bridge.
//
// Builds a JavaVM and a JNIEnv in guest memory. Each is the JNI
// double-indirection (env -> *env -> function table), and every table slot is
// an SVC trampoline whose handler implements that JNI function on the host.
// Slots default to a logging "unimplemented JNI #i" stub; the P0 subset is
// overridden with real handlers.
#pragma once

#include <cstdint>
#include <string>

#include "vardoger/engine/engine.hpp"
#include "vardoger/engine/memory.hpp"
#include "vardoger/engine/trampoline.hpp"
#include "vardoger/jni/java_runtime.hpp"

namespace vardoger {

class JniBridge {
 public:
  JniBridge(Engine& engine, Memory& mem, Trampoline& tramp, JavaRuntime& jrt);

  // Build both structures; returns the JavaVM* guest address (pass to
  // JNI_OnLoad).
  uint64_t build();

  uint64_t java_vm() const { return vm_; }   // JavaVM*  guest address
  uint64_t jni_env() const { return env_; }  // JNIEnv*  guest address

 private:
  void build_env();
  void build_vm();
  void install_env_handlers();
  void install_vm_handlers();

  // Shared Call<Type>Method[Static] implementation: read receiver+method+args
  // (per the method signature), run the host impl, write the return per
  // ret_kind
  // ('L' object, 'I' int/bool, 'V' void).
  void call_dispatch(Engine& e, bool is_static, char ret_kind);
  // Same, but args come from a va_list (the Call<Type>Method*V* variants, which
  // C++ JNI inline wrappers route through). AArch64 va_list decoding in
  // jni.cpp.
  void call_dispatch_v(Engine& e, bool is_static, char ret_kind);

  void write_ptr(uint64_t addr, uint64_t val);
  uint64_t read_ptr(uint64_t addr) const;
  void set_env(const char* name,
               Trampoline::Handler h);  // override a JNIEnv slot
  void set_vm(const char* name,
              Trampoline::Handler h);  // override a JavaVM slot

  Engine& e_;
  Memory& mem_;
  Trampoline& tramp_;
  JavaRuntime& jrt_;
  uint64_t env_ = 0, env_table_ = 0;
  uint64_t vm_ = 0, vm_table_ = 0;
};

}  // namespace vardoger
