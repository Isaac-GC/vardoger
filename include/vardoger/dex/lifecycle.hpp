// vardoger: generic ART class-resolution lifecycle runner (task #12).
//
// Drives a packer stub's Java lifecycle
// (Application.attachBaseContext/onCreate, custom ClassLoader.loadClass) with
// the mini-Dalvik interpreter so the packer's natives fire IN ORDER via the JNI
// bridge and its lazy class-load decrypt triggers. GENERIC: works for any stub
// DEX + RegisterNatives'd packer (classic Jiagu, ijiami, ...); packer specifics
// stay in the driver.
//
// on_invoke resolves each DEX method by InvokeKind: super -> declared
// SUPERclass; virtual/interface
// -> the receiver's actual class (so overrides run); direct/static -> declared
// type. Then dispatches: interpreted (re-enter Dalvik) | packer native
// (Scheduler::run via the JNI ABI) | framework (JavaRuntime host method by
// name).
#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "vardoger/dex/dalvik.hpp"
#include "vardoger/dex/dex_file.hpp"

namespace vardoger {

class JavaRuntime;
class Scheduler;

// Register host implementations of the common java.lang / java.io framework
// methods packer stubs + natives lean on (StringBuilder, String, Boolean,
// Integer, File, ...). By-name (coarse) but enough for the decrypt lifecycle.
// Call once after JavaRuntime setup. GENERIC (jiagu / ijiami / ...).
void register_java_framework(JavaRuntime& jrt);

class LifecycleRunner {
 public:
  // env = the JNIEnv* handle (jni.jni_env()); natives are called as (env,
  // this|jclass, args...).
  LifecycleRunner(const DexFile& dex, JavaRuntime& jrt, Scheduler& sched,
                  uint64_t env);

  bool trace = false;  // log each invoke dispatch
  std::string entry_class_fallback =
      "com.stub.StubApp";  // substituted for a null loadClass name

  // ── Generic ART class-loading chain
  // ────────────────────────────────────────────────────────── When interpreted
  // code delegates a class load to a FRAMEWORK ClassLoader (super.loadClass, or
  // a stock PathClassLoader/BaseDexClassLoader), model ART's chain
  //   loadClass -> findClass -> DexPathList.findClass -> DexFile.defineClass ->
  //   defineClassNative
  // and CAPTURE the class at the defineClassNative point. This handles packers
  // that decrypt ON-DEFINE (InMemoryDexClassLoader / stock defineClassNative
  // over an in-memory decrypted DEX): the packer's decrypt native (if it
  // registered one) runs; otherwise we resolve the class from a host-supplied
  // DEX and notify_bytes it. Enable with `art_chain = true`.
  bool art_chain = false;

  // Resolve a class (JNI binary name, e.g. "com/foo/Bar") to the DEX bytes that
  // define it, the host wires this to its decrypted-DEX registry
  // (InMemoryDexClassLoader buffers, openDexFile cookies, ...). Return empty if
  // unknown. If unset, the runtime searches DEXes added via add_dex() and the
  // stub DEX itself.
  using ClassResolver =
      std::function<std::vector<uint8_t>(const std::string& binary_name)>;
  ClassResolver on_resolve_class;

  // Register an additional (decrypted) DEX for the ART chain's class
  // resolution. Takes ownership.
  void add_dex(std::vector<uint8_t> bytes);

  // Run Class.method with the given shorty and args (object handles /
  // primitives as slots). class_desc is a DEX descriptor
  // ("Lcom/stub/StubApp;"). Returns the result slot.
  uint64_t run(const std::string& class_desc, const std::string& method,
               const std::string& shorty, std::vector<uint64_t> args);

  // Convenience: run <cls>.attachBaseContext(ctx) then onCreate() on the app
  // object.
  void run_lifecycle(const std::string& class_desc, uint64_t app, uint64_t ctx);

  // ART chain entry: define/capture a class by JNI binary name. Returns a
  // jclass handle (or 0). Tries the packer's registered defineClassNative
  // native first, then host-supplied DEX resolution
  // + notify_bytes capture. Public so drivers can drive loadClass(name)
  // directly for validation.
  uint64_t define_class(const std::string& binary_name);

  Dalvik& dalvik() { return dvk_; }

 private:
  void wire();
  uint32_t find_code(const std::string& desc, const std::string& name,
                     const std::string& sig);

  const DexFile& dex_;
  JavaRuntime& jrt_;
  Scheduler& sched_;
  uint64_t env_;
  Dalvik dvk_;
  std::vector<DexFile>
      extra_dexes_;  // decrypted DEXes registered for class resolution
  std::vector<std::vector<uint8_t>>
      dex_bytes_;  // backing bytes for extra_dexes_ + capture source
};

}  // namespace vardoger
