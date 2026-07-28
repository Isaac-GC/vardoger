#include "vardoger/android/android_env.hpp"

#include <cstdint>
#include <cstdlib>

namespace vardoger {

namespace {
// Deterministic PRNG (splitmix64) seeded from an FNV-1a hash of the package, so
// the "random" install tokens are stable per package across runs but still look
// like real device tokens.
uint64_t fnv1a(const std::string& s) {
  uint64_t h = 1469598103934665603ull;
  for (unsigned char c : s) {
    h ^= c;
    h *= 1099511628211ull;
  }
  return h;
}
uint64_t splitmix64(uint64_t& x) {
  x += 0x9E3779B97F4A7C15ull;
  uint64_t z = x;
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
  return z ^ (z >> 31);
}
void fill_bytes(uint64_t& state, uint8_t* out, size_t n) {
  for (size_t i = 0; i < n;) {
    uint64_t r = splitmix64(state);
    for (int b = 0; b < 8 && i < n; ++b, ++i)
      out[i] = static_cast<uint8_t>(r >> (8 * b));
  }
}
}  // namespace

std::string base64url_nopad(const uint8_t* data, size_t n) {
  static const char* A =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string out;
  size_t i = 0;
  for (; i + 3 <= n; i += 3) {
    uint32_t v = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8) |
                 data[i + 2];
    out.push_back(A[(v >> 18) & 63]);
    out.push_back(A[(v >> 12) & 63]);
    out.push_back(A[(v >> 6) & 63]);
    out.push_back(A[v & 63]);
  }
  if (n - i == 1) {
    uint32_t v = uint32_t(data[i]) << 16;
    out.push_back(A[(v >> 18) & 63]);
    out.push_back(A[(v >> 12) & 63]);
  } else if (n - i == 2) {
    uint32_t v = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8);
    out.push_back(A[(v >> 18) & 63]);
    out.push_back(A[(v >> 12) & 63]);
    out.push_back(A[(v >> 6) & 63]);
  }
  return out;
}

std::string android_code_path(const std::string& package, int sdk,
                              uint64_t seed) {
  uint64_t state = seed ? seed : (fnv1a(package) ^ 0xA5A5A5A5A5A5A5A5ull);
  uint8_t t1[16], t2[16];
  fill_bytes(state, t1, sizeof t1);  // the ~~ package-dir token
  fill_bytes(state, t2, sizeof t2);  // the <package>- suffix token
  const std::string suffix = base64url_nopad(t2, sizeof t2);
  if (sdk >= 30)
    return "/data/app/~~" + base64url_nopad(t1, sizeof t1) + "/" + package +
           "-" + suffix;
  if (sdk >= 26) return "/data/app/" + package + "-" + suffix;
  return "/data/app/" + package + "-1";
}

void apply_install_paths(DeviceIdentity& id, const std::string& lib_arch,
                         uint64_t seed) {
  const std::string code = android_code_path(id.package_name, id.sdk_int, seed);
  id.apk_path = code + "/base.apk";
  id.native_lib_dir = code + "/lib/" + lib_arch;
  id.data_dir = "/data/user/0/" + id.package_name + "/files";
}

AndroidEnv::AndroidEnv(JavaRuntime& jrt, DeviceIdentity id)
    : jrt_(jrt), id_(std::move(id)) {
  // The Application object handed to native code as its Context.
  application_ = jrt_.new_object("android/app/Application");

  // ApplicationInfo, with its string fields pre-populated.
  const uint64_t app_info =
      jrt_.new_object("android/content/pm/ApplicationInfo");
  jrt_.set_field(app_info, "sourceDir",
                 DvmValue::O(jrt_.new_string_utf(id_.apk_path)));
  jrt_.set_field(app_info, "nativeLibraryDir",
                 DvmValue::O(jrt_.new_string_utf(id_.native_lib_dir)));
  jrt_.set_field(app_info, "dataDir",
                 DvmValue::O(jrt_.new_string_utf(id_.data_dir)));

  const uint64_t class_loader =
      jrt_.new_object("dalvik/system/PathClassLoader");

  // Context / ContextWrapper methods packers reach for (host-impl, keyed by
  // name).
  const std::string pkg = id_.package_name;
  const std::string apk = id_.apk_path;
  const std::string dir = id_.data_dir;
  jrt_.register_method("getPackageName", [pkg](JavaRuntime& r, uint64_t,
                                               const std::vector<DvmValue>&) {
    return DvmValue::O(r.new_string_utf(pkg));
  });
  jrt_.register_method(
      "getPackageCodePath",
      [apk](JavaRuntime& r, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::O(r.new_string_utf(apk));
      });
  jrt_.register_method(
      "getPackageResourcePath",
      [apk](JavaRuntime& r, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::O(r.new_string_utf(
            apk));  // Context.getPackageResourcePath() -> base.apk
      });
  // System.getProperty(key[, def]), return the default if given, else null.
  // Packers probe e.g. "os.arch"/"java.vm.version"; null/default is a safe
  // answer.
  jrt_.register_method("getProperty", [](JavaRuntime&, uint64_t,
                                         const std::vector<DvmValue>& a) {
    return a.size() >= 2 ? a[1] : DvmValue::V();
  });
  jrt_.register_method(
      "getApplicationInfo",
      [app_info](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::O(app_info);
      });
  jrt_.register_method(
      "getClassLoader",
      [class_loader](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::O(class_loader);
      });

  // ActivityThread access path. When native code is NOT handed a Context (e.g.
  // CoreUtils.init(null) on the instantiateApplication path), it reaches the
  // app graph itself via
  // ActivityThread.currentActivityThread()/currentApplication(). Return the
  // Application as the universal handle, the by-name dispatch then resolves
  // getApplicationInfo()/getClassLoader()/getPackageManager() off it, so the
  // unpacker gets the same APK path / class loader / signature chain it would
  // on a real device. Without this, currentActivityThread() returns null and
  // the APK path comes back empty (openat "") → module parse fails.
  const uint64_t app = application_;
  jrt_.register_method(
      "currentActivityThread",
      [app](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::O(app);
      });
  jrt_.register_method(
      "currentApplication",
      [app](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::O(app);
      });
  jrt_.register_method("getApplication", [app](JavaRuntime&, uint64_t,
                                               const std::vector<DvmValue>&) {
    return DvmValue::O(app);
  });
  jrt_.register_method(
      "getApplicationContext",
      [app](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::O(app);
      });
  jrt_.register_method("getBaseContext", [app](JavaRuntime&, uint64_t,
                                               const std::vector<DvmValue>&) {
    return DvmValue::O(app);
  });
  // VMRuntime.setApiDenylistExemptions(String[]), hidden-API gray/blocklist
  // bypass the packer installs during init_array. Pure side effect on a real
  // device; a no-op here keeps the bootstrap from logging "no host impl".
  jrt_.register_method(
      "setApiDenylistExemptions",
      [](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::V();
      });
  jrt_.register_method(
      "setHiddenApiExemptions",
      [](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::V();
      });
  // android.os.Process/UserHandle.myUserId, primary user is 0.
  jrt_.register_method(
      "myUserId", [](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::I(0);
      });
  jrt_.register_method("getFilesDir", [dir](JavaRuntime& r, uint64_t,
                                            const std::vector<DvmValue>&) {
    const uint64_t f = r.new_object("java/io/File");
    r.set_field(f, "path", DvmValue::O(r.new_string_utf(dir)));
    return DvmValue::O(f);
  });
  jrt_.register_method("getAbsolutePath", [](JavaRuntime& r, uint64_t self,
                                             const std::vector<DvmValue>&) {
    return r.get_field(self, "path");  // File.getAbsolutePath()
  });

  // --- general java.lang.String helpers (not Android-specific) ---
  jrt_.register_method("getBytes", [](JavaRuntime& r, uint64_t self,
                                      const std::vector<DvmValue>&) {
    const std::string* s = r.string_of(self);
    if (std::getenv("VARDOGER_JNI_LOG"))
      std::fprintf(stderr, "[getBytes] self=obj%#llx -> \"%s\" (%s)\n",
                   (unsigned long long)self, s ? s->c_str() : "",
                   s ? "string" : "NON-STRING/null");
    return DvmValue::O(
        r.new_byte_array(s ? std::vector<uint8_t>(s->begin(), s->end())
                           : std::vector<uint8_t>{}));
  });
  jrt_.register_method("length", [](JavaRuntime& r, uint64_t self,
                                    const std::vector<DvmValue>&) {
    const std::string* s = r.string_of(self);
    return DvmValue::I(s ? static_cast<int64_t>(s->size()) : 0);
  });
  jrt_.register_method("toString", [](JavaRuntime&, uint64_t self,
                                      const std::vector<DvmValue>&) {
    return DvmValue::O(self);  // identity for our string/object handles
  });

  // --- java.lang stdlib coverage
  // (StringBuilder/String/Boolean/File/reflection) so a packer's stub
  //     bytecode (attachBaseContext/onCreate) runs far enough to reach the
  //     class-load that fires the on-demand DEX decrypt. Dispatch is
  //     class-qualified ("owner#name") for ambiguous names.
  //     ---
  auto as_str = [](JavaRuntime& r, const DvmValue& v) -> std::string {
    if (v.kind == DvmValue::Object) {
      if (const std::string* s = r.string_of(v.obj)) return *s;
      const std::string* sb = nullptr;
      (void)sb;
      // StringBuilder or other object: try its "sb" text field, else its class
      // name.
      DvmValue f = r.get_field(v.obj, "sb");
      if (f.kind == DvmValue::Object)
        if (const std::string* s = r.string_of(f.obj)) return *s;
      return std::string{};
    }
    if (v.kind == DvmValue::Int) return std::to_string(v.i);
    if (v.kind == DvmValue::Double) return std::to_string(v.d);
    return std::string{};
  };
  // StringBuilder: accumulate text in the object's "sb" String field; append
  // returns self (chaining).
  jrt_.register_method(
      "java/lang/StringBuilder#<init>",
      [as_str](JavaRuntime& r, uint64_t self, const std::vector<DvmValue>& a) {
        std::string init = a.empty() ? std::string{} : as_str(r, a[0]);
        r.set_field(self, "sb", DvmValue::O(r.new_string_utf(init)));
        return DvmValue::V();
      });
  jrt_.register_method("append", [as_str](JavaRuntime& r, uint64_t self,
                                          const std::vector<DvmValue>& a) {
    std::string cur;
    DvmValue f = r.get_field(self, "sb");
    if (f.kind == DvmValue::Object)
      if (const std::string* s = r.string_of(f.obj)) cur = *s;
    if (!a.empty()) cur += as_str(r, a[0]);
    r.set_field(self, "sb", DvmValue::O(r.new_string_utf(cur)));
    return DvmValue::O(self);  // chaining
  });
  jrt_.register_method(
      "java/lang/StringBuilder#toString",
      [](JavaRuntime& r, uint64_t self, const std::vector<DvmValue>&) {
        DvmValue f = r.get_field(self, "sb");
        return DvmValue::O(f.kind == DvmValue::Object ? f.obj
                                                      : r.new_string_utf(""));
      });
  // String helpers.
  jrt_.register_method("contains", [as_str](JavaRuntime& r, uint64_t self,
                                            const std::vector<DvmValue>& a) {
    const std::string* s = r.string_of(self);
    std::string needle = a.empty() ? std::string{} : as_str(r, a[0]);
    return DvmValue::I(s && s->find(needle) != std::string::npos ? 1 : 0);
  });
  jrt_.register_method("isEmpty", [](JavaRuntime& r, uint64_t self,
                                     const std::vector<DvmValue>&) {
    const std::string* s = r.string_of(self);
    return DvmValue::I(!s || s->empty() ? 1 : 0);
  });
  jrt_.register_method(
      "equalsIgnoreCase",
      [as_str](JavaRuntime& r, uint64_t self, const std::vector<DvmValue>& a) {
        const std::string* s = r.string_of(self);
        std::string o = a.empty() ? std::string{} : as_str(r, a[0]);
        if (!s || s->size() != o.size()) return DvmValue::I(0);
        for (size_t i = 0; i < o.size(); ++i)
          if (std::tolower((unsigned char)(*s)[i]) !=
              std::tolower((unsigned char)o[i]))
            return DvmValue::I(0);
        return DvmValue::I(1);
      });
  jrt_.register_method("equals", [as_str](JavaRuntime& r, uint64_t self,
                                          const std::vector<DvmValue>& a) {
    const std::string* s = r.string_of(self);
    if (s) return DvmValue::I(!a.empty() && *s == as_str(r, a[0]) ? 1 : 0);
    return DvmValue::I(
        !a.empty() && a[0].kind == DvmValue::Object && a[0].obj == self ? 1
                                                                        : 0);
  });
  jrt_.register_method("hashCode", [](JavaRuntime& r, uint64_t self,
                                      const std::vector<DvmValue>&) {
    const std::string* s = r.string_of(self);
    int32_t h = 0;
    if (s)
      for (unsigned char c : *s) h = h * 31 + c;
    return DvmValue::I(h);
  });
  jrt_.register_method("toCharArray", [](JavaRuntime& r, uint64_t self,
                                         const std::vector<DvmValue>&) {
    const std::string* s = r.string_of(self);
    return DvmValue::O(
        r.new_byte_array(s ? std::vector<uint8_t>(s->begin(), s->end())
                           : std::vector<uint8_t>{}));
  });
  jrt_.register_method(
      "java/lang/String#valueOf",
      [as_str](JavaRuntime& r, uint64_t, const std::vector<DvmValue>& a) {
        return DvmValue::O(
            r.new_string_utf(a.empty() ? std::string{} : as_str(r, a[0])));
      });
  // String.intern() -> the canonical instance; returning self is faithful
  // (equal strings share identity in our runtime only weakly, but the packer
  // uses intern() for identity of its own literals). Without this the "no host
  // impl" 0-return made Jiagu's per-method reflection walk spin (Gem harness
  // hang).
  jrt_.register_method(
      "java/lang/String#intern",
      [](JavaRuntime&, uint64_t self, const std::vector<DvmValue>&) {
        return DvmValue::O(self);
      });
  // Class.getInterfaces() -> Class[]; we don't model the interface hierarchy,
  // so return an EMPTY array. The packer iterates it (looking for a marker
  // interface); an empty array ends the loop cleanly instead of spinning on a
  // null return (root cause of the Gem trampoline's String#intern spin).
  jrt_.register_method(
      "java/lang/Class#getInterfaces",
      [](JavaRuntime& r, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::O(r.new_object_array({}));
      });
  // Boolean: valueOf(x) -> boxed object holding "boolval"; booleanValue() ->
  // the bit.
  jrt_.register_method(
      "java/lang/Boolean#valueOf",
      [](JavaRuntime& r, uint64_t, const std::vector<DvmValue>& a) {
        const uint64_t b = r.new_object("java/lang/Boolean");
        r.set_field(b, "boolval", DvmValue::I(!a.empty() && a[0].i ? 1 : 0));
        return DvmValue::O(b);
      });
  jrt_.register_method("booleanValue", [](JavaRuntime& r, uint64_t self,
                                          const std::vector<DvmValue>&) {
    return DvmValue::I(r.get_field(self, "boolval").i);
  });
  // File: store path; report not-exists (force fresh decrypt), mkdir ok,
  // parent/canonical = path.
  jrt_.register_method(
      "java/io/File#<init>",
      [as_str](JavaRuntime& r, uint64_t self, const std::vector<DvmValue>& a) {
        std::string p;
        if (a.size() >= 2) {
          p = as_str(r, a[0]);
          if (!p.empty() && p.back() != '/') p += '/';
          p += as_str(r, a[1]);
        } else if (a.size() == 1)
          p = as_str(r, a[0]);
        r.set_field(self, "path", DvmValue::O(r.new_string_utf(p)));
        return DvmValue::V();
      });
  jrt_.register_method(
      "exists", [](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::I(0);
      });
  jrt_.register_method(
      "mkdir", [](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::I(1);
      });
  jrt_.register_method(
      "mkdirs", [](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::I(1);
      });
  jrt_.register_method("getParentFile", [](JavaRuntime& r, uint64_t self,
                                           const std::vector<DvmValue>&) {
    const uint64_t f = r.new_object("java/io/File");
    std::string p;
    DvmValue pf = r.get_field(self, "path");
    if (pf.kind == DvmValue::Object)
      if (const std::string* s = r.string_of(pf.obj)) {
        p = *s;
        auto sl = p.find_last_of('/');
        if (sl != std::string::npos) p = p.substr(0, sl);
      }
    r.set_field(f, "path", DvmValue::O(r.new_string_utf(p)));
    return DvmValue::O(f);
  });
  jrt_.register_method("getCanonicalPath", [](JavaRuntime& r, uint64_t self,
                                              const std::vector<DvmValue>&) {
    DvmValue pf = r.get_field(self, "path");
    return DvmValue::O(pf.kind == DvmValue::Object ? pf.obj
                                                   : r.new_string_utf(""));
  });
  // BufferedReader / streams over /proc etc., report EOF so read loops
  // terminate cleanly.
  jrt_.register_method(
      "readLine", [](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::O(0);
      });
  jrt_.register_method(
      "read", [](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::I(-1);
      });
  jrt_.register_method(
      "close", [](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::V();
      });
  jrt_.register_method(
      "flush", [](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::V();
      });
  // System/Runtime, native lib load is a no-op (natives already registered);
  // block process exit.
  jrt_.register_method(
      "load", [](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::V();
      });
  jrt_.register_method(
      "loadLibrary", [](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::V();
      });
  jrt_.register_method(
      "exit", [](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
        std::fprintf(stderr, "[java] System.exit blocked\n");
        return DvmValue::V();
      });
  // Reflection, best-effort so a reflective decrypt/init call proceeds.
  // getDeclaredMethod returns a Method-ish object carrying the name;
  // setAccessible is a no-op; invoke returns void (the real work in packers is
  // usually the class-load side, handled by the ART chain / loadClass).
  jrt_.register_method("setAccessible", [](JavaRuntime&, uint64_t,
                                           const std::vector<DvmValue>&) {
    return DvmValue::V();
  });
  jrt_.register_method("getDeclaredMethod", [](JavaRuntime& r, uint64_t self,
                                               const std::vector<DvmValue>& a) {
    const uint64_t m = r.new_object("java/lang/reflect/Method");
    if (!a.empty() && a[0].kind == DvmValue::Object)
      r.set_field(m, "name", DvmValue::O(a[0].obj));
    r.set_field(m, "declaringClass", DvmValue::O(self));
    return DvmValue::O(m);
  });
  jrt_.register_method("getMethod", [](JavaRuntime& r, uint64_t self,
                                       const std::vector<DvmValue>& a) {
    const uint64_t m = r.new_object("java/lang/reflect/Method");
    if (!a.empty() && a[0].kind == DvmValue::Object)
      r.set_field(m, "name", DvmValue::O(a[0].obj));
    r.set_field(m, "declaringClass", DvmValue::O(self));
    return DvmValue::O(m);
  });
  jrt_.register_method(
      "invoke", [](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::O(0);
      });
  // Context.getResources/getAssets, return stable objects so
  // resource/asset probes don't bail.
  {
    const uint64_t res = jrt_.new_object("android/content/res/Resources");
    const uint64_t am = jrt_.new_object("android/content/res/AssetManager");
    jrt_.register_method("getResources", [res](JavaRuntime&, uint64_t,
                                               const std::vector<DvmValue>&) {
      return DvmValue::O(res);
    });
    jrt_.register_method("getAssets", [am](JavaRuntime&, uint64_t,
                                           const std::vector<DvmValue>&) {
      return DvmValue::O(am);
    });
  }
  // Timing, packers time regions for anti-debug (t2-t1 > threshold => being
  // traced). Return a fixed large timestamp so every delta reads ~0 (fast, not
  // debugged). nanoTime likewise.
  jrt_.register_method("currentTimeMillis", [](JavaRuntime&, uint64_t,
                                               const std::vector<DvmValue>&) {
    return DvmValue::I(1700000000000LL);
  });
  jrt_.register_method(
      "nanoTime", [](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::I(1700000000000000000LL);
      });
  jrt_.register_method("elapsedRealtime", [](JavaRuntime&, uint64_t,
                                             const std::vector<DvmValue>&) {
    return DvmValue::I(1000000LL);
  });
  jrt_.register_method(
      "uptimeMillis", [](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::I(1000000LL);
      });
  // System.getProperty(key[, def]), packers probe java.vm.version / os.arch /
  // anti-VM keys. A null return can gate them; answer the common ones with
  // realistic non-emulator values.
  jrt_.register_method("getProperty", [](JavaRuntime& r, uint64_t,
                                         const std::vector<DvmValue>& a) {
    std::string k;
    if (!a.empty() && a[0].kind == DvmValue::Object)
      if (const std::string* s = r.string_of(a[0].obj)) k = *s;
    static const std::pair<const char*, const char*> P[] = {
        {"java.vm.version", "2.1.0"},
        {"java.vm.name", "Dalvik"},
        {"java.runtime.name", "Android Runtime"},
        {"java.vm.vendor", "The Android Project"},
        {"os.arch", "aarch64"},
        {"os.name", "Linux"},
        {"os.version", "5.10.0"},
        {"java.io.tmpdir", "/data/local/tmp"},
        {"user.dir", "/"},
        {"line.separator", "\n"},
        {"file.separator", "/"},
        {"path.separator", ":"},
        {"java.vendor", "The Android Project"},
        {"java.version", "0"},
        {"http.agent", "Dalvik/2.1.0"},
    };
    for (auto& kv : P)
      if (k == kv.first) return DvmValue::O(r.new_string_utf(kv.second));
    // fall back to the provided default (2nd arg) if any, else null
    if (a.size() > 1 && a[1].kind == DvmValue::Object) return a[1];
    return DvmValue::V();
  });

  // Build.* static fields, packers read these for device-key derivation +
  // anti-emulator checks; a NULL field (e.g. BRAND) reads as
  // "emulator/tampered" and can gate the decrypt. Populate the full set, kept
  // consistent with the system properties + fingerprint
  // (brand/product/device:release/id/incremental:type/tags).
  {
    const std::string& fp = id_.fingerprint;
    auto cut = [](const std::string& s, char d, size_t& p) {
      size_t q = s.find(d, p);
      std::string r = s.substr(p, q == std::string::npos ? q : q - p);
      p = q == std::string::npos ? s.size() : q + 1;
      return r;
    };
    size_t p = 0;
    std::string brand = cut(fp, '/', p), product = cut(fp, '/', p),
                rest = fp.substr(p);
    size_t q = 0;
    std::string device = cut(rest, ':', q), release = cut(rest, '/', q),
                bid = cut(rest, '/', q), incr = cut(rest, ':', q),
                type = cut(rest, '/', q), tags = rest.substr(q);
    if (brand.empty()) brand = "google";
    if (product.empty()) product = "raven";
    if (device.empty()) device = product;
    if (release.empty()) release = "12";
    if (bid.empty()) bid = "SQ3A.220705.004";
    if (incr.empty()) incr = "8836240";
    if (type.empty()) type = "user";
    if (tags.empty()) tags = "release-keys";
    auto S = [&](const char* c, const char* f, const std::string& v) {
      jrt_.set_static(c, f, DvmValue::O(jrt_.new_string_utf(v)));
    };
    auto SA = [&](const char* f, std::vector<uint64_t> a) {
      jrt_.set_static("android/os/Build", f,
                      DvmValue::O(jrt_.new_object_array(std::move(a))));
    };
    S("android/os/Build", "BRAND", brand);
    S("android/os/Build", "MANUFACTURER", id_.manufacturer);
    S("android/os/Build", "MODEL", id_.model);
    S("android/os/Build", "PRODUCT", product);
    S("android/os/Build", "DEVICE", device);
    S("android/os/Build", "BOARD", device);
    S("android/os/Build", "HARDWARE", device);
    S("android/os/Build", "FINGERPRINT", fp);
    S("android/os/Build", "DISPLAY", bid);
    S("android/os/Build", "ID", bid);
    S("android/os/Build", "TYPE", type);
    S("android/os/Build", "TAGS", tags);
    S("android/os/Build", "HOST", "abfarm");
    S("android/os/Build", "USER", "android-build");
    S("android/os/Build", "BOOTLOADER", "unknown");
    S("android/os/Build", "RADIO", "unknown");
    S("android/os/Build", "SERIAL", "unknown");
    S("android/os/Build", "CPU_ABI", "arm64-v8a");
    S("android/os/Build", "CPU_ABI2", "");
    SA("SUPPORTED_ABIS",
       {jrt_.new_string_utf("arm64-v8a"), jrt_.new_string_utf("armeabi-v7a"),
        jrt_.new_string_utf("armeabi")});
    SA("SUPPORTED_64_BIT_ABIS", {jrt_.new_string_utf("arm64-v8a")});
    SA("SUPPORTED_32_BIT_ABIS",
       {jrt_.new_string_utf("armeabi-v7a"), jrt_.new_string_utf("armeabi")});
    jrt_.set_static("android/os/Build$VERSION", "SDK_INT",
                    DvmValue::I(id_.sdk_int));
    jrt_.set_static("android/os/Build$VERSION", "PREVIEW_SDK_INT",
                    DvmValue::I(0));
    S("android/os/Build$VERSION", "RELEASE", release);
    S("android/os/Build$VERSION", "RELEASE_OR_CODENAME", release);
    S("android/os/Build$VERSION", "CODENAME", "REL");
    S("android/os/Build$VERSION", "INCREMENTAL", incr);
    S("android/os/Build$VERSION", "SDK", std::to_string(id_.sdk_int));
    S("android/os/Build$VERSION", "SECURITY_PATCH", "2022-07-05");
    S("android/os/Build$VERSION", "BASE_OS", "");
  }

  // --- signature chain: getPackageManager().getPackageInfo(pkg,
  // GET_SIGNATURES)
  //     .signatures[0].toByteArray() -> cert DER (packers hash this) ---
  if (id_.signing_cert.empty()) {  // plausible placeholder DER
    id_.signing_cert.assign(256, 0);
    id_.signing_cert[0] = 0x30;
    id_.signing_cert[1] = 0x82;  // ASN.1 SEQUENCE
    id_.signing_cert[2] = 0x00;
    id_.signing_cert[3] = 0xFC;
    for (size_t i = 4; i < id_.signing_cert.size(); ++i)
      id_.signing_cert[i] = static_cast<uint8_t>(0x40 + (i & 0x3F));
  }
  const uint64_t signature = jrt_.new_object("android/content/pm/Signature");
  const uint64_t sig_array = jrt_.new_object_array({signature});
  const uint64_t pkg_info = jrt_.new_object("android/content/pm/PackageInfo");
  jrt_.set_field(pkg_info, "signatures", DvmValue::O(sig_array));
  const uint64_t pm = jrt_.new_object("android/content/pm/PackageManager");

  const std::vector<uint8_t> cert = id_.signing_cert;
  jrt_.register_method("getPackageManager", [pm](JavaRuntime&, uint64_t,
                                                 const std::vector<DvmValue>&) {
    return DvmValue::O(pm);
  });
  jrt_.register_method(
      "getPackageInfo",
      [pkg_info](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::O(pkg_info);
      });
  jrt_.register_method("toByteArray", [cert](JavaRuntime& r, uint64_t,
                                             const std::vector<DvmValue>&) {
    return DvmValue::O(r.new_byte_array(cert));
  });
}

// The full reflected context graph. Registrations here run AFTER AndroidEnv's
// device-base and intentionally override the shared method names
// (currentActivityThread/getPackageInfo/toByteArray/
// getProperty/getApplicationContext/...) with graph-consistent objects.
ContextGraph build_context_graph(JavaRuntime& jrt, const DeviceIdentity& id,
                                 const ContextGraphOptions& opt) {
  ContextGraph g;
  const std::string jdir = "/data/user/0/" + id.package_name + "/.jiagu";
  const uint64_t jctx = jrt.new_object("android/content/Context");
  g.context = jctx;
  jrt.register_method("getAppContext", [jctx](JavaRuntime&, uint64_t,
                                              const std::vector<DvmValue>&) {
    return DvmValue::O(jctx);
  });
  jrt.register_method(
      "getDir", [jdir](JavaRuntime& r, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::O(r.new_string_utf(jdir));
      });
  jrt.register_method("currentPackageName",
                      [pkg = id.package_name](JavaRuntime& r, uint64_t,
                                              const std::vector<DvmValue>&) {
                        return DvmValue::O(r.new_string_utf(pkg));
                      });

  const uint64_t jAppInfo =
      jrt.new_object("android/content/pm/ApplicationInfo");
  g.app_info = jAppInfo;
  jrt.set_field(jAppInfo, "sourceDir",
                DvmValue::O(jrt.new_string_utf(id.apk_path)));
  jrt.set_field(jAppInfo, "publicSourceDir",
                DvmValue::O(jrt.new_string_utf(id.apk_path)));
  jrt.set_field(
      jAppInfo, "dataDir",
      DvmValue::O(jrt.new_string_utf("/data/user/0/" + id.package_name)));
  jrt.set_field(jAppInfo, "nativeLibraryDir",
                DvmValue::O(jrt.new_string_utf(id.native_lib_dir)));
  jrt.set_field(jAppInfo, "packageName",
                DvmValue::O(jrt.new_string_utf(id.package_name)));
  jrt.set_field(jAppInfo, "flags",
                DvmValue::I(0));  // not FLAG_DEBUGGABLE (anti-tamper gate)
  const uint64_t jBindData =
      jrt.new_object("android/app/ActivityThread$AppBindData");
  jrt.set_field(jBindData, "appInfo", DvmValue::O(jAppInfo));
  jrt.set_field(jBindData, "processName",
                DvmValue::O(jrt.new_string_utf(id.package_name)));
  jrt.set_field(jBindData, "providers",
                DvmValue::O(jrt.new_object("java/util/ArrayList")));
  const uint64_t jPkgInfo = jrt.new_object("android/content/pm/PackageInfo");
  g.package_info = jPkgInfo;
  jrt.set_field(jPkgInfo, "applicationInfo", DvmValue::O(jAppInfo));
  jrt.set_field(jPkgInfo, "packageName",
                DvmValue::O(jrt.new_string_utf(id.package_name)));
  // GET_SIGNATURES / key-derivation: signatures[0].toByteArray() -> real cert
  // DER (id.signing_cert), plus the modern SigningInfo path. Classic inner-lib
  // SM4 key + tamper gates derive from this.
  const uint64_t jSig = jrt.new_object("android/content/pm/Signature");
  jrt.register_method("toByteArray",
                      [cert = id.signing_cert](JavaRuntime& r, uint64_t,
                                               const std::vector<DvmValue>&) {
                        return DvmValue::O(r.new_byte_array(cert));
                      });
  jrt.set_field(jPkgInfo, "signatures",
                DvmValue::O(jrt.new_object_array({jSig})));
  const uint64_t jSignInfo = jrt.new_object("android/content/pm/SigningInfo");
  jrt.set_field(jPkgInfo, "signingInfo", DvmValue::O(jSignInfo));
  jrt.register_method(
      "getApkContentsSigners",
      [jSig](JavaRuntime& r, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::O(r.new_object_array({jSig}));
      });
  jrt.register_method(
      "getSigningCertificateHistory",
      [jSig](JavaRuntime& r, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::O(r.new_object_array({jSig}));
      });
  jrt.register_method(
      "getPackageInfo",
      [jPkgInfo](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::O(jPkgInfo);
      });

  const uint64_t jAT = jrt.new_object("android/app/ActivityThread");
  g.activity_thread = jAT;
  jrt.set_field(jAT, "mBoundApplication", DvmValue::O(jBindData));
  jrt.register_method(
      "currentActivityThread",
      [jAT](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::O(jAT);
      });
  // The one Application/StubApp object, ActivityThread.mInitialApplication /
  // mAllApplications and the driver's interfaceN drive calls all share it, so
  // interface7/8 find "the app" (non-null mAllApplications).
  const uint64_t jApp = jrt.new_object(opt.app_class.c_str());
  g.application = jApp;
  jrt.set_field(jAT, "mInitialApplication", DvmValue::O(jApp));
  jrt.set_field(jAT, "mAllApplications",
                DvmValue::O(jrt.new_object("java/util/ArrayList")));
  const uint64_t jBinder = jrt.new_object("android/os/BinderProxy");
  jrt.register_method(
      "getContextObject",
      [jBinder](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::O(jBinder);
      });
  const uint64_t jSM = jrt.new_object("android/os/IServiceManager");
  jrt.register_method("asInterface", [jSM](JavaRuntime&, uint64_t,
                                           const std::vector<DvmValue>&) {
    return DvmValue::O(jSM);
  });
  jrt.register_method("getService", [jBinder](JavaRuntime&, uint64_t,
                                              const std::vector<DvmValue>&) {
    return DvmValue::O(jBinder);
  });
  jrt.register_method("checkService", [jBinder](JavaRuntime&, uint64_t,
                                                const std::vector<DvmValue>&) {
    return DvmValue::O(jBinder);
  });

  const uint64_t jClassLoader = jrt.new_object(opt.class_loader_class.c_str());
  g.class_loader = jClassLoader;
  const uint64_t jPathList = jrt.new_object("dalvik/system/DexPathList");
  jrt.set_field(jPathList, "dexElements",
                DvmValue::O(jrt.new_object_array({})));
  jrt.set_field(jClassLoader, "pathList", DvmValue::O(jPathList));
  const uint64_t jLoadedApk = jrt.new_object("android/app/LoadedApk");
  jrt.set_field(jLoadedApk, "mClassLoader", DvmValue::O(jClassLoader));
  jrt.set_field(jLoadedApk, "mApplicationInfo", DvmValue::O(jAppInfo));
  jrt.set_field(jctx, "mPackageInfo", DvmValue::O(jLoadedApk));
  jrt.set_field(jctx, "mOuterContext", DvmValue::O(jctx));
  // ContextImpl.mMainThread -> the ActivityThread. Real ContextImpl holds this;
  // packers (e.g. the Virbox clone family) read ContextImpl.mMainThread to
  // reach ActivityThread.mAllApplications / mBoundApplication. Without it that
  // chain dead-ends at null and the packer takes a degenerate (no real
  // DEX-load) path. Defaulted so a Context the bytecode builds itself also
  // resolves it.
  if (!std::getenv("VARDOGER_NO_MMAINTHREAD"))
    jrt.set_field(jctx, "mMainThread", DvmValue::O(jAT));
  // Defaults so any Context the bytecode constructs itself still resolves the
  // graph. mClassLoader is deliberately NOT defaulted (that would make the
  // loader look already-populated and skip decrypting).
  if (!std::getenv("VARDOGER_NO_FIELD_DEFAULTS")) {
    jrt.set_field_default("mPackageInfo", DvmValue::O(jLoadedApk));
    jrt.set_field_default("mOuterContext", DvmValue::O(jctx));
    if (!std::getenv("VARDOGER_NO_MMAINTHREAD"))
      jrt.set_field_default("mMainThread", DvmValue::O(jAT));
  }
  jrt.set_field(jAT, "mH",
                DvmValue::O(jrt.new_object("android/app/ActivityThread$H")));
  jrt.register_method(
      "getClassLoader",
      [jClassLoader](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::O(jClassLoader);
      });
  for (const char* m :
       {"getApplicationContext", "getBaseContext", "getApplication",
        "currentApplication", "getApplicationOnCreate"})
    jrt.register_method(
        m, [jctx](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
          return DvmValue::O(jctx);
        });
  // Thread.currentThread().getContextClassLoader() /
  // ActivityThread.getSystemContext, the loader walks both during JNI_OnLoad
  // (null -> JNI_ERR).
  const uint64_t jThread = jrt.new_object("java/lang/Thread");
  jrt.register_method("currentThread", [jThread](JavaRuntime&, uint64_t,
                                                 const std::vector<DvmValue>&) {
    return DvmValue::O(jThread);
  });
  jrt.register_method(
      "getContextClassLoader",
      [jClassLoader](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::O(jClassLoader);
      });
  jrt.register_method("getSystemContext", [jctx](JavaRuntime&, uint64_t,
                                                 const std::vector<DvmValue>&) {
    return DvmValue::O(jctx);
  });
  jrt.register_method(
      "getSystemContextInner",
      [jctx](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::O(jctx);
      });
  jrt.register_method("getStackTrace", [](JavaRuntime& r, uint64_t,
                                          const std::vector<DvmValue>&) {
    return DvmValue::O(r.new_object_array({}));
  });
  for (const char* m :
       {"sendEmptyMessageDelayed", "sendEmptyMessage", "sendMessageDelayed",
        "sendMessage", "post", "postDelayed"})
    jrt.register_method(
        m, [](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
          return DvmValue::I(1);
        });
  // java.util collections surface loaders walk while enumerating classes
  // (Arrays.asList / Collections.enumeration / DexFile.entries), non-null so a
  // null result isn't called through.
  jrt.register_method("add",
                      [](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
                        return DvmValue::I(1);
                      });
  jrt.register_method(
      "asList", [](JavaRuntime& r, uint64_t, const std::vector<DvmValue>& a) {
        if (!a.empty() && a[0].kind == DvmValue::Object && a[0].obj)
          return DvmValue::O(a[0].obj);
        return DvmValue::O(r.new_object("java/util/ArrayList"));
      });
  jrt.register_method(
      "toArray", [](JavaRuntime& r, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::O(r.new_object_array({}));
      });
  jrt.register_method(
      "iterator", [](JavaRuntime& r, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::O(r.new_object("java/util/Iterator"));
      });
  jrt.register_method("hasNext",
                      [](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
                        return DvmValue::I(0);
                      });
  jrt.register_method("enumeration", [](JavaRuntime& r, uint64_t,
                                        const std::vector<DvmValue>&) {
    return DvmValue::O(r.new_object("java/util/Enumeration"));
  });
  jrt.register_method(
      "entries", [](JavaRuntime& r, uint64_t, const std::vector<DvmValue>&) {
        return DvmValue::O(r.new_object("java/util/Enumeration"));
      });
  jrt.register_method("hasMoreElements",
                      [](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
                        return DvmValue::I(0);
                      });
  jrt.register_method("nextElement",
                      [](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
                        return DvmValue::O(0);
                      });
  // System.getProperty(key), VARDOGER_PROPS override (Jiagu stub props the native
  // loader reads), then well-known ART/system keys, then a benign non-null ""
  // (packers bail on null, not "").
  jrt.register_method("getProperty", [](JavaRuntime& r, uint64_t,
                                        const std::vector<DvmValue>& a) {
    std::string k;
    if (!a.empty() && a[0].kind == DvmValue::Object)
      if (const std::string* s = r.string_of(a[0].obj)) k = *s;
    auto S = [&](const char* v) { return DvmValue::O(r.new_string_utf(v)); };
    if (const char* pv = std::getenv("VARDOGER_PROPS")) {
      std::string s = pv, key, val;
      bool inval = false;
      for (size_t i = 0; i <= s.size(); ++i) {
        if (i == s.size() || s[i] == ';') {
          if (!key.empty() && key == k) return S(val.c_str());
          key.clear();
          val.clear();
          inval = false;
        } else if (s[i] == '=' && !inval)
          inval = true;
        else
          (inval ? val : key) += s[i];
      }
    }
    if (k == "java.vm.version") return S("2.1.0");
    if (k == "java.vm.name") return S("Dalvik");
    if (k == "java.vm.vendor") return S("The Android Project");
    if (k == "java.runtime.version") return S("0.9");
    if (k == "os.arch") return S("aarch64");
    if (k == "os.name") return S("Linux");
    if (k == "os.version") return S("4.14.0");
    if (k == "java.io.tmpdir") return S("/data/local/tmp");
    if (k == "user.dir") return S("/");
    if (k == "line.separator") return S("\n");
    if (k == "file.separator") return S("/");
    if (k == "path.separator") return S(":");
    return S("");
  });

  if (opt.extra_probes) {
    // Classic (VMOS-variant) probes the loader makes during JNI_OnLoad.
    jrt.register_method("getSoPath1", [jdir](JavaRuntime& r, uint64_t,
                                             const std::vector<DvmValue>&) {
      return DvmValue::O(r.new_string_utf(jdir + "/libjiagu.so"));
    });
    jrt.register_method("getSoPath2", [jdir](JavaRuntime& r, uint64_t,
                                             const std::vector<DvmValue>&) {
      return DvmValue::O(r.new_string_utf(jdir + "/libjiagu_64.so"));
    });
    jrt.register_method("checkPermission", [](JavaRuntime&, uint64_t,
                                              const std::vector<DvmValue>&) {
      return DvmValue::I(0);
    });  // PERMISSION_GRANTED
    jrt.register_method("permissionToOp", [](JavaRuntime& r, uint64_t,
                                             const std::vector<DvmValue>&) {
      return DvmValue::O(r.new_string_utf("android:none"));
    });
    const uint64_t jResolver =
        jrt.new_object("android/content/ContentResolver");
    jrt.register_method(
        "getContentResolver",
        [jResolver](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
          return DvmValue::O(jResolver);
        });
    jrt.register_method(
        "getExternalStorageState",
        [](JavaRuntime& r, uint64_t, const std::vector<DvmValue>&) {
          return DvmValue::O(r.new_string_utf("mounted"));
        });
    const uint64_t jDataDir = jrt.new_object("java/io/File");
    jrt.set_field(jDataDir, "path", DvmValue::O(jrt.new_string_utf("/data")));
    jrt.register_method(
        "getDataDirectory",
        [jDataDir](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
          return DvmValue::O(jDataDir);
        });
    const uint64_t jExtDir = jrt.new_object("java/io/File");
    jrt.set_field(jExtDir, "path",
                  DvmValue::O(jrt.new_string_utf("/storage/emulated/0")));
    jrt.register_method(
        "getExternalStorageDirectory",
        [jExtDir](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
          return DvmValue::O(jExtDir);
        });
    auto path_getter = [](JavaRuntime& r, uint64_t self,
                          const std::vector<DvmValue>&) {
      DvmValue v = r.get_field(self, "path");
      return v.kind == DvmValue::Object
                 ? v
                 : DvmValue::O(r.new_string_utf("/data"));
    };
    jrt.register_method("getPath", path_getter);
    jrt.register_method("getAbsolutePath", path_getter);
    const uint64_t jAppOps = jrt.new_object("android/app/AppOpsManager");
    jrt.register_method(
        "getSystemService",
        [jAppOps](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
          return DvmValue::O(jAppOps);
        });
    jrt.register_method(
        "noteOp", [](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
          return DvmValue::I(0);
        });  // MODE_ALLOWED
    jrt.register_method(
        "isIsolated", [](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
          return DvmValue::I(0);
        });
    for (const char* m :
         {"installContentProviders", "addAction", "unregisterReceiver"})
      jrt.register_method(
          m, [](JavaRuntime&, uint64_t, const std::vector<DvmValue>&) {
            return DvmValue::V();
          });
    jrt.register_method("registerReceiver", [](JavaRuntime& r, uint64_t,
                                               const std::vector<DvmValue>&) {
      return DvmValue::O(r.new_object("android/content/Intent"));
    });
    jrt.register_method("getInstance", [](JavaRuntime& r, uint64_t,
                                          const std::vector<DvmValue>&) {
      return DvmValue::O(r.new_object("java/lang/Object"));
    });
    jrt.register_method("getDefault", [](JavaRuntime& r, uint64_t,
                                         const std::vector<DvmValue>&) {
      return DvmValue::O(r.new_object("java/util/Locale"));
    });
    jrt.register_method(
        "get", [](JavaRuntime& r, uint64_t, const std::vector<DvmValue>&) {
          return DvmValue::O(r.new_string_utf(""));
        });
    jrt.register_method("getLanguage", [](JavaRuntime& r, uint64_t,
                                          const std::vector<DvmValue>&) {
      return DvmValue::O(r.new_string_utf("zh"));
    });
    jrt.register_method("getCountry", [](JavaRuntime& r, uint64_t,
                                         const std::vector<DvmValue>&) {
      return DvmValue::O(r.new_string_utf("CN"));
    });
    jrt.set_static("android/net/ConnectivityManager", "CONNECTIVITY_ACTION",
                   DvmValue::O(jrt.new_string_utf(
                       "android.net.conn.CONNECTIVITY_CHANGE")));
  }
  return g;
}

}  // namespace vardoger
