// vardoger: generic ART class-resolution lifecycle runner (see
// include/vardoger/dex/lifecycle.hpp).
#include "vardoger/dex/lifecycle.hpp"

#include <cctype>
#include <cstdio>
#include <cstdlib>

#include "vardoger/engine/scheduler.hpp"
#include "vardoger/jni/java_runtime.hpp"

namespace vardoger {

// JNI/jrt internal class names use SLASHES ("com/stub/StubApp"), NOT dots.
// DexFile's descriptor_to_binary yields dots (breaks lookup_native/find_class)
//, strip "L.;" keeping slashes.
static std::string jni_name(const std::string& desc) {
  return (desc.size() >= 2 && desc.front() == 'L' && desc.back() == ';')
             ? desc.substr(1, desc.size() - 2)
             : desc;
}

void register_java_framework(JavaRuntime& jrt) {
  using V = DvmValue;
  auto str = [](JavaRuntime& r, uint64_t h) -> std::string {
    if (const std::string* s = r.string_of(h)) return *s;
    return {};
  };
  auto argstr = [str](JavaRuntime& r, const std::vector<V>& a,
                      size_t i) -> std::string {
    if (i >= a.size()) return {};
    const V& v = a[i];
    if (v.kind == V::Object) return str(r, v.obj);
    if (v.kind == V::Int) return std::to_string(v.i);
    return {};
  };
  // ── StringBuilder (content in field "__sb"); append(x) -> this; toString()
  // -> the string ──
  auto sbget = [str](JavaRuntime& r, uint64_t self) {
    return str(r, r.get_field(self, "__sb").obj);
  };
  jrt.register_method("append", [sbget, argstr](JavaRuntime& r, uint64_t self,
                                                const std::vector<V>& a) {
    r.set_field(self, "__sb",
                V::O(r.new_string_utf(sbget(r, self) + argstr(r, a, 0))));
    return V::O(self);
  });
  jrt.register_method("toString", [sbget, str](JavaRuntime& r, uint64_t self,
                                               const std::vector<V>&) {
    std::string s = sbget(r, self);
    if (s.empty())
      s = str(r, self);  // String.toString() / Object -> best-effort
    return V::O(r.new_string_utf(s));
  });
  // ── String ──
  jrt.register_method("contains", [str, argstr](JavaRuntime& r, uint64_t self,
                                                const std::vector<V>& a) {
    return V::I(str(r, self).find(argstr(r, a, 0)) != std::string::npos);
  });
  jrt.register_method("startsWith", [str, argstr](JavaRuntime& r, uint64_t self,
                                                  const std::vector<V>& a) {
    return V::I(str(r, self).rfind(argstr(r, a, 0), 0) == 0);
  });
  jrt.register_method("endsWith", [str, argstr](JavaRuntime& r, uint64_t self,
                                                const std::vector<V>& a) {
    const std::string s = str(r, self), t = argstr(r, a, 0);
    return V::I(s.size() >= t.size() &&
                s.compare(s.size() - t.size(), t.size(), t) == 0);
  });
  jrt.register_method("equals", [str, argstr](JavaRuntime& r, uint64_t self,
                                              const std::vector<V>& a) {
    return V::I(str(r, self) == argstr(r, a, 0));
  });
  jrt.register_method(
      "isEmpty", [str](JavaRuntime& r, uint64_t self, const std::vector<V>&) {
        return V::I(str(r, self).empty());
      });
  jrt.register_method(
      "length", [str](JavaRuntime& r, uint64_t self, const std::vector<V>&) {
        return V::I(int64_t(str(r, self).size()));
      });
  jrt.register_method(
      "hashCode", [str](JavaRuntime& r, uint64_t self, const std::vector<V>&) {
        // java.lang.String.hashCode: s[0]*31^(n-1)+...+s[n-1], 32-bit wraparound.
        // MUST accumulate in unsigned — signed int32 overflow is UB and clang
        // miscompiles it, yielding hashes that don't match the guest's, so the
        // packer stub's hash-keyed class/config lookups silently fail.
        uint32_t h = 0;
        for (char c : str(r, self)) h = h * 31u + (unsigned char)c;
        return V::I(int32_t(h));
      });
  jrt.register_method(
      "trim", [str](JavaRuntime& r, uint64_t self, const std::vector<V>&) {
        std::string s = str(r, self);
        size_t b = s.find_first_not_of(" \t\n\r"),
               e = s.find_last_not_of(" \t\n\r");
        return V::O(r.new_string_utf(
            b == std::string::npos ? std::string{} : s.substr(b, e - b + 1)));
      });
  // ── boxing: Boolean/Integer/Long valueOf(prim) -> box{__v};
  // booleanValue/intValue/longValue ->
  // __v ──
  jrt.register_method("valueOf", [argstr](JavaRuntime& r, uint64_t,
                                          const std::vector<V>& a) {
    if (!a.empty() && a[0].kind == V::Int) {
      uint64_t o = r.new_object("java/lang/Boolean");
      r.set_field(o, "__v", a[0]);
      return V::O(o);
    }
    return V::O(r.new_string_utf(argstr(r, a, 0)));  // String.valueOf(Object)
  });
  jrt.register_method("booleanValue",
                      [](JavaRuntime& r, uint64_t self, const std::vector<V>&) {
                        return r.get_field(self, "__v");
                      });
  jrt.register_method("intValue",
                      [](JavaRuntime& r, uint64_t self, const std::vector<V>&) {
                        return r.get_field(self, "__v");
                      });
  jrt.register_method("longValue",
                      [](JavaRuntime& r, uint64_t self, const std::vector<V>&) {
                        return r.get_field(self, "__v");
                      });
  // ── reflection / Class ── newInstance() -> an instance of the (jclass)
  // receiver; getDeclaredMethod
  //    / getMethod -> a Method object carrying the target name; setAccessible
  //    -> no-op; invoke -> best-effort null (the packer mostly needs a non-null
  //    Method + successful newInstance).
  jrt.register_method("newInstance",
                      [](JavaRuntime& r, uint64_t self, const std::vector<V>&) {
                        std::string cn = r.class_name(self);  // self = jclass
                        if (cn.empty()) cn = "java/lang/Object";
                        return V::O(r.new_object(cn));
                      });
  jrt.register_method("getDeclaredMethod", [argstr](JavaRuntime& r, uint64_t,
                                                    const std::vector<V>& a) {
    uint64_t m = r.new_object("java/lang/reflect/Method");
    r.set_field(m, "__name", V::O(r.new_string_utf(argstr(r, a, 0))));
    return V::O(m);
  });
  jrt.register_method(
      "getMethod", [argstr](JavaRuntime& r, uint64_t, const std::vector<V>& a) {
        uint64_t m = r.new_object("java/lang/reflect/Method");
        r.set_field(m, "__name", V::O(r.new_string_utf(argstr(r, a, 0))));
        return V::O(m);
      });
  jrt.register_method(
      "setAccessible",
      [](JavaRuntime&, uint64_t, const std::vector<V>&) { return V::V(); });
  // Method.invoke(receiver, Object[] args) -> route to the named host method on
  // the receiver.
  jrt.register_method(
      "invoke", [](JavaRuntime& r, uint64_t self, const std::vector<V>& a) {
        std::string name;
        if (const std::string* s = r.string_of(r.get_field(self, "__name").obj))
          name = *s;
        const uint64_t recv =
            (a.size() >= 1 && a[0].kind == V::Object) ? a[0].obj : 0;
        std::vector<V> args;
        if (a.size() >= 2 && a[1].kind == V::Object) {
          size_t n = r.array_length(a[1].obj);
          for (size_t i = 0; i < n; ++i)
            args.push_back(V::O(r.object_array_element(a[1].obj, i)));
        }
        if (name.empty()) return V::V();
        const uint64_t mid = r.get_method_id(r.class_of(recv), name, "", false);
        return r.call_method(
            mid, recv, args);  // dispatches by name to a host method (or Void)
      });
  // Class.forName(name) -> a jclass handle (normalize dots -> slashes).
  jrt.register_method(
      "forName", [argstr](JavaRuntime& r, uint64_t, const std::vector<V>& a) {
        std::string n = argstr(r, a, 0);
        for (char& c : n)
          if (c == '.') c = '/';
        return V::O(r.find_class(n));
      });
  jrt.register_method(
      "equalsIgnoreCase",
      [str, argstr](JavaRuntime& r, uint64_t self, const std::vector<V>& a) {
        std::string x = str(r, self), y = argstr(r, a, 0);
        auto low = [](std::string s) {
          for (char& c : s) c = (char)std::tolower((unsigned char)c);
          return s;
        };
        return V::I(low(x) == low(y));
      });
  jrt.register_method("asList",
                      [](JavaRuntime&, uint64_t, const std::vector<V>& a) {
                        return a.empty() ? V::V() : a[0];
                      });  // Arrays.asList(arr) -> arr as List
  // ── File path ops (path in field "path"; fall back to the object's own
  // string) ──
  auto fpath = [str](JavaRuntime& r, uint64_t self) {
    std::string p = str(r, r.get_field(self, "path").obj);
    return p.empty() ? str(r, self) : p;
  };
  jrt.register_method("getParentFile", [fpath](JavaRuntime& r, uint64_t self,
                                               const std::vector<V>&) {
    std::string p = fpath(r, self);
    size_t s = p.find_last_of('/');
    std::string par = (s == std::string::npos) ? std::string{} : p.substr(0, s);
    uint64_t f = r.new_object("java/io/File");
    r.set_field(f, "path", V::O(r.new_string_utf(par)));
    return V::O(f);
  });
  jrt.register_method("getCanonicalPath", [fpath](JavaRuntime& r, uint64_t self,
                                                  const std::vector<V>&) {
    return V::O(r.new_string_utf(fpath(r, self)));
  });
  jrt.register_method("getCanonicalFile",
                      [](JavaRuntime&, uint64_t self, const std::vector<V>&) {
                        return V::O(self);
                      });
  // ── streams (best-effort so read loops terminate cleanly) ──
  jrt.register_method("close", [](JavaRuntime&, uint64_t,
                                  const std::vector<V>&) { return V::V(); });
  jrt.register_method(
      "available",
      [](JavaRuntime&, uint64_t, const std::vector<V>&) { return V::I(0); });
  jrt.register_method("read",
                      [](JavaRuntime&, uint64_t, const std::vector<V>&) {
                        return V::I(-1);
                      });  // EOF
  jrt.register_method("readLine",
                      [](JavaRuntime&, uint64_t, const std::vector<V>&) {
                        return V::V();
                      });  // null
  jrt.register_method("flush", [](JavaRuntime&, uint64_t,
                                  const std::vector<V>&) { return V::V(); });
  jrt.register_method("open",
                      [](JavaRuntime& r, uint64_t, const std::vector<V>&) {
                        return V::O(r.new_object("java/io/InputStream"));
                      });  // AssetManager.open -> empty stream
  // ── File / misc (best-effort so path/existence checks don't bail) ──
  jrt.register_method("exists", [](JavaRuntime&, uint64_t,
                                   const std::vector<V>&) { return V::I(1); });
  jrt.register_method("mkdir", [](JavaRuntime&, uint64_t,
                                  const std::vector<V>&) { return V::I(1); });
  jrt.register_method("mkdirs", [](JavaRuntime&, uint64_t,
                                   const std::vector<V>&) { return V::I(1); });
  jrt.register_method(
      "isDirectory",
      [](JavaRuntime&, uint64_t, const std::vector<V>&) { return V::I(1); });
}

LifecycleRunner::LifecycleRunner(const DexFile& dex, JavaRuntime& jrt,
                                 Scheduler& sched, uint64_t env)
    : dex_(dex), jrt_(jrt), sched_(sched), env_(env), dvk_(dex) {
  wire();
}

uint32_t LifecycleRunner::find_code(const std::string& desc,
                                    const std::string& name,
                                    const std::string& sig) {
  std::string cur = desc;
  for (int hop = 0; hop < 8 && !cur.empty(); ++hop) {
    bool found_class = false;
    for (const auto& c : dex_.classes()) {
      if (c.descriptor != cur) continue;
      found_class = true;
      for (const auto& mm : c.direct_methods)
        if (mm.name == name && mm.sig == sig && mm.code_off) return mm.code_off;
      for (const auto& mm : c.virtual_methods)
        if (mm.name == name && mm.sig == sig && mm.code_off) return mm.code_off;
      cur = c.superclass;
      break;
    }
    if (!found_class) break;  // class not in stub DEX
  }
  return 0;
}

void LifecycleRunner::wire() {
  const bool lt = trace;  // captured by ref below via this->trace? use this->
  dvk_.on_const_string = [this](uint32_t s) {
    return jrt_.new_string_utf(dex_.string_at(s));
  };
  dvk_.on_new_instance = [this](uint32_t t) {
    return jrt_.new_object(jni_name(dex_.type_at(t)));
  };
  dvk_.on_sget = [this](uint32_t f) -> uint64_t {
    auto fd = dex_.field_at(f);
    return jrt_.get_static(jni_name(fd.cls), fd.name).obj;
  };
  dvk_.on_sput = [this](uint32_t f, uint64_t v) {
    auto fd = dex_.field_at(f);
    jrt_.set_static(jni_name(fd.cls), fd.name, DvmValue::O(v));
  };
  dvk_.on_iget = [this](uint64_t obj, uint32_t f) -> uint64_t {
    return jrt_.get_field(obj, dex_.field_at(f).name).obj;
  };
  dvk_.on_iput = [this](uint64_t obj, uint32_t f, uint64_t v) {
    jrt_.set_field(obj, dex_.field_at(f).name, DvmValue::O(v));
  };
  dvk_.on_new_array = [this](uint32_t t, int32_t len) -> uint64_t {
    if (len < 0 || len > (1 << 24)) len = 0;
    const std::string ty = dex_.type_at(t);
    if (ty.size() >= 2 && ty[1] == 'L')
      return jrt_.new_object_array(std::vector<uint64_t>(size_t(len), 0));
    return jrt_.new_byte_array(size_t(len));
  };
  dvk_.on_array_length = [this](uint64_t arr) -> int32_t {
    return int32_t(jrt_.array_length(arr));
  };
  dvk_.on_aget = [this](uint64_t arr, int32_t i) -> uint64_t {
    if (i < 0) return 0;
    if (const auto* b = jrt_.bytes_view(arr))
      return size_t(i) < b->size() ? (*b)[size_t(i)] : 0;
    return jrt_.object_array_element(arr, size_t(i));
  };
  dvk_.on_aput = [this](uint64_t arr, int32_t i, uint64_t v) {
    if (i < 0) return;
    if (auto* b = jrt_.bytes_ptr(arr)) {
      if (size_t(i) < b->size()) (*b)[size_t(i)] = uint8_t(v);
    } else
      jrt_.set_object_array_element(arr, size_t(i), v);
  };

  using IK = Dalvik::InvokeKind;
  dvk_.on_invoke = [this](IK kind, uint32_t midx,
                          const std::vector<uint64_t>& a) -> uint64_t {
    const auto m = dex_.method_at(midx);  // m.cls = "Lcom/..;", m.sig = shorty
    const std::string clsb = jni_name(m.cls);
    const bool is_static = (kind == IK::Static);
    const bool lt = trace;

    // Null-name guard: loadClass/forName/class-load natives crash (null-string
    // path -> stack smash / unmapped) when the app-class name (derived from
    // packer state) is null in our env.
    static const char* NAMEY[] = {"loadClass", "forName", "interface23",
                                  "findClass", "al"};
    bool namey = false;
    for (const char* n : NAMEY)
      if (m.name == n) {
        namey = true;
        break;
      }
    if (namey && !a.empty()) {
      std::vector<uint64_t> a2 = a;
      const size_t ni = is_static ? (a2.size() ? a2.size() - 1 : 0) : 1;
      if (ni < a2.size() && a2[ni] == 0) {
        const char* ec = std::getenv("VARDOGER_ENTRY_CLASS");
        a2[ni] = jrt_.new_string_utf(ec ? ec : entry_class_fallback.c_str());
        if (lt)
          std::fprintf(stderr, "  [inv] %s: null name -> '%s'\n",
                       m.name.c_str(), ec ? ec : entry_class_fallback.c_str());
        return dvk_.on_invoke(kind, midx, a2);
      }
    }

    // ART chain: a class-load delegated to a FRAMEWORK ClassLoader
    // (super.loadClass, stock PathClassLoader, ...) -> model defineClassNative
    // + capture. Fires only when art_chain is on and the method isn't
    // interpreted in the stub DEX (handled below at paths 0-2).
    auto art_try = [&]() -> uint64_t {
      if (!art_chain) return 0;
      static const char* LOADISH[] = {
          "loadClass",   "findClass",         "findClassInternal",
          "defineClass", "defineClassNative", "loadClassBinaryName"};
      bool loadish = false;
      for (const char* n : LOADISH)
        if (m.name == n) {
          loadish = true;
          break;
        }
      if (!loadish) return 0;
      for (size_t i = is_static ? 0 : 1; i < a.size(); ++i)
        if (const std::string* s = jrt_.string_of(a[i]))
          if (!s->empty()) {
            if (uint64_t c = define_class(*s)) return c;
            break;
          }
      return 0;
    };

    // (0) invoke-super -> declared type's SUPERclass (NOT the receiver's
    // override).
    if (kind == IK::Super) {
      std::string sup;
      for (const auto& c : dex_.classes())
        if (c.descriptor == m.cls) {
          sup = c.superclass;
          break;
        }
      if (uint32_t co = find_code(sup, m.name, m.sig)) {
        if (lt)
          std::fprintf(stderr, "  [inv] super %s.%s%s\n", jni_name(sup).c_str(),
                       m.name.c_str(), m.sig.c_str());
        return dvk_.run(dex_.code_at(co), a, m.name);
      }
      if (uint64_t c = art_try()) return c;  // super.loadClass -> ART chain
      if (lt)
        std::fprintf(stderr, "  [inv] super->framework %s.%s (no-op)\n",
                     clsb.c_str(), m.name.c_str());
      return 0;
    }
    // (1) virtual/interface -> receiver's actual class first (so overrides
    // run).
    if ((kind == IK::Virtual || kind == IK::Interface) && !a.empty() && a[0]) {
      const std::string rcb = jrt_.class_name(jrt_.class_of(a[0]));
      if (!rcb.empty())
        if (uint32_t co =
                find_code(DexFile::binary_to_descriptor(rcb), m.name, m.sig)) {
          if (lt)
            std::fprintf(stderr, "  [inv] vDISPATCH %s.%s%s\n", rcb.c_str(),
                         m.name.c_str(), m.sig.c_str());
          return dvk_.run(dex_.code_at(co), a, m.name);
        }
    }
    // (2) interpreted at the declared type.
    if (uint32_t co = find_code(m.cls, m.name, m.sig)) {
      if (lt)
        std::fprintf(stderr, "  [inv] interp %s.%s%s\n", clsb.c_str(),
                     m.name.c_str(), m.sig.c_str());
      return dvk_.run(dex_.code_at(co), a, m.name);
    }
    // (3) packer native (RegisterNatives'd). JNI ABI: (env, this|jclass,
    // args...).
    if (uint64_t fn = jrt_.lookup_native(clsb, m.name)) {
      std::vector<uint64_t> j;
      j.push_back(env_);
      size_t start = 0;
      if (is_static)
        j.push_back(jrt_.find_class(clsb));
      else {
        j.push_back(a.empty() ? 0 : a[0]);
        start = 1;
      }
      for (size_t i = start; i < a.size(); ++i) j.push_back(a[i]);
      while (j.size() < 2) j.push_back(0);
      if (lt)
        std::fprintf(stderr, "  [inv] NATIVE %s.%s (%zu jni-args)\n",
                     clsb.c_str(), m.name.c_str(), j.size());
      try {
        switch (j.size()) {
          case 2:
            return sched_.run(fn, {j[0], j[1]});
          case 3:
            return sched_.run(fn, {j[0], j[1], j[2]});
          case 4:
            return sched_.run(fn, {j[0], j[1], j[2], j[3]});
          case 5:
            return sched_.run(fn, {j[0], j[1], j[2], j[3], j[4]});
          default:
            return sched_.run(fn, {j[0], j[1], j[2], j[3], j[4], j[5]});
        }
      } catch (const std::exception& ex2) {
        std::fprintf(stderr, "  [inv] native %s threw: %s\n", m.name.c_str(),
                     ex2.what());
        return 0;
      }
    }
    // (3b) ART chain: framework ClassLoader.loadClass/findClass/defineClass ->
    // capture.
    if (uint64_t c = art_try()) return c;
    // (4) framework host method (register_method, by name); best-effort.
    const uint64_t clazz = jrt_.find_class(clsb);
    const uint64_t mid = jrt_.get_method_id(clazz, m.name, m.sig, is_static);
    const uint64_t self = is_static ? 0 : (a.empty() ? 0 : a[0]);
    std::vector<DvmValue> dv;
    size_t ai = is_static ? 0 : 1;
    for (size_t pi = 1; pi < m.sig.size() && ai < a.size(); ++pi, ++ai)
      dv.push_back((m.sig[pi] == 'L' || m.sig[pi] == '[')
                       ? DvmValue::O(a[ai])
                       : DvmValue::I(int64_t(a[ai])));
    if (lt)
      std::fprintf(stderr, "  [inv] framework %s.%s%s\n", clsb.c_str(),
                   m.name.c_str(), m.sig.c_str());
    const DvmValue r = jrt_.call_method(mid, self, dv);
    return r.kind == DvmValue::Object ? r.obj : uint64_t(r.i);
  };
  (void)lt;
}

uint64_t LifecycleRunner::run(const std::string& class_desc,
                              const std::string& method,
                              const std::string& shorty,
                              std::vector<uint64_t> args) {
  dvk_.trace = trace;
  const uint32_t co = find_code(class_desc, method, shorty);
  if (!co) {
    std::fprintf(stderr, "[lifecycle] %s.%s%s not found in stub DEX\n",
                 class_desc.c_str(), method.c_str(), shorty.c_str());
    return 0;
  }
  std::fprintf(stderr, "\n==== LIFECYCLE RUN: %s.%s%s ====\n",
               jni_name(class_desc).c_str(), method.c_str(), shorty.c_str());
  try {
    return dvk_.run(dex_.code_at(co), args, method);
  } catch (const std::exception& ex2) {
    std::fprintf(stderr, "[lifecycle] %s threw: %s\n", method.c_str(),
                 ex2.what());
    return 0;
  }
}

void LifecycleRunner::run_lifecycle(const std::string& class_desc, uint64_t app,
                                    uint64_t ctx) {
  run(class_desc, "attachBaseContext", "VL", {app, ctx});
  run(class_desc, "onCreate", "V", {app});
}

void LifecycleRunner::add_dex(std::vector<uint8_t> bytes) {
  DexFile d(bytes);  // parse over a copy
  if (!d.valid()) {
    std::fprintf(stderr, "[art] add_dex: parse failed: %s\n",
                 d.error().c_str());
    return;
  }
  std::fprintf(stderr, "[art] add_dex: %zu classes, %zu bytes\n",
               d.num_classes(), bytes.size());
  dex_bytes_.push_back(std::move(bytes));
  extra_dexes_.push_back(std::move(d));
}

uint64_t LifecycleRunner::define_class(const std::string& raw_name) {
  std::string name = raw_name;
  for (char& c : name)
    if (c == '.') c = '/';  // -> JNI binary
  if (name.empty()) return 0;
  const std::string desc = "L" + name + ";";
  std::vector<uint8_t> bytes;

  // (1) packer decrypt-ON-DEFINE native, if it registered one for
  // DexFile.defineClassNative.
  if (uint64_t fn =
          jrt_.lookup_native("dalvik/system/DexFile", "defineClassNative")) {
    try {
      sched_.run(fn, {env_, jrt_.find_class("dalvik/system/DexFile"),
                      jrt_.new_string_utf(name)});
    } catch (const std::exception&) {
    }
    // capture happens at the JNI DefineClass / notify_bytes handler the native
    // drives.
  }
  // (2) host resolver -> the decrypted DEX that defines this class.
  if (on_resolve_class) bytes = on_resolve_class(name);
  // (3) search registered (decrypted) DEXes, then the stub DEX itself.
  if (bytes.empty()) {
    for (size_t i = 0; i < extra_dexes_.size() && bytes.empty(); ++i)
      for (const auto& c : extra_dexes_[i].classes())
        if (c.descriptor == desc) {
          bytes = dex_bytes_[i];
          break;
        }
    if (bytes.empty())
      for (const auto& c : dex_.classes())
        if (c.descriptor == desc) {
          bytes = dex_.bytes();
          break;
        }
  }
  if (bytes.empty()) {
    if (trace)
      std::fprintf(stderr, "  [art] defineClass %s -> not found in any DEX\n",
                   name.c_str());
    return 0;
  }
  jrt_.notify_bytes(bytes, "defineClassNative:" + name);
  if (trace)
    std::fprintf(stderr, "  [art] defineClass %s -> captured %zu-byte DEX\n",
                 name.c_str(), bytes.size());
  return jrt_.find_class(name);
}

}  // namespace vardoger
