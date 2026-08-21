// vardoger: minimal ART class-loading substrate (see
// include/vardoger/art/art_runtime.hpp).
#include "vardoger/art/art_runtime.hpp"

#include <unicorn/unicorn.h>

#include <cstdio>
#include <cstring>

#include "vardoger/dex/dex_file.hpp"
#include "vardoger/engine/engine.hpp"
#include "vardoger/engine/memory.hpp"
#include "vardoger/jni/java_runtime.hpp"

namespace vardoger {

ArtRuntime::Dex ArtRuntime::register_dex(const std::vector<uint8_t>& bytes,
                                         const std::string& location) {
  Dex d;
  d.bytes_len = bytes.size();
  // 1) raw DEX bytes into guest memory.
  d.bytes_addr = mem_.mmap_alloc(bytes.size() ? bytes.size() : 1,
                                 UC_PROT_READ | UC_PROT_WRITE, "art dex bytes");
  if (!bytes.empty()) e_.write(d.bytes_addr, bytes.data(), bytes.size());
  // 2) the art::DexFile struct (zeroed, then begin_/size_/data_* set).
  d.struct_addr = mem_.mmap_alloc(0x100, UC_PROT_READ | UC_PROT_WRITE,
                                  "art DexFile struct");
  std::vector<uint8_t> zero(0x100, 0);
  e_.write(d.struct_addr, zero.data(), zero.size());
  e_.write_t<uint64_t>(d.struct_addr + layout.begin, d.bytes_addr);
  e_.write_t<uint64_t>(d.struct_addr + layout.size, d.bytes_len);
  e_.write_t<uint64_t>(d.struct_addr + layout.data_begin, d.bytes_addr);
  e_.write_t<uint64_t>(d.struct_addr + layout.data_size, d.bytes_len);
  // location c-string ptr (best-effort; some readers deref it).
  const uint64_t loc = mem_.mmap_alloc(
      location.size() + 1, UC_PROT_READ | UC_PROT_WRITE, "art dex location");
  e_.write(loc, location.c_str(), location.size() + 1);
  e_.write_t<uint64_t>(d.struct_addr + layout.location, loc);
  // 3) cookie = jlong[]{0, struct_addr}  (DexFile.mCookie on API 26+). Model as
  // a byte[] holding the
  //    two little-endian longs; GetLongArrayElements copies it to guest memory
  //    for native readers.
  std::vector<uint8_t> cookie(16, 0);
  const uint64_t oat = 0, dfp = d.struct_addr;
  std::memcpy(cookie.data() + 0, &oat, 8);
  std::memcpy(cookie.data() + 8, &dfp, 8);
  d.cookie_arr = jrt_.new_byte_array(std::move(cookie));
  // 4) the java DexFile object with mCookie + mFileName set.
  d.dexfile_obj = jrt_.new_object("dalvik/system/DexFile");
  jrt_.set_field(d.dexfile_obj, "mCookie", DvmValue::O(d.cookie_arr));
  jrt_.set_field(d.dexfile_obj, "mInternalCookie", DvmValue::O(d.cookie_arr));
  jrt_.set_field(d.dexfile_obj, "mFileName",
                 DvmValue::O(jrt_.new_string_utf(location)));
  // 5) parse the DEX (our parser) -> real class names, so
  // getClassNameList/entries return them.
  DexFile parsed(bytes);
  if (parsed.valid())
    for (const auto& c : parsed.classes())
      d.class_names.push_back(
          DexFile::descriptor_to_binary(c.descriptor));  // "com.foo.Bar" form

  std::fprintf(stderr,
               "[art] register_dex '%s': %llu bytes @%#llx, DexFile struct "
               "@%#llx (begin_=%#llx "
               "size_=%llu), %zu classes, cookie[1]=DexFile*\n",
               location.c_str(), (unsigned long long)d.bytes_len,
               (unsigned long long)d.bytes_addr,
               (unsigned long long)d.struct_addr,
               (unsigned long long)d.bytes_addr,
               (unsigned long long)d.bytes_len, d.class_names.size());
  dexes_.push_back(d);
  return dexes_.back();
}

uint64_t ArtRuntime::build_classloader(const std::vector<Dex>& dexes,
                                       uint64_t parent) {
  // Element[] : one android.app/dalvik Element per DexFile, with the dexFile
  // field set.
  std::vector<uint64_t> elems;
  for (const auto& d : dexes) {
    const uint64_t el = jrt_.new_object("dalvik/system/DexPathList$Element");
    jrt_.set_field(el, "dexFile", DvmValue::O(d.dexfile_obj));
    jrt_.set_field(el, "dex", DvmValue::O(d.dexfile_obj));
    elems.push_back(el);
  }
  const uint64_t pathList = jrt_.new_object("dalvik/system/DexPathList");
  jrt_.set_field(pathList, "dexElements",
                 DvmValue::O(jrt_.new_object_array(elems)));
  const uint64_t loader = jrt_.new_object("dalvik/system/PathClassLoader");
  jrt_.set_field(loader, "pathList", DvmValue::O(pathList));
  if (parent) jrt_.set_field(loader, "parent", DvmValue::O(parent));
  std::fprintf(stderr,
               "[art] build_classloader: PathClassLoader -> DexPathList -> %zu "
               "Element(s)\n",
               elems.size());
  return loader;
}

std::vector<uint8_t> ArtRuntime::extract_dex_bytes(uint64_t h) const {
  if (!h) return {};
  if (const std::vector<uint8_t>* b = jrt_.bytes_view(h)) return *b;  // byte[]
  const DvmValue ad = jrt_.get_field(h, "address"),
                 cp = jrt_.get_field(h, "capacity");  // direct ByteBuffer
  if (ad.i && cp.i > 0 && mem_.is_mapped((uint64_t)ad.i)) {
    std::vector<uint8_t> v((size_t)cp.i);
    e_.read((uint64_t)ad.i, v.data(), v.size());
    return v;
  }
  return {};
}

void ArtRuntime::install() {
  using V = DvmValue;
  auto is_dex = [](const std::vector<uint8_t>& b) {
    return b.size() >= 8 && std::memcmp(b.data(), "dex\n", 4) == 0;
  };
  // Extract a DEX from an arg (byte[] / direct ByteBuffer / ByteBuffer[]),
  // register it, capture it.
  auto load = [this, is_dex](uint64_t h, const char* src) -> const Dex* {
    std::vector<uint8_t> bytes = extract_dex_bytes(h);
    if (!is_dex(bytes)) {  // maybe a ByteBuffer[], take element 0.N
      for (size_t i = 0; i < jrt_.array_length(h); ++i) {
        std::vector<uint8_t> b =
            extract_dex_bytes(jrt_.object_array_element(h, i));
        if (is_dex(b)) {
          auto d = register_dex(b, "InMemoryDex");
          jrt_.notify_bytes(b, src);
          (void)d;
        }
      }
      return dexes_.empty() ? nullptr : &dexes_.back();
    }
    auto d = register_dex(bytes, "InMemoryDex");
    jrt_.notify_bytes(bytes, src);
    (void)d;
    return &dexes_.back();
  };

  // DexFile.openInMemoryDexFile(ByteBuffer, String, ClassLoader) -> DexFile
  // (also *Native / array form).
  jrt_.register_method(
      "openInMemoryDexFile",
      [this, load](JavaRuntime&, uint64_t, const std::vector<V>& a) {
        if (!a.empty())
          if (const Dex* d = load(a[0].obj, "openInMemoryDexFile"))
            return V::O(d->dexfile_obj);
        return V::V();
      });
  jrt_.register_method(
      "openInMemoryDexFilesNative",
      [this, load](JavaRuntime&, uint64_t, const std::vector<V>& a) {
        if (!a.empty())
          if (const Dex* d = load(a[0].obj, "openInMemoryDexFilesNative"))
            return V::O(d->cookie_arr);
        return V::V();
      });
  jrt_.register_method(
      "createCookieWithArray",
      [this, load](JavaRuntime&, uint64_t, const std::vector<V>& a) {
        if (!a.empty())
          if (const Dex* d = load(a[0].obj, "createCookieWithArray"))
            return V::O(d->cookie_arr);
        return V::V();
      });
  // DexFile.openDexFileNative(source, output, flags, loader, elements) ->
  // cookie
  jrt_.register_method(
      "openDexFileNative",
      [this, load](JavaRuntime&, uint64_t, const std::vector<V>& a) {
        for (const auto& v : a)
          if (v.kind == V::Object)
            if (const Dex* d = load(v.obj, "openDexFileNative"))
              return V::O(d->cookie_arr);
        return V::V();
      });
  // Build an Element[] (one dalvik/system/DexPathList$Element per registered
  // DEX) so a loader that installs via makePathElements/makeDexElements gets a
  // real, non-null array back and proceeds instead of stalling on our stub.
  auto make_elements = [this](JavaRuntime& r) {
    std::vector<uint64_t> elems;
    for (const auto& d : dexes_) {
      const uint64_t el = r.new_object("dalvik/system/DexPathList$Element");
      r.set_field(el, "dexFile", V::O(d.dexfile_obj));
      r.set_field(el, "dex", V::O(d.dexfile_obj));
      elems.push_back(el);
    }
    return V::O(r.new_object_array(std::move(elems)));
  };
  // DexPathList.makeInMemoryDexElements(ByteBuffer[] dexFiles, List suppressed)
  // -> Element[]. THE InMemoryDexClassLoader install path (API 26+): the DEX
  // ride in as direct ByteBuffers -> capture them, then hand back Element[].
  jrt_.register_method(
      "makeInMemoryDexElements",
      [this, load, make_elements](JavaRuntime& r, uint64_t,
                                  const std::vector<V>& a) {
        if (!a.empty()) load(a[0].obj, "makeInMemoryDexElements");
        return make_elements(r);
      });
  // DexPathList.makePathElements(List<File> files, File optDir, List suppressed)
  // and makeDexElements(..., ClassLoader) -> Element[]. File-based install: the
  // bytes live behind File paths (captured at the VFS write / openDexFileNative
  // read), not in these args — so here we just return a valid Element[] so a
  // loader that keys off a non-null return keeps going.
  jrt_.register_method(
      "makePathElements",
      [make_elements](JavaRuntime& r, uint64_t, const std::vector<V>&) {
        return make_elements(r);
      });
  jrt_.register_method(
      "makeDexElements",
      [make_elements](JavaRuntime& r, uint64_t, const std::vector<V>&) {
        return make_elements(r);
      });
  // DexFile.defineClassNative(name, loader, cookie, dexFile) -> Class. The DEX
  // is already captured at register time; return a class handle so the packer's
  // loader proceeds to the next class.
  jrt_.register_method("defineClassNative",
                       [](JavaRuntime& r, uint64_t, const std::vector<V>& a) {
                         std::string name;
                         if (!a.empty() && a[0].kind == V::Object)
                           if (const std::string* s = r.string_of(a[0].obj))
                             name = *s;
                         for (char& c : name)
                           if (c == '.') c = '/';
                         return V::O(name.empty() ? 0 : r.find_class(name));
                       });
  // DexFile.getClassNameList(cookie) -> String[] : the real class names from
  // the registered DEX(es).
  jrt_.register_method("getClassNameList", [this](JavaRuntime& r, uint64_t,
                                                  const std::vector<V>&) {
    std::vector<uint64_t> names;
    for (const auto& d : dexes_)
      for (const auto& n : d.class_names) names.push_back(r.new_string_utf(n));
    std::fprintf(stderr, "[art] getClassNameList -> %zu classes\n",
                 names.size());
    return V::O(r.new_object_array(std::move(names)));
  });
  // DexFile.entries(cookie) -> Enumeration<String> over the class names
  // (stateful: __names[] +
  // __idx).
  jrt_.register_method(
      "entries", [this](JavaRuntime& r, uint64_t, const std::vector<V>&) {
        std::vector<uint64_t> names;
        for (const auto& d : dexes_)
          for (const auto& n : d.class_names)
            names.push_back(r.new_string_utf(n));
        const uint64_t en = r.new_object("java/util/Enumeration");
        r.set_field(en, "__names", V::O(r.new_object_array(std::move(names))));
        r.set_field(en, "__idx", V::I(0));
        return V::O(en);
      });
  jrt_.register_method("hasMoreElements", [](JavaRuntime& r, uint64_t self,
                                             const std::vector<V>&) {
    const uint64_t arr = r.get_field(self, "__names").obj;
    const int64_t i = r.get_field(self, "__idx").i;
    return V::I(arr && (size_t)i < r.array_length(arr));
  });
  jrt_.register_method(
      "nextElement", [](JavaRuntime& r, uint64_t self, const std::vector<V>&) {
        const uint64_t arr = r.get_field(self, "__names").obj;
        const int64_t i = r.get_field(self, "__idx").i;
        r.set_field(self, "__idx", V::I(i + 1));
        return V::O(arr && (size_t)i < r.array_length(arr)
                        ? r.object_array_element(arr, (size_t)i)
                        : 0);
      });
  std::fprintf(stderr,
               "[art] install: openInMemoryDexFile/openDexFileNative/"
               "defineClassNative/getClassNameList + make{InMemoryDex,Path,Dex}"
               "Elements wired to substrate\n");
}

uint64_t ArtRuntime::dex_begin(const Dex& d) const {
  return e_.read_t<uint64_t>(d.struct_addr + layout.begin);
}
uint64_t ArtRuntime::dex_size(const Dex& d) const {
  return e_.read_t<uint64_t>(d.struct_addr + layout.size);
}

}  // namespace vardoger
