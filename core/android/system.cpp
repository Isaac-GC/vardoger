#include "vardoger/android/system.hpp"

#include <cstdio>

namespace vardoger {

System::System(Memory& mem, DeviceIdentity id) : mem_(mem), id_(std::move(id)) {
  // A real, un-rooted physical-device fingerprint. The emulator/root tells
  // (ro.kernel.qemu, ro.secure=0, ro.debuggable=1) are deliberately "clean".
  props_ = {
      {"ro.product.model", id_.model},
      {"ro.product.real_model",
       id_.model},  // vendor prop some packers probe (was null)
      {"ro.product.manufacturer", id_.manufacturer},
      {"ro.product.brand", "google"},
      {"ro.product.name", "raven"},
      {"ro.product.device", "raven"},
      {"ro.hardware", "raven"},
      {"ro.build.version.sdk", std::to_string(id_.sdk_int)},
      {"ro.build.version.release", "12"},
      {"ro.build.fingerprint", id_.fingerprint},
      {"ro.build.type", "user"},
      {"ro.build.tags", "release-keys"},
      {"ro.kernel.qemu", ""},  // non-empty would scream "emulator"
      {"ro.secure", "1"},
      {"ro.debuggable", "0"},
      {"ro.boot.verifiedbootstate", "green"},
      // Runtime/ART facts a real Android device always reports. Packers that
      // probe the runtime (e.g. Ducex's init constructor checks the VM is ART)
      // branch on these; absent values look like a non-Android / broken host
      // and can disarm device-targeted activation paths. Values match a real
      // API-31 device.
      {"persist.sys.dalvik.vm.lib.2", "libart.so"},
      {"build.version.extensions.r", "1"},
      {"build.version.extensions.s", "1"},
      {"debug.atrace.tags.enableflags", "0"},
  };
  // The VFS serves real/created files directly; paths it lacks fall through to
  // synth() for the dynamic /proc/* views (which reflect live memory and can't
  // be static files).
  vfs_.set_provider([this](const std::string& path) { return synth(path); });
}

void System::register_app_dirs() {
  // Add a directory and every ancestor down to "/data" so intermediate
  // stat()/access() calls succeed too.
  auto add_with_parents = [this](std::string p) {
    while (p.size() > 1 && p.back() == '/') p.pop_back();
    while (p.size() > 1) {
      vfs_.add_dir(p);
      const auto s = p.find_last_of('/');
      if (s == std::string::npos || s == 0) break;
      p = p.substr(0, s);
    }
  };
  auto dirname = [](const std::string& p) {
    const auto s = p.find_last_of('/');
    return (s == std::string::npos || s == 0) ? std::string("/")
                                              : p.substr(0, s);
  };
  const std::string& pkg = id_.package_name;
  add_with_parents(dirname(id_.apk_path));   // code dir (+ ~~ dir + /data/app)
  add_with_parents(id_.native_lib_dir);      // lib/<arch> (+ lib dir)
  add_with_parents(id_.data_dir);            // files (+ /data/user/0/<pkg>)
  add_with_parents("/data/user/0/" + pkg + "/cache");
  add_with_parents("/data/data/" + pkg + "/cache");
  add_with_parents("/data/data/" + pkg);
}

std::string System::get_property(const std::string& name) const {
  auto it = props_.find(name);
  std::string value = it == props_.end() ? std::string{} : it->second;
  if (prop_observer_) prop_observer_(name, value);
  return value;
}

void System::set_property(const std::string& name, std::string value) {
  props_[name] = std::move(value);
}

void System::add_file(const std::string& path, std::string content) {
  vfs_.add_file(path, std::move(content));
}

std::optional<std::string> System::synth(const std::string& path) const {
  // process name = last component of the package
  std::string proc = id_.package_name;
  if (auto dot = proc.find_last_of('.'); dot != std::string::npos)
    proc = proc.substr(dot + 1);

  if (std::getenv("VARDOGER_PROC_HIDE") &&
      (path == "/proc/self/status" || path == "/proc/self/maps"))
    return std::nullopt;
  if (path == "/proc/self/status") {
    return "Name:\t" + proc +
           "\n"
           "Umask:\t0077\n"
           "State:\tS (sleeping)\n"
           "Tgid:\t1234\n"
           "Pid:\t1234\n"
           "PPid:\t903\n"     // parent = zygote64 (matches getppid stub)
           "TracerPid:\t0\n"  // not being debugged
           "Uid:\t10234\t10234\t10234\t10234\n"
           "Gid:\t10234\t10234\t10234\t10234\n";
  }
  if (path == "/proc/self/cmdline") {
    return id_.package_name + std::string(1, '\0');
  }
  // /proc/<ppid>/cmdline & /proc/<ppid>/comm: anti-debug guardians read the
  // PARENT's cmdline and require it to be zygote/zygote64 (a normal Android app
  // parent). A missing file (or a debugger name) trips detection. Serve
  // zygote64 for any non-self numeric pid the packer probes.
  if (path.rfind("/proc/", 0) == 0 &&
      (path.size() > 9 && (path.substr(path.size() - 8) == "/cmdline" ||
                           path.substr(path.size() - 5) == "/comm"))) {
    const std::string mid = path.substr(6, path.find('/', 6) - 6);
    if (mid != "self" && !mid.empty() &&
        mid.find_first_not_of("0123456789") == std::string::npos)
      return std::string("zygote64") + '\0';
  }
  if (path == "/proc/self/comm") return std::string(proc) + "\n";
  // /proc/self/wchan + /proc/<tid>/wchan: the kernel wait-channel symbol.
  // Anti-analysis code polls it (looking for "ptrace_stop"/"SyS_ptrace" = a
  // ptraced/stopped process) and can spin-retry if the read FAILS. A missing
  // file (ENOENT) made Ijiami's N.al loop forever on
  // openat("/proc/self/wchan"). Serve a benign on-CPU value ("0") so the read
  // succeeds and looks untraced.
  if (path.rfind("/proc/", 0) == 0 && path.size() > 6 &&
      path.substr(path.size() - 6) == "/wchan")
    return std::string("0");
  if (path == "/proc/cpuinfo") {
    return "Processor\t: AArch64 Processor rev 1 (aarch64)\n"
           "Hardware\t: Google Tensor\n"  // not "goldfish"/"ranchu"
           "CPU implementer\t: 0x41\n";
  }
  if (path == "/proc/version") {
    return "Linux version 4.14.180-g1234567 (android-build@abfarm) "
           "(clang version 8.0.7) #1 SMP PREEMPT Wed Jan 1 00:00:00 UTC 2020\n";
  }
  if (path == "/proc/meminfo") {
    return "MemTotal:        3809296 kB\nMemFree:          123456 kB\n"
           "MemAvailable:    1987654 kB\nBuffers:           45678 kB\n";
  }
  if (path == "/proc/self/maps") {
    std::string out;
    char line[512];
    auto emit = [&](uint64_t a, uint64_t b, const char* perms, uint64_t off,
                    int inode, const std::string& nm) {
      std::snprintf(line, sizeof(line),
                    "%012llx-%012llx %s %08llx fd:03 %-8d %s\n",
                    (unsigned long long)a, (unsigned long long)b, perms,
                    (unsigned long long)off, inode, nm.c_str());
      out += line;
    };
    for (const Memory::Region& r : mem_.regions()) {
      std::string name = r.label;
      if (name.size() > 3 && name.substr(name.size() - 3) == ".so") {
        // ART/runtime libs live under /apex on API>=29, NOT the app lib dir. A
        // packer that scans /proc/self/maps to locate libart (to inline-hook
        // ClassLinker::LoadMethod etc.) matches on the real apex path; the
        // app-lib path defeats detection. Map the known ART libs to /apex.
        static const std::pair<const char*, const char*> kApexLibs[] = {
            {"libart.so", "/apex/com.android.art/lib64/libart.so"},
            {"libartbase.so", "/apex/com.android.art/lib64/libartbase.so"},
            {"libdexfile.so", "/apex/com.android.art/lib64/libdexfile.so"},
            {"libprofile.so", "/apex/com.android.art/lib64/libprofile.so"},
        };
        bool apex = false;
        for (const auto& [b, p] : kApexLibs)
          if (name == b) {
            name = p;
            apex = true;
            break;
          }
        if (!apex) name = id_.native_lib_dir + "/" + name;
      }
      const int inode = 1000 + static_cast<int>(r.base >> 20);
      // A loaded .so: split into per-PT_LOAD lines with REAL segment perms
      // (r-xp / rw-p) and a realistic path, so packers that locate their
      // executable segment by perms or match by path find the correct base (one
      // rwxp blob fails those checks). General.
      Engine& e = mem_.engine();
      bool split = false;
      if (r.kind == Memory::Kind::Lib && mem_.is_mapped(r.base) &&
          e.read_t<uint32_t>(r.base) == 0x464c457f) {
        const uint64_t phoff = e.read_t<uint64_t>(r.base + 32);
        const uint16_t phnum = e.read_t<uint16_t>(r.base + 56),
                       phent = e.read_t<uint16_t>(r.base + 54);
        for (uint16_t i = 0; i < phnum && phent; ++i) {
          const uint64_t ph = r.base + phoff + i * phent;
          if (e.read_t<uint32_t>(ph) != 1) continue;  // PT_LOAD
          const uint32_t fl = e.read_t<uint32_t>(ph + 4);
          const uint64_t va = e.read_t<uint64_t>(ph + 16),
                         msz = e.read_t<uint64_t>(ph + 40),
                         fo = e.read_t<uint64_t>(ph + 8);
          char p[5] = "---p";
          if (fl & 4) p[0] = 'r';
          if (fl & 2) p[1] = 'w';
          if (fl & 1) p[2] = 'x';
          emit((r.base + va) & ~uint64_t(0xfff),
               (r.base + va + msz + 0xfff) & ~uint64_t(0xfff), p, fo, inode,
               name);
          split = true;
        }
      }
      if (split) continue;
      // Sanitise vardoger-internal regions so a maps-scanning anti-inject
      // watchdog doesn't flag them: an EXECUTABLE region with a non-file path
      // (our trampoline) is a classic code-injection signature, real Android
      // has no anonymous executable mappings. Hide it, and give the other
      // internal regions realistic anonymous/[stack]/[heap] names instead of
      // "trampoline"/"java"/"tls"/"soname"/"dl_phdr_info".
      using K = Memory::Kind;
      if (r.kind == K::Trampoline || r.kind == K::Kuser || r.kind == K::Fini)
        continue;
      char perms[5] = "---p";
      if (r.prot & UC_PROT_READ) perms[0] = 'r';
      if (r.prot & UC_PROT_WRITE) perms[1] = 'w';
      if (r.prot & UC_PROT_EXEC) perms[2] = 'x';
      if (perms[2] == 'x' && r.kind != K::Lib)
        continue;  // no anonymous executable mappings
      if (r.kind == K::Stack)
        name = "[stack]";
      else if (r.kind == K::Heap)
        name = "[anon:libc_malloc]";
      else if (r.kind != K::Lib)
        name = "";  // Java/Tls/Mmap/Other -> anonymous
      emit(r.base, r.base + r.size, perms, 0, inode, name);
    }
    // Synthetic system mappings that a real Android process always has and that
    // maps-scanning anti-inject watchdogs check for by presence (their ABSENCE
    // reads as injected/abnormal, e.g. Virbox scans for "/linker"). General:
    // harmless extra lines for any packer.
    emit(0x7b40000000ull, 0x7b40040000ull, "r-xp", 0, 2001,
         "/apex/com.android.runtime/bin/linker64");
    emit(0x7b40040000ull, 0x7b40052000ull, "r--p", 0x40000, 2001,
         "/apex/com.android.runtime/bin/linker64");
    emit(0x7b50000000ull, 0x7b50120000ull, "r-xp", 0, 2002,
         "/apex/com.android.runtime/lib64/bionic/libc.so");
    return out;
  }
  return std::nullopt;  // not a synth path -> let the VFS report ENOENT
}

int System::vopen(const std::string& path, int flags) {
  return vfs_.open(path, flags);
}

uint64_t System::now_ns() {
  clock_ns_ +=
      1'000'000;  // +1 ms per query, decoupled from real emulation speed
  return clock_ns_;
}

}  // namespace vardoger
