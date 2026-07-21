// vardoger: system facade for anti-analysis consistency.
//
// One place that answers "what device is this": system properties, synthesized
// /proc files, and a controlled monotonic clock, all derived from the same
// DeviceIdentity the JNI Build.* fields use, so every check sees one coherent,
// un-rooted, un-debugged, non-emulator device.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

#include "vardoger/android/android_env.hpp"  // DeviceIdentity
#include "vardoger/android/vfs.hpp"
#include "vardoger/engine/memory.hpp"

namespace vardoger {

class System {
 public:
  System(Memory& mem, DeviceIdentity id);

  // __system_property_get(name): the fingerprint value, or "" if unknown.
  std::string get_property(const std::string& name) const;
  // Override/add a property (e.g. a driver simulating a specific OEM device so
  // a device-targeted packer takes its activation path). Empty value ==
  // "absent".
  void set_property(const std::string& name, std::string value);

  // Serve real bytes for a path (e.g. the sample's APK/classes.dex) through the
  // virtual FS. General primitive, a driver registers what a packer will read.
  void add_file(const std::string& path, std::string content);

  // Virtual filesystem: synthesized /proc/* (provider) plus anything
  // add_file()'d or written by the guest. ONE fd table (in Vfs), shared by libc
  // stubs AND raw syscalls, a file opened via raw openat fstat's the same via
  // the libc import, and a file the guest WRITES (a dropped decrypted DEX)
  // reads back. vopen returns an fd >= 3, or 0 if the path isn't served.
  // `flags` are raw Linux open() flags (Vfs::kCreat/kWrOnly/...).
  int vopen(const std::string& path, int flags = Vfs::kRdOnly);
  bool is_open(int fd) const { return vfs_.is_open(fd); }
  bool vgets(int fd, std::string& line_out, size_t max) {
    return vfs_.gets(fd, line_out, max);
  }
  size_t vread(int fd, std::string& out, size_t n) {
    return vfs_.read(fd, out, n);
  }
  size_t vwrite(int fd, const uint8_t* data, size_t n) {
    return vfs_.write(fd, data, n);
  }
  size_t vsize(int fd) const { return vfs_.size(fd); }
  size_t vtell(int fd) const { return vfs_.tell(fd); }
  void vseek(int fd, size_t pos) { vfs_.seek(fd, pos); }
  void vclose(int fd) { vfs_.close(fd); }
  bool vexists(const std::string& path) const { return vfs_.exists(path); }
  bool vunlink(const std::string& path) { return vfs_.unlink(path); }

  // Direct VFS access, e.g. a driver registering a write-observer to capture a
  // decrypted DEX the packer drops to disk, or inspecting the resulting files.
  Vfs& vfs() { return vfs_; }
  const Vfs& vfs() const { return vfs_; }
  void set_write_observer(Vfs::WriteObserver o) {
    vfs_.set_write_observer(std::move(o));
  }

  // Monotonic clock in nanoseconds; advances a fixed delta per call so elapsed
  // time looks normal regardless of how slowly we actually emulate.
  uint64_t now_ns();

  // Wall-clock epoch (seconds since 1970), one consistent "now" for
  // time()/date checks (e.g. a packer's license window). Fixed by default; a
  // driver can pin it.
  uint64_t now_unix() const { return unix_epoch_; }
  void set_now_unix(uint64_t t) { unix_epoch_ = t; }

 private:
  // Synthetic, dynamically-generated paths (/proc/self/maps reflects live
  // memory, so it can't be a static file). Returns the content, or nullopt if
  // this isn't a synth path.
  std::optional<std::string> synth(const std::string& path) const;

  Memory& mem_;
  DeviceIdentity id_;
  std::unordered_map<std::string, std::string> props_;
  Vfs vfs_;  // read-write virtual filesystem
  uint64_t clock_ns_ = 1'500'000'000ull;
  uint64_t unix_epoch_ = 1'748'736'000ull;  // 2025-06-01 UTC
};

}  // namespace vardoger
