// vardoger: in-memory virtual filesystem.
//
// A path->bytes store plus an fd table, shared by the libc stubs and the
// raw-syscall layer (so a file opened via fopen fstat's the same as one opened
// via openat). Unlike the original read-only file model, the VFS is READ-WRITE:
// the guest can create and write files, a packer dropping a decrypted DEX/odex
// to "disk", read them back, and stat/unlink them. A write-observer fires when
// a written file is closed, so the extractor can capture payloads that only
// ever touch the filesystem. Paths the store doesn't hold are offered to a
// Provider (System wires the synthetic /proc/* files).
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace vardoger {

class Vfs {
 public:
  // Low bits of Linux/bionic open() flags, so raw openat flags pass straight
  // through.
  enum {
    kRdOnly = 0,
    kWrOnly = 1,
    kRdWr = 2,
    kCreat = 0100,
    kTrunc = 01000,
    kAppend = 02000
  };
  static bool wants_write(int flags) {
    return (flags & (kWrOnly | kRdWr)) || (flags & kCreat);
  }

  using Provider =
      std::function<std::optional<std::string>(const std::string&)>;
  using WriteObserver =
      std::function<void(const std::string& path, const std::vector<uint8_t>&)>;

  void set_provider(Provider p) { provider_ = std::move(p); }
  void set_write_observer(WriteObserver o) { on_write_ = std::move(o); }

  // Host -> guest preload (e.g. the APK). Overwrites any existing entry.
  void add_file(const std::string& path, std::string content) {
    store_[path] = std::move(content);
  }
  // Register a directory so it "exists" (access/stat), the way an installed
  // app's /data/app/... and /data/user/0/... directories do on a real device.
  // Trailing slashes are trimmed.
  void add_dir(const std::string& path);
  // A directory exists if it was add_dir'd or if any stored file lives under it.
  bool is_dir(const std::string& path) const;
  bool exists(const std::string& path) const;
  bool unlink(const std::string& path);
  const std::string* content(
      const std::string& path) const;  // peek backing bytes (nullptr if absent)
  const std::map<std::string, std::string>& files() const { return store_; }
  const std::set<std::string>& dirs() const { return dirs_; }

  int open(const std::string& path, int flags);  // fd >= 3, or 0 if unavailable
  // Duplicate an open fd onto a fresh number (dup): the new handle shares the
  // backing path but has its own position. Returns the new fd, or 0 if oldfd
  // isn't open.
  int dup(int oldfd);
  // Duplicate oldfd onto the specific number newfd (dup2/dup3): closes whatever
  // was at newfd first. Returns newfd, or -1 if oldfd isn't open.
  int dup2(int oldfd, int newfd);
  bool is_open(int fd) const { return handles_.count(fd) != 0; }
  size_t read(int fd, std::string& out, size_t n);
  size_t write(int fd, const uint8_t* data, size_t n);
  bool gets(int fd, std::string& line, size_t max);
  size_t size(int fd) const;
  size_t tell(int fd) const;
  void seek(int fd, size_t pos);
  void close(int fd);

 private:
  struct Handle {
    std::string path;  // backing key in store_ (empty for synthetic)
    std::string
        snapshot;  // provider content captured at open (synthetic reads)
    size_t pos = 0;
    bool writable = false;
    bool synthetic = false;
    bool dirty = false;
  };
  const std::string& data_of(const Handle& h) const;

  std::map<std::string, std::string>
      store_;                      // path -> bytes (preloaded + created)
  std::set<std::string> dirs_;     // registered directory paths (no trailing /)
  std::map<int, Handle> handles_;  // fd -> open handle
  int next_fd_ = 3;                // 0,1,2 reserved
  Provider provider_;
  WriteObserver on_write_;
};

}  // namespace vardoger
