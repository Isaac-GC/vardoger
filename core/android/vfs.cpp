#include "vardoger/android/vfs.hpp"

#include <algorithm>
#include <cstring>

namespace vardoger {

bool Vfs::exists(const std::string& path) const {
  if (store_.count(path)) return true;
  return provider_ && provider_(path).has_value();
}

bool Vfs::unlink(const std::string& path) { return store_.erase(path) != 0; }

const std::string* Vfs::content(const std::string& path) const {
  auto it = store_.find(path);
  return it == store_.end() ? nullptr : &it->second;
}

const std::string& Vfs::data_of(const Handle& h) const {
  if (h.synthetic) return h.snapshot;
  static const std::string kEmpty;
  auto it = store_.find(h.path);
  return it == store_.end() ? kEmpty : it->second;
}

int Vfs::open(const std::string& path, int flags) {
  if (wants_write(flags)) {
    auto it = store_.find(path);
    if (it == store_.end())
      it = store_.emplace(path, std::string{}).first;  // create
    else if (flags & kTrunc)
      it->second.clear();
    Handle h;
    h.path = path;
    h.writable = true;
    h.pos = (flags & kAppend) ? it->second.size() : 0;
    const int fd = next_fd_++;
    handles_[fd] = std::move(h);
    return fd;
  }
  if (store_.count(path)) {
    Handle h;
    h.path = path;
    const int fd = next_fd_++;
    handles_[fd] = std::move(h);
    return fd;
  }
  if (provider_) {
    if (auto c = provider_(path)) {
      Handle h;
      h.synthetic = true;
      h.snapshot = std::move(*c);
      const int fd = next_fd_++;
      handles_[fd] = std::move(h);
      return fd;
    }
  }
  return 0;  // not served
}

size_t Vfs::read(int fd, std::string& out, size_t n) {
  auto it = handles_.find(fd);
  if (it == handles_.end()) return 0;
  Handle& h = it->second;
  const std::string& src = data_of(h);
  const size_t avail = src.size() > h.pos ? src.size() - h.pos : 0;
  const size_t take = std::min(n, avail);
  out.assign(src, h.pos, take);
  h.pos += take;
  return take;
}

size_t Vfs::write(int fd, const uint8_t* data, size_t n) {
  auto it = handles_.find(fd);
  if (it == handles_.end() || !it->second.writable) return 0;
  Handle& h = it->second;
  std::string& dst = store_[h.path];
  if (h.pos + n > dst.size()) dst.resize(h.pos + n, '\0');
  if (n) std::memcpy(&dst[h.pos], data, n);
  h.pos += n;
  h.dirty = true;
  return n;
}

bool Vfs::gets(int fd, std::string& line_out, size_t max) {
  auto it = handles_.find(fd);
  if (it == handles_.end() || max == 0) return false;
  Handle& h = it->second;
  const std::string& src = data_of(h);
  if (h.pos >= src.size()) return false;
  line_out.clear();
  while (h.pos < src.size() && line_out.size() + 1 < max) {
    const char c = src[h.pos++];
    line_out.push_back(c);
    if (c == '\n') break;
  }
  return true;
}

size_t Vfs::size(int fd) const {
  auto it = handles_.find(fd);
  return it == handles_.end() ? 0 : data_of(it->second).size();
}

size_t Vfs::tell(int fd) const {
  auto it = handles_.find(fd);
  return it == handles_.end() ? 0 : it->second.pos;
}

void Vfs::seek(int fd, size_t pos) {
  auto it = handles_.find(fd);
  if (it == handles_.end()) return;
  it->second.pos = std::min(pos, data_of(it->second).size());
}

void Vfs::close(int fd) {
  auto it = handles_.find(fd);
  if (it == handles_.end()) return;
  Handle& h = it->second;
  if (h.writable && h.dirty && on_write_) {
    const std::string& d = store_[h.path];
    on_write_(h.path, std::vector<uint8_t>(d.begin(), d.end()));
  }
  handles_.erase(it);
}

}  // namespace vardoger
