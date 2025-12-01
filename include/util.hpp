// Small utility helpers
//
// `starts_with` and `ends_with` provide simple string prefix/suffix checks.
// `check` prints an error (errno) when a syscall-like function returns < 0
// and converts the result into 0 (success) or -1 (failure).
#pragma once
#include <algorithm>
#include <cerrno>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

// True if `s` starts with `prefix`.
static inline bool starts_with(const std::string& s, const std::string& prefix) {
  return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

// True if `s` ends with `suffix`.
static inline bool ends_with(const std::string& s, const std::string& suffix) {
  return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// Print errno if result < 0; return 0 on success, -1 on error.
static inline int check(int result, const char* funcname) {
  if (result < 0) {
    perror(funcname);
    return -1;
  }
  return 0;
}

// Attempt to read exactly `n` bytes from `fd` into `buf` (appending).
// Returns:
//  1  - successfully read `n` bytes (buf has >= initial+n)
//  0  - would block / not enough data yet (no fatal error)
// -1  - fatal error or EOF (caller should close)
static inline int recv_n_nb(int fd, std::vector<uint8_t>& buf, size_t n) {
  char tmp[4096];
  while (buf.size() < n) {
    size_t remaining = n - buf.size();
    size_t toRead = std::min<size_t>(remaining, sizeof(tmp));
    ssize_t r = recv(fd, tmp, toRead, 0);
    if (r < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return 0;
      return -1;
    }
    if (r == 0)
      return -1;
    buf.insert(buf.end(), tmp, tmp + r);
  }
  return 1;
}
