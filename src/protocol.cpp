#include "protocol.hpp"
#include <cerrno>
#include <cstring>
#include <iostream>
#include <time.h>
#include <unistd.h>

// build_frame deprecated; prefer build_message which constructs typed Message.

bool read_exact(int fd, void* dst, size_t n) {
  uint8_t* buf = reinterpret_cast<uint8_t*>(dst);
  size_t total = 0;

  while (total < n) {
    ssize_t bytes = read(fd, buf + total, n - total);

    if (bytes == 0) {
      return false;
    }

    if (bytes < 0) {
      if (errno == EINTR)
        continue;
      return false;
    }

    total += bytes;
  }

  return true;
}
