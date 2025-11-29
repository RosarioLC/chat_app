#include "../include/protocol.hpp"
#include <cerrno>
#include <iostream>
#include <time.h>
#include <unistd.h>

std::vector<uint8_t> build_frame(uint16_t type, uint16_t sender, const void* payload,
                                 uint32_t pay_len) {
  Header header;
  header.length = pay_len;
  header.sender = sender;
  header.type = type;
  header.timestamp = static_cast<uint32_t>(time(nullptr));

  std::vector<uint8_t> out;
  out.reserve(sizeof(Header) + pay_len);

  const uint8_t* header_bytes = reinterpret_cast<const uint8_t*>(&header);
  out.insert(out.end(), header_bytes, header_bytes + sizeof(header));

  const uint8_t* payload_bytes = static_cast<const uint8_t*>(payload);
  out.insert(out.end(), payload_bytes, payload_bytes + pay_len);

  return out;
}

bool read_exact(int fd, void* dst, size_t n) {
  uint8_t* buf = reinterpret_cast<uint8_t*>(dst);
  size_t total = 0;

  while (total < n) {
    ssize_t bytes = read(fd, buf + total, n - total);

    if (bytes == 0) {
      // EOF → connection closed cleanly
      return false;
    }

    if (bytes < 0) {
      // If the read was interrupted, retry
      if (errno == EINTR)
        continue;
      return false;
    }

    total += bytes;
  }

  return true;
}

int check(int result, const char* funcname) {
  if (result < 0) {
    perror(funcname);
    return -1;
  }
  return 0;
}
