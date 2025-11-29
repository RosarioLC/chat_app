#ifndef PROTOCOL_HPP
#define PROTOCOL_HPP

#include <cstdint>
#include <vector>

// packed 12-byte header
#pragma pack(push, 1)
struct Header {
  uint32_t length; // payload size only
  uint16_t type;
  uint16_t sender;
  uint32_t timestamp;
};
#pragma pack(pop)

/* build a full frame: header + payload */
std::vector<uint8_t> build_frame(uint16_t type, uint16_t sender, const void* payload,
                                 uint32_t pay_len);

/* read exactly n bytes (false on EOF/error) */
bool read_exact(int fd, void* dst, size_t n);

int check(int result, const char* funcname);

#endif // PROTOCOL_HPP
