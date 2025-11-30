#ifndef PROTOCOL_HPP
#define PROTOCOL_HPP

#include <cstdint>
#include <vector>

#define MAX_PAYLOAD_SIZE 4096

enum class MessageType : uint8_t {
  CHAT = 0,
  // Add more types here if needed:
  // FILE,
  // TYPING,
  // HEARTBEAT,
  // AUTH,
  MAX_TYPE // Always keep this last for validation
};

// packed 12-byte header
#pragma pack(push, 1)
struct Header {
  uint32_t length;
  uint16_t type;
  uint16_t sender;
  uint32_t timestamp;
};
#pragma pack(pop)

struct Message {
  Header header;
  std::vector<uint8_t> payload;
  bool valid = false;
};

/* build a full frame: header + payload */
std::vector<uint8_t> build_frame(uint16_t type, uint16_t sender, const void* payload, uint32_t pay_len);

/* read exactly n bytes (false on EOF/error) */
bool read_exact(int fd, void* dst, size_t n);

#endif // PROTOCOL_HPP
