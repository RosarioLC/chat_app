// Message protocol structures and helpers
//
// Overview:
// - Defines the wire format for chat messages exchanged between client/server
// - Header is a packed 12 bytes with payload length, type, sender, timestamp
// - `build_frame()` assembles a binary frame (header + payload)
// - `read_exact()` ensures robust socket reads of fixed-size segments
#ifndef PROTOCOL_HPP
#define PROTOCOL_HPP
#include <cstdint>
#include <ctime>
#include <vector>

// Upper bound for payload size in bytes.
// Keep under typical MTU for efficiency in simple setups.
#define MAX_PAYLOAD_SIZE 4096

// Supported message channels/types.
// Extend as needed; keep `MAX_TYPE` last for bounds checking.
// Define explicit message type ids used on the wire.
// CHAT: textual user messages
// KEY: binary public key frame after auth
// MAX_TYPE: sentinel (keep last)
enum class MessageType : uint8_t { CHAT = 1, KEY = 2, EPHEMERAL = 3, MAX_TYPE };

// Packed 12-byte header layout.
// Fields:
// - `length`: payload size in bytes
// - `type`: value from `MessageType` (channel)
// - `sender`: numeric user id (server stamps this)
// - `timestamp`: epoch seconds
#pragma pack(push, 1)
struct Header {
  uint32_t length;
  uint16_t type;
  uint16_t sender;
  uint32_t timestamp;
};
#pragma pack(pop)

// Complete message: header + payload.
// `valid` is set by assembly logic when the frame is ready.
struct Message {
  Header header;
  std::vector<uint8_t> payload;
  bool valid = false;
};

// Build a message frame (header + payload).
// Inputs:
// - `type`: message type
// - `sender`: user id
// - `payload` and `pay_len`: raw bytes and length
// Returns: binary buffer ready to send via `send()`.
std::vector<uint8_t> build_frame(uint16_t type, uint16_t sender, const void* payload, uint32_t pay_len);
inline Message build_message(uint16_t type, uint16_t sender, const void* payload, uint32_t pay_len) {
  Message m;
  m.header.length = pay_len;
  m.header.type = type;
  m.header.sender = sender;
  m.header.timestamp = static_cast<uint32_t>(time(nullptr));
  const uint8_t* p = static_cast<const uint8_t*>(payload);
  m.payload.assign(p, p + pay_len);
  m.valid = true;
  return m;
}

// Read exactly `n` bytes into `dst` (false on EOF/error).
// Useful for assembling headers/payloads across multiple `recv()` calls.
bool read_exact(int fd, void* dst, size_t n);

// Validate header fields against basic constraints (payload size, type bounds)
inline bool validate_header(const Header& h) {
  // Allow types in [CHAT..KEY]; reject zero or sentinel values.
  return h.length <= MAX_PAYLOAD_SIZE && h.type >= static_cast<uint16_t>(MessageType::CHAT) && h.type < static_cast<uint16_t>(MessageType::MAX_TYPE);
}
#endif
