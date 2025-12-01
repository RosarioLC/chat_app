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
#include <vector>

// Upper bound for payload size in bytes.
// Keep under typical MTU for efficiency in simple setups.
#define MAX_PAYLOAD_SIZE 4096

// Supported message channels/types.
// Extend as needed; keep `MAX_TYPE` last for bounds checking.
enum class MessageType : uint8_t { CHAT = 0, MAX_TYPE };

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

// Read exactly `n` bytes into `dst` (false on EOF/error).
// Useful for assembling headers/payloads across multiple `recv()` calls.
bool read_exact(int fd, void* dst, size_t n);
#endif
