#pragma once
// Net module: shared networking helpers for line and framed I/O.
#include "protocol.hpp"
#include <string>
#include <vector>

namespace net {
// Write all bytes handling partial writes and EAGAIN.
bool send_all(int fd, const uint8_t* data, size_t len);
// Send a line (no implicit terminator). Attempts to write all bytes.
void send_line(int socket, const std::string& line);

// Message/frame send following `protocol::Header` layout.
bool send_message(int fd, const Message& m);

// Read a line terminated by '\n' into a std::string (blocking exact read helper).
std::string read_line(int socket);

// Read a line terminated by '\n' using an accumulator buffer (server variant).
std::string read_line_acc(int socket, std::vector<uint8_t>& accumulator);
// Non-blocking read helper: attempts to read up to `n` bytes, appending into `buffer`.
// Returns true on any progress; false if peer closed or hard error; handles EAGAIN with brief backoff.
bool recv_all_nb(int fd, std::vector<uint8_t>& buffer, size_t n);
} // namespace net
