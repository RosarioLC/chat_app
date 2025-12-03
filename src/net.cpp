#include "net.hpp"
#include "protocol.hpp"
#include "util.hpp"
#include <cerrno>
#include <sys/socket.h>
#include <unistd.h>

namespace net {
bool send_all(int fd, const uint8_t* data, size_t len) {
  size_t sent = 0;
  while (sent < len) {
    ssize_t rc = send(fd, data + sent, len - sent, MSG_NOSIGNAL);
    if (rc > 0) {
      sent += static_cast<size_t>(rc);
      continue;
    }
    if (rc == 0) {
      return false; // peer closed
    }
    if (rc < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // brief yield; caller is non-blocking, try again
        usleep(1000);
        continue;
      }
      return false;
    }
  }
  return true;
}

void send_line(int socket, const std::string& line) {
  send(socket, line.data(), line.size(), MSG_NOSIGNAL);
}

bool send_message(int fd, const Message& m) {
  if (m.header.length != m.payload.size()) {
    return false;
  }
  if (!validate_header(m.header)) {
    return false;
  }
  if (!send_all(fd, reinterpret_cast<const uint8_t*>(&m.header), sizeof(m.header))) {
    return false;
  }
  if (m.header.length) {
    if (!send_all(fd, m.payload.data(), m.header.length)) {
      return false;
    }
  }
  return true;
}

std::string read_line(int socket) {
  std::string line;
  char ch;
  while (read_exact(socket, &ch, 1)) {
    line.push_back(ch);
    if (ch == '\n')
      return line;
  }
  return {};
}

std::string read_line_acc(int socket, std::vector<uint8_t>& accumulator) {
  char ch;
  while (read_exact(socket, &ch, 1)) {
    accumulator.push_back(static_cast<uint8_t>(ch));
    if (ch == '\n') {
      std::string out(accumulator.begin(), accumulator.end());
      accumulator.clear();
      return out;
    }
  }
  return {};
}

bool recv_all_nb(int fd, std::vector<uint8_t>& buffer, size_t n) {
  size_t got = 0;
  buffer.reserve(buffer.size() + n);
  while (got < n) {
    uint8_t tmp[1024];
    size_t want = std::min(sizeof(tmp), n - got);
    ssize_t rc = recv(fd, tmp, want, 0);
    if (rc > 0) {
      buffer.insert(buffer.end(), tmp, tmp + rc);
      got += static_cast<size_t>(rc);
      continue;
    }
    if (rc == 0) {
      return false; // peer closed
    }
    if (rc < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        usleep(1000);
        continue;
      }
      return false;
    }
  }
  return true;
}
} // namespace net
