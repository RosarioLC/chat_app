#include "client.hpp"
#include "../include/crypto.hpp"
#include "../include/protocol.hpp"
#include "../include/util.hpp"
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <netinet/in.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>

static void send_line(int socket, const std::string& line) {
  send(socket, line.data(), line.size(), MSG_NOSIGNAL);
}

static inline bool send_message(int fd, const Message& m) {
  if (m.header.length != m.payload.size()) {
    return false;
  }
  if (!validate_header(m.header)) {
    return false;
  }
  if (send(fd, &m.header, sizeof(m.header), MSG_NOSIGNAL) < 0) {
    return false;
  }
  if (m.header.length) {
    if (send(fd, m.payload.data(), m.header.length, MSG_NOSIGNAL) < 0) {
      return false;
    }
  }
  return true;
}

static std::string read_line(int socket) {
  std::string line;
  char ch;

  while (read_exact(socket, &ch, 1)) {
    line.push_back(ch);
    if (ch == '\n')
      return line;
  }
  return {};
}

/* ============================================================
 *                        Constructor
 * ============================================================ */

Client::Client() {
  client_socket = socket(AF_INET, SOCK_STREAM, 0);
  check(client_socket, "socket");

  sockaddr_in serverAddr{};
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_port = htons(6969);
  serverAddr.sin_addr.s_addr = INADDR_ANY;

  check(connect(client_socket, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)), "connect");

  std::cout << "Connected to server.\n";
}

/* ============================================================
 *                        Login Phase
 * ============================================================ */

static int authenticate(int sock) {
  std::cout << "Commands: /register <user>  or  /login <user>\n";
  std::string command;

  while (true) {
    std::cout << "> " << std::flush;
    if (!std::getline(std::cin, command))
      return 0;

    std::string username, password, hash;

    if (starts_with(command, "/register ")) {
      username = command.substr(10);

      std::cout << "password: ";
      std::getline(std::cin, password);

      send_line(sock, "REG " + username + "\n");
      send_line(sock, password + "\n");
    } else if (starts_with(command, "/login ")) {
      username = command.substr(7);

      std::cout << "password: ";
      std::getline(std::cin, password);

      send_line(sock, "LOGIN " + username + "\n");
      send_line(sock, password + "\n");
    } else {
      std::cout << "Unknown command\n";
      continue;
    }

    std::string reply = read_line(sock);
    if (reply.empty()) {
      std::cout << "Server closed\n";
      return 0;
    }

    std::cout << reply;

    if (starts_with(reply, "OK")) {
      int id = std::stoi(reply.substr(3));
      std::cout << "Authenticated! Your id = " << id << "\n";
      return id;
    }
  }
}

/* ============================================================
 *                        Main Loop
 * ============================================================ */

void Client::run() {
  int user_id = authenticate(client_socket);
  if (user_id == 0) {
    return;
  }

  fcntl(client_socket, F_SETFL, O_NONBLOCK);

  struct Receiver {
    std::vector<uint8_t> buffer;
    Header header;
    bool has_header = false;
  } receiver;

  pollfd fds[2] = {{client_socket, POLLIN, 0}, {STDIN_FILENO, POLLIN, 0}};

  char input[16 * 1024];

  while (true) {
    if (poll(fds, 2, -1) <= 0) {
      std::cout << "poll error or timeout" << std::endl;
      break;
    }

    /* ==== Incoming Network Data ==== */
    if (fds[0].revents & POLLIN) {

      // Step 1: Header
      if (!receiver.has_header) {
        receiver.buffer.clear();
        receiver.buffer.reserve(sizeof(Header));

        int rc = recv_n_nb(client_socket, receiver.buffer, sizeof(Header));
        if (rc == 0)
          continue;
        if (rc == -1) {
          std::cout << "Failed to read header from socket" << std::endl;
          return;
        }

        std::memcpy(&receiver.header, receiver.buffer.data(), sizeof(Header));

        receiver.buffer.clear();
        receiver.buffer.reserve(receiver.header.length);
        receiver.has_header = true;
      }

      // Step 2: Payload
      int rc2 = recv_n_nb(client_socket, receiver.buffer, receiver.header.length);
      if (rc2 == 0)
        continue;
      if (rc2 == -1) {
        std::cout << "Failed to read payload from socket" << std::endl;
        return;
      }

      // Full frame received
      if (receiver.header.type == static_cast<uint16_t>(MessageType::CHAT)) {
        receiver.buffer.push_back('\0'); // for printing safely
        std::cout << "[" << receiver.header.sender << "] " << receiver.buffer.data();
      } else {
        // Non-text payload (e.g., keys). Ignore for display.
      }

      // Reset state
      receiver.buffer.clear();
      receiver.has_header = false;
    }

    /* ==== Outgoing User Input ==== */
    if (fds[1].revents & POLLIN) {
      if (!fgets(input, sizeof(input), stdin)) {
        std::cout << "Failed to read input" << std::endl;
        return;
      }

      std::string line = input;
      Message m = build_message(static_cast<uint16_t>(MessageType::CHAT), user_id, line.data(), line.size());
      if (!send_message(client_socket, m)) {
        std::cout << "Failed to send message" << std::endl;
        return;
      }
    }
  }
}
