#include "client.hpp"
#include "../include/bcrypt.hpp"
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

static bool read_from_socket(int sock, std::vector<uint8_t>& buf, size_t amount) {
  char tmp[4096];
  while (buf.size() < amount) {
    size_t remaining = amount - buf.size();
    size_t toRead = std::min(remaining, sizeof(tmp));

    ssize_t n = recv(sock, tmp, toRead, 0);
    if (n <= 0) {
      if (n == 0)
        std::cerr << "Server closed\n";
      return false;
    }
    buf.insert(buf.end(), tmp, tmp + n);
  }
  return true;
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
  if (user_id == 0)
    return;

  fcntl(client_socket, F_SETFL, O_NONBLOCK);

  struct Receiver {
    std::vector<uint8_t> buffer;
    Header header;
    bool hasHeader = false;
  } receiver;

  pollfd fds[2] = {{client_socket, POLLIN, 0}, {STDIN_FILENO, POLLIN, 0}};

  char input[16 * 1024];

  while (true) {
    if (poll(fds, 2, -1) <= 0)
      break;

    /* ==== Incoming Network Data ==== */
    if (fds[0].revents & POLLIN) {

      // Step 1: Header
      if (!receiver.hasHeader) {
        receiver.buffer.clear();
        receiver.buffer.reserve(sizeof(Header));

        if (!read_from_socket(client_socket, receiver.buffer, sizeof(Header)))
          return;

        std::memcpy(&receiver.header, receiver.buffer.data(), sizeof(Header));

        receiver.buffer.clear();
        receiver.buffer.reserve(receiver.header.length);
        receiver.hasHeader = true;
      }

      // Step 2: Payload
      if (!read_from_socket(client_socket, receiver.buffer, receiver.header.length)) {
        return;
      }

      // Full frame received
      receiver.buffer.push_back('\0'); // for printing safely
      std::cout << "[" << receiver.header.sender << "] " << receiver.buffer.data();

      // Reset state
      receiver.buffer.clear();
      receiver.hasHeader = false;
    }

    /* ==== Outgoing User Input ==== */
    if (fds[1].revents & POLLIN) {
      if (!fgets(input, sizeof(input), stdin))
        return;

      std::string line = input;
      auto frame = build_frame(1, // Message type/channel
                               user_id, line.data(), line.size());

      send(client_socket, frame.data(), frame.size(), MSG_NOSIGNAL);
    }
  }
}
