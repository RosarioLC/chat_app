#include "server.hpp"
#include "../include/bcrypt.hpp"
#include "../include/util.hpp"
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <netinet/in.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

static std::string read_line(int socket, std::string& accumulator) {
  char ch;
  while (read_exact(socket, &ch, 1)) {
    accumulator += ch;
    if (ch == '\n') {
      std::string out = accumulator;
      accumulator.clear();
      return out;
    }
  }
  return {};
}

static void send_line(int socket, const std::string& line) {
  send(socket, line.data(), line.size(), MSG_NOSIGNAL);
}

void Server::broadcast_message(const Message& message) {
  for (auto& client : clients) {
    if (client.fd == -1)
      continue;

    send(client.fd, &message.header, sizeof(message.header), MSG_NOSIGNAL);
    send(client.fd, message.payload.data(), message.header.length, MSG_NOSIGNAL);
  }
}

bool Server::assemble_frame(Client& client, Message& output) {
  output = Message{};

  if (!client.hdr_ready) {
    size_t needed = sizeof(Header) - client.buffer.size();

    if (needed) {
      char tmp[needed];
      ssize_t n = recv(client.fd, tmp, needed, 0);

      if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        return false;

      if (n <= 0) {
        close(client.fd);
        client.fd = -1;
        return false;
      }

      client.buffer.insert(client.buffer.end(), tmp, tmp + n);

      if (client.buffer.size() < sizeof(Header))
        return false;
    }

    std::memcpy(&client.pending_header, client.buffer.data(), sizeof(Header));
    client.buffer.erase(client.buffer.begin(), client.buffer.begin() + sizeof(Header));
    client.hdr_ready = true;
  }

  size_t payload_size = client.pending_header.length;

  if (client.buffer.size() < payload_size) {
    size_t needed = payload_size - client.buffer.size();
    char tmp[needed];

    ssize_t n = recv(client.fd, tmp, needed, 0);

    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
      return false;

    if (n <= 0) {
      close(client.fd);
      client.fd = -1;
      return false;
    }

    client.buffer.insert(client.buffer.end(), tmp, tmp + n);
  }

  if (client.buffer.size() == payload_size) {
    output.header = client.pending_header;
    output.payload = {client.buffer.begin(), client.buffer.begin() + payload_size};

    output.valid = true;
    client.buffer.clear();
    client.hdr_ready = false;
    return true;
  }

  return false;
}

void Server::handshake_step(Client& client) {
  std::string line = read_line(client.fd, client.buffer);

  if (line.empty()) {
    close(client.fd);
    client.fd = -1;
    return;
  }

  if (!ends_with(line, "\n"))
    return;

  if (starts_with(line, "REG ")) {
    std::string username = line.substr(4, line.find('\n', 4) - 4);
    std::string password = read_line(client.fd, client.buffer);

    if (password.empty()) {
      return;
    }

    database->add_user(username, bcrypt_hash(password));
    client.user_id = database->fetch_user_id(username);

    send_line(client.fd, "OK " + std::to_string(client.user_id) + "\n");
    Message key_message;
    key_message.header = {32, 2, 0, (uint32_t)time(nullptr)};
    key_message.payload = database->fetch_public_key(client.user_id);

    send(client.fd, &key_message.header, sizeof(key_message.header), MSG_NOSIGNAL);
    send(client.fd, key_message.payload.data(), key_message.header.length, MSG_NOSIGNAL);

    fcntl(client.fd, F_SETFL, O_NONBLOCK);
    client.state = ChatState::CHATTING;

    std::cout << "User registered: " << username << " id=" << client.user_id << '\n';
  } else if (starts_with(line, "LOGIN ")) {
    std::string username = line.substr(6, line.find('\n', 6) - 6);
    std::string password = read_line(client.fd, client.buffer);

    if (password.empty())
      return;

    client.user_id = database->check_user(username, password);

    if (client.user_id) {
      send_line(client.fd, "OK " + std::to_string(client.user_id) + "\n");

      Message key_message;
      key_message.header = {32, 2, 0, (uint32_t)time(nullptr)};
      key_message.payload = database->fetch_public_key(client.user_id);
      send(client.fd, &key_message.header, sizeof(key_message.header), MSG_NOSIGNAL);
      send(client.fd, key_message.payload.data(), key_message.header.length, MSG_NOSIGNAL);

      fcntl(client.fd, F_SETFL, O_NONBLOCK);
      client.state = ChatState::CHATTING;

      std::cout << "User logged in: " << username << " id=" << client.user_id << '\n';
    } else {
      send_line(client.fd, "ERR auth_fail\n");
    }
  }
}

Server::Server(uint16_t port) : listen_port(port) {
  server_socket = socket(AF_INET, SOCK_STREAM, 0);
  check(server_socket, "socket");

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(listen_port);
  addr.sin_addr.s_addr = INADDR_ANY;

  int opt = 1;
  check(setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)), "setsockopt");

  check(bind(server_socket, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)), "bind");

  check(listen(server_socket, 1), "listen");

  database = new Database("./db/database.db");
}

void Server::run() {
  while (running.load()) {

    pollfd listener{server_socket, POLLIN, 0};
    if (poll(&listener, 1, 0) > 0) {
      int cli = accept(server_socket, nullptr, nullptr);
      if (cli >= 0) {
        fcntl(cli, F_SETFL, O_NONBLOCK);
        clients.emplace_back(Client{cli});
        std::cout << "Client connected\n";
      }
    }

    for (auto& client : clients) {
      if (client.fd == -1)
        continue;

      pollfd p{client.fd, POLLIN, 0};
      if (poll(&p, 1, 0) <= 0)
        continue;

      if (client.state == ChatState::HANDSHAKE) {
        handshake_step(client);
      } else {
        Message message;
        if (assemble_frame(client, message)) {
          message.header.sender = client.user_id;
          broadcast_message(message);
        }
      }
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
}

void Server::stop() {
  running.store(false);
}

Server::~Server() {
  running.store(false);
  close(server_socket);
  for (auto& c : clients) {
    if (c.fd != -1)
      close(c.fd);
  }
  delete database;
}
