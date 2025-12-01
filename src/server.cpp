#include "server.hpp"
#include "../include/crypto.hpp"
#include "../include/util.hpp"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <iomanip>
#include <iostream>
#include <netinet/in.h>
#include <sstream>
#include <sys/poll.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

static std::string read_line(int socket, std::vector<uint8_t>& accumulator) {
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

static inline void server_log(const char* level, const std::string& msg) {
  auto now = std::chrono::system_clock::now();
  std::time_t t = std::chrono::system_clock::to_time_t(now);
  std::tm tm = *std::localtime(&t);
  std::ostringstream oss;
  oss << std::put_time(&tm, "%F %T") << " [" << level << "] " << msg;
  std::cout << oss.str() << std::endl;
}

static void send_line(int socket, const std::string& line) {
  send(socket, line.data(), line.size(), MSG_NOSIGNAL);
}

static inline void send_message(int fd, const Message& m) {
  ssize_t n1 = send(fd, &m.header, sizeof(m.header), MSG_NOSIGNAL);
  if (n1 < 0) {
    server_log("ERROR", std::string("send header failed fd=") + std::to_string(fd) + " err=" + std::to_string(errno));
    return;
  }
  if (m.header.length && !m.payload.empty()) {
    ssize_t n2 = send(fd, m.payload.data(), m.header.length, MSG_NOSIGNAL);
    if (n2 < 0) {
      server_log("ERROR", std::string("send payload failed fd=") + std::to_string(fd) + " err=" + std::to_string(errno));
      return;
    }
  }
  server_log("DEBUG", std::string("sent message type=") + std::to_string(m.header.type) + " len=" + std::to_string(m.header.length) + " to fd=" + std::to_string(fd));
}

void Server::broadcast_message(const Message& message) {
  for (auto& client : clients) {
    if (client.fd == -1)
      continue;
    if (message.header.type == static_cast<uint16_t>(MessageType::CHAT) && client.user_id == message.header.sender)
      continue;

    server_log("DEBUG", std::string("broadcast: type=") + std::to_string(message.header.type) + " from=" + std::to_string(message.header.sender) + " -> fd=" + std::to_string(client.fd) +
                            " user=" + std::to_string(client.user_id));
    send_message(client.fd, message);
  }
}

bool Server::assemble_frame(Client& client, Message& output) {
  output = Message{};

  if (!client.hdr_ready) {
    int rc = recv_n_nb(client.fd, client.buffer, sizeof(Header));
    if (rc == 0)
      return false;
    if (rc == -1) {
      server_log("INFO", std::string("closing client fd=") + std::to_string(client.fd) + " (header read error)");
      close(client.fd);
      client.fd = -1;
      return false;
    }

    std::memcpy(&client.pending_header, client.buffer.data(), sizeof(Header));
    if (!validate_header(client.pending_header)) {
      server_log("WARN", std::string("invalid header from fd=") + std::to_string(client.fd) + " type=" + std::to_string(client.pending_header.type) +
                             " len=" + std::to_string(client.pending_header.length));
      close(client.fd);
      client.fd = -1;
      return false;
    }
    server_log("DEBUG",
               std::string("read header from fd=") + std::to_string(client.fd) + " type=" + std::to_string(client.pending_header.type) + " len=" + std::to_string(client.pending_header.length));
    client.buffer.erase(client.buffer.begin(), client.buffer.begin() + sizeof(Header));
    client.hdr_ready = true;
  }

  size_t payload_size = client.pending_header.length;

  int rc2 = recv_n_nb(client.fd, client.buffer, payload_size);
  if (rc2 == 0)
    return false;
  if (rc2 == -1) {
    server_log("INFO", std::string("closing client fd=") + std::to_string(client.fd) + " (payload read error)");
    close(client.fd);
    client.fd = -1;
    return false;
  }

  if (client.buffer.size() >= payload_size) {
    output.header = client.pending_header;
    output.payload = {client.buffer.begin(), client.buffer.begin() + payload_size};

    server_log("DEBUG", std::string("assembled message from fd=") + std::to_string(client.fd) + " type=" + std::to_string(output.header.type) + " len=" + std::to_string(output.header.length));
    output.valid = true;
    client.buffer.clear();
    client.hdr_ready = false;
    return true;
  }

  return false;
}

void Server::handle_client(Client& client) {
  pollfd p{client.fd, POLLIN, 0};
  if (poll(&p, 1, 0) <= 0)
    return;

  if (client.state == ChatState::HANDSHAKE) {
    server_log("DEBUG", std::string("handshake poll fd=") + std::to_string(client.fd));
    handshake_step(client);
    return;
  }

  Message message;
  if (assemble_frame(client, message)) {
    message.header.sender = client.user_id;
    std::string chat_text(reinterpret_cast<char*>(message.payload.data()), message.payload.size());
    server_log("INFO", std::string("recv from uid=") + std::to_string(client.user_id) + " fd=" + std::to_string(client.fd) + " len=" + std::to_string(message.payload.size()) + " text='" +
                           chat_text + "'");
    broadcast_message(message);
  }
}

void Server::accept_new_connections() {
  pollfd listener{server_socket, POLLIN, 0};
  if (poll(&listener, 1, 0) > 0) {
    int cli = accept(server_socket, nullptr, nullptr);
    if (cli >= 0) {
      fcntl(cli, F_SETFL, O_NONBLOCK);
      clients.emplace_back(Client{cli});
      server_log("INFO", std::string("Client connected fd=") + std::to_string(cli));
    }
  }
}

void Server::send_user_pubkey(int fd, int user_id) {
  Message key_message;
  key_message.payload = database->fetch_public_key(user_id);
  key_message.header.length = key_message.payload.size();
  key_message.header.type = static_cast<uint16_t>(MessageType::KEY);
  key_message.header.sender = 0;
  key_message.header.timestamp = static_cast<uint32_t>(time(nullptr));
  server_log("DEBUG", std::string("sending KEY frame len=") + std::to_string(key_message.header.length) + " to fd=" + std::to_string(fd));
  send_message(fd, key_message);
}

void Server::finish_auth(Client& client, const std::string& username, const char* action) {
  send_line(client.fd, "OK " + std::to_string(client.user_id) + "\n");
  send_user_pubkey(client.fd, client.user_id);

  std::vector<uint8_t> ep_pub, ep_priv;
  generate_ephemeral_keypair(ep_pub, ep_priv);

  Message ep_frame;
  ep_frame.header = {static_cast<uint32_t>(ep_pub.size()), static_cast<uint16_t>(MessageType::EPHEMERAL), 0, static_cast<uint32_t>(time(nullptr))};
  ep_frame.payload = std::move(ep_pub);
  send_message(client.fd, ep_frame);
  client.ephemeral_priv = std::move(ep_priv);

  fcntl(client.fd, F_SETFL, O_NONBLOCK);
  client.state = ChatState::CHATTING;

  server_log("INFO", std::string("User ") + action + ": " + username + " id=" + std::to_string(client.user_id));
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
    finish_auth(client, username, "registered");
  } else if (starts_with(line, "LOGIN ")) {
    std::string username = line.substr(6, line.find('\n', 6) - 6);
    std::string password = read_line(client.fd, client.buffer);

    if (password.empty())
      return;

    client.user_id = database->check_user(username, password);

    if (client.user_id) {
      finish_auth(client, username, "logged in");
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
  while (running) {
    accept_new_connections();
    for (auto& client : clients) {
      if (client.fd == -1)
        continue;
      handle_client(client);
    }
    // Remove closed client entries to keep `clients` compact
    clients.erase(std::remove_if(clients.begin(), clients.end(), [](const Client& c) { return c.fd == -1; }), clients.end());
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
}

void Server::stop() {}

Server::~Server() {
  close(server_socket);
  for (auto& c : clients) {
    if (c.fd != -1)
      close(c.fd);
  }
  delete database;
}
