#include "server.hpp"
#include "logger.hpp"
#include "net.hpp"
#include "util.hpp"
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

void Server::broadcast_message(const Message& message) {
  for (auto& client : clients) {
    if (client.fd == -1)
      continue;
    if (message.header.type == static_cast<uint16_t>(MessageType::CHAT) && client.user_id == message.header.sender)
      continue;
    // Blind relay: server does not decrypt CHAT frames; it forwards as-is.
    Logger::log(Logger::DEBUG,
                Logger::with_conn(client.fd, client.user_id, std::string("broadcast type=") + std::to_string(message.header.type) + " from=" + std::to_string(message.header.sender)));
    net::send_message(client.fd, message);
  }
}

bool Server::assemble_frame(Client& client, Message& output) {
  output = Message{};

  if (!client.hdr_ready) {
    bool ok = net::recv_all_nb(client.fd, client.buffer, sizeof(Header));
    if (!ok) {
      Logger::log(Logger::INFO, Logger::with_conn(client.fd, client.user_id, "closing client (header read error)"));
      close(client.fd);
      client.fd = -1;
      return false;
    }

    std::memcpy(&client.pending_header, client.buffer.data(), sizeof(Header));
    if (!validate_header(client.pending_header)) {
      Logger::log(Logger::WARN, Logger::with_conn(client.fd, client.user_id,
                                                  std::string("invalid header type=") + std::to_string(client.pending_header.type) + " len=" + std::to_string(client.pending_header.length)));
      close(client.fd);
      client.fd = -1;
      return false;
    }
    // Enforce maximum payload size
    if (client.pending_header.length > MAX_PAYLOAD_SIZE) {
      Logger::log(Logger::WARN, Logger::with_conn(client.fd, client.user_id, std::string("payload too large len=") + std::to_string(client.pending_header.length)));
      close(client.fd);
      client.fd = -1;
      return false;
    }
    Logger::log(Logger::DEBUG, Logger::with_conn(client.fd, client.user_id,
                                                 std::string("read header type=") + std::to_string(client.pending_header.type) + " len=" + std::to_string(client.pending_header.length)));
    client.buffer.erase(client.buffer.begin(), client.buffer.begin() + sizeof(Header));
    client.hdr_ready = true;
  }

  size_t payload_size = client.pending_header.length;

  bool ok2 = net::recv_all_nb(client.fd, client.buffer, payload_size);
  if (!ok2) {
    Logger::log(Logger::INFO, Logger::with_conn(client.fd, client.user_id, "closing client (payload read error)"));
    close(client.fd);
    client.fd = -1;
    return false;
  }

  if (client.buffer.size() >= payload_size) {
    output.header = client.pending_header;
    output.payload = {client.buffer.begin(), client.buffer.begin() + payload_size};

    Logger::log(Logger::DEBUG,
                Logger::with_conn(client.fd, client.user_id, std::string("assembled message type=") + std::to_string(output.header.type) + " len=" + std::to_string(output.header.length)));
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
    Logger::log(Logger::DEBUG, Logger::with_conn(client.fd, client.user_id, "handshake poll"));
    handshake_step(client);
    return;
  }

  Message message;
  if (assemble_frame(client, message)) {
    message.header.sender = client.user_id;

    if (message.header.type == static_cast<uint16_t>(MessageType::CHAT)) {
      // Blind relay - server never decrypts
      Logger::log(Logger::DEBUG, Logger::with_conn(client.fd, client.user_id, "relaying encrypted message"));
      broadcast_message(message);
    }
  }
}

void Server::accept_new_connections() {
  pollfd listener{server_socket, POLLIN, 0};
  if (poll(&listener, 1, 0) > 0) {
    int cli = accept(server_socket, nullptr, nullptr);
    if (cli >= 0) {
      fcntl(cli, F_SETFL, O_NONBLOCK);
      clients.emplace_back(Client{cli});
      Logger::log(Logger::INFO, Logger::with_conn(cli, 0, "Client connected"));
    }
  }
}

void Server::send_user_pubkey(int fd, int user_id) {
  Message key_message;
  key_message.payload = database->fetch_public_key(user_id);
  key_message.header.length = key_message.payload.size();
  key_message.header.type = static_cast<uint16_t>(MessageType::KEY);
  key_message.header.sender = user_id; // Set sender to identify whose key this is
  key_message.header.timestamp = static_cast<uint32_t>(time(nullptr));
  // Server distributes public keys only; clients derive shared secrets.
  Logger::log(Logger::DEBUG, Logger::with_conn(fd, user_id, std::string("sending KEY frame len=") + std::to_string(key_message.header.length)));
  net::send_message(fd, key_message);
}

void Server::finish_auth(Client& client, const std::string& username, const char* action) {
  net::send_line(client.fd, "OK " + std::to_string(client.user_id) + "\n");

  // Send all users' public keys to the newly authenticated client
  for (auto& other : clients) {
    if (other.fd == -1 || other.user_id == 0)
      continue;
    send_user_pubkey(client.fd, other.user_id);
  }

  // Broadcast this user's public key to all other authenticated clients
  for (auto& other : clients) {
    if (other.fd == -1 || other.user_id == 0 || other.user_id == client.user_id)
      continue;
    if (other.state == ChatState::CHATTING) {
      send_user_pubkey(other.fd, client.user_id);
    }
  }

  fcntl(client.fd, F_SETFL, O_NONBLOCK);
  client.state = ChatState::CHATTING;

  Logger::log(Logger::INFO, std::string("User ") + action + ": " + username + " id=" + std::to_string(client.user_id));
}

void Server::handshake_step(Client& client) {
  std::string line = net::read_line_acc(client.fd, client.buffer);

  if (line.empty()) {
    close(client.fd);
    client.fd = -1;
    return;
  }

  if (!ends_with(line, "\n"))
    return;

  if (starts_with(line, "REG ")) {
    std::string username = line.substr(4, line.find('\n', 4) - 4);
    std::string password = net::read_line_acc(client.fd, client.buffer);
    if (password.empty()) {
      return;
    }

    // Expect public key as next line (hex encoded for simplicity)
    std::string pubkey_hex = net::read_line_acc(client.fd, client.buffer);
    if (pubkey_hex.empty()) {
      return;
    }

    // Convert hex to bytes
    std::vector<uint8_t> pubkey;
    pubkey_hex.erase(std::remove(pubkey_hex.begin(), pubkey_hex.end(), '\n'), pubkey_hex.end());
    for (size_t i = 0; i < pubkey_hex.length(); i += 2) {
      std::string byte_str = pubkey_hex.substr(i, 2);
      pubkey.push_back(static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16)));
    }

    database->add_user(username, bcrypt_hash(password), pubkey);
    client.user_id = database->fetch_user_id(username);
    client.buffer.clear(); // Clear any leftover data
    finish_auth(client, username, "registered");
  } else if (starts_with(line, "LOGIN ")) {
    std::string username = line.substr(6, line.find('\n', 6) - 6);
    std::string password = net::read_line_acc(client.fd, client.buffer);

    if (password.empty())
      return;

    client.user_id = database->check_user(username, password);

    if (client.user_id) {
      // Receive updated public key for this session
      std::string pubkey_hex = net::read_line_acc(client.fd, client.buffer);
      if (!pubkey_hex.empty()) {
        // Convert hex to bytes
        std::vector<uint8_t> pubkey;
        pubkey_hex.erase(std::remove(pubkey_hex.begin(), pubkey_hex.end(), '\n'), pubkey_hex.end());
        for (size_t i = 0; i < pubkey_hex.length(); i += 2) {
          std::string byte_str = pubkey_hex.substr(i, 2);
          pubkey.push_back(static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16)));
        }
        // Update the public key in database
        database->update_public_key(client.user_id, pubkey);
        client.buffer.clear(); // Clear any leftover data
      }
      finish_auth(client, username, "logged in");
    } else {
      net::send_line(client.fd, "ERR auth_fail\n");
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
