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
#include <vector>

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

  // Generate long-term keypair for E2EE
  generate_ephemeral_keypair(my_public_key, my_private_key);

  std::cout << "Connected to server.\n";
}

/* ============================================================
 *                        Login Phase
 * ============================================================ */

int Client::authenticate() {
  std::cout << "Commands: /register <user>  or  /login <user>\n";
  std::string command;

  while (true) {
    std::cout << "> " << std::flush;
    if (!std::getline(std::cin, command))
      return 0;

    std::string username, password;

    if (starts_with(command, "/register ")) {
      username = command.substr(10);

      std::cout << "password: ";
      std::getline(std::cin, password);

      send_line(client_socket, "REG " + username + "\n");
      send_line(client_socket, password + "\n");

      // Send public key as hex
      std::string pubkey_hex;
      for (uint8_t byte : my_public_key) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", byte);
        pubkey_hex += buf;
      }
      send_line(client_socket, pubkey_hex + "\n");
    } else if (starts_with(command, "/login ")) {
      username = command.substr(7);

      std::cout << "password: ";
      std::getline(std::cin, password);

      send_line(client_socket, "LOGIN " + username + "\n");
      send_line(client_socket, password + "\n");

      // Send current session's public key
      std::string pubkey_hex;
      for (uint8_t byte : my_public_key) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", byte);
        pubkey_hex += buf;
      }
      send_line(client_socket, pubkey_hex + "\n");
    } else {
      std::cout << "Unknown command\n";
      continue;
    }

    std::string reply = read_line(client_socket);
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
} /* ============================================================
   *                        Main Loop
   * ============================================================ */

void Client::run() {
  int user_id = authenticate();
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
        int sender_id = receiver.header.sender;

        // Look up sender's public key
        auto it = peer_public_keys.find(sender_id);
        if (it == peer_public_keys.end()) {
          std::cerr << "No public key for sender " << sender_id << "\n";
        } else {
          // Decrypt using ECDH(my_private, sender_public)
          std::vector<uint8_t> shared = ecdh_shared_secret(my_private_key, it->second);
          CryptoKeys keys = derive_aes_keys(shared);

          std::string plain = aes_gcm_decrypt(receiver.buffer, keys.aes, keys.nonce);
          std::cout << "[" << sender_id << "] " << plain << '\n';
        }
      } else if (receiver.header.type == static_cast<uint16_t>(MessageType::KEY)) {
        // Received public key from server - store it
        // First 4 bytes could be user_id, or we use header.sender
        // For simplicity, use header.sender as the user_id
        int peer_id = receiver.header.sender;
        if (peer_id != 0 && peer_id != user_id) {
          peer_public_keys[peer_id] = receiver.buffer;
          std::cout << "[System] Received public key for user " << peer_id << "\n";
        }
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

      if (peer_public_keys.empty()) {
        std::cout << "No peers connected yet\n";
      } else {
        // For simplicity: encrypt with first peer's key (1-to-1 E2EE)
        // In a real group chat, you'd need to send separate encrypted copies
        auto first_peer = peer_public_keys.begin();
        std::vector<uint8_t> shared = ecdh_shared_secret(my_private_key, first_peer->second);
        CryptoKeys keys = derive_aes_keys(shared);

        std::vector<uint8_t> encrypted = aes_gcm_encrypt(line, keys.aes, keys.nonce);
        Message m = build_message(static_cast<uint16_t>(MessageType::CHAT), user_id, encrypted.data(), encrypted.size());

        if (!send_message(client_socket, m)) {
          std::cout << "Failed to send message" << std::endl;
          return;
        }
      }
    }
  }
}
