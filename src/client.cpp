#include "client.hpp"
#include "../include/crypto.hpp"
#include "../include/logger.hpp"
#include "../include/net.hpp"
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

// Helper: encrypt and send chat to the first known peer (current behavior)
static bool send_chat_to_first_peer(int client_socket, int user_id, const std::map<int, std::vector<uint8_t>>& peer_public_keys, const std::vector<uint8_t>& my_private_key,
                                    const std::string& line) {
  if (peer_public_keys.empty()) {
    std::cout << "No peers connected yet\n";
    return true; // not an error
  }
  auto first_peer = peer_public_keys.begin();
  std::vector<uint8_t> shared = ecdh_shared_secret(my_private_key, first_peer->second);
  CryptoKeys keys = derive_aes_keys(shared);

  std::vector<uint8_t> encrypted = aes_gcm_encrypt(line, keys.aes);
  Message m = build_message(static_cast<uint16_t>(MessageType::CHAT), user_id, encrypted.data(), encrypted.size());
  if (!net::send_message(client_socket, m)) {
    std::cout << "Failed to send message" << std::endl;
    return false;
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

      net::send_line(client_socket, "REG " + username + "\n");
      net::send_line(client_socket, password + "\n");

      // Send public key as hex
      std::string pubkey_hex;
      for (uint8_t byte : my_public_key) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", byte);
        pubkey_hex += buf;
      }
      net::send_line(client_socket, pubkey_hex + "\n");
    } else if (starts_with(command, "/login ")) {
      username = command.substr(7);

      std::cout << "password: ";
      std::getline(std::cin, password);

      net::send_line(client_socket, "LOGIN " + username + "\n");
      net::send_line(client_socket, password + "\n");

      // Send current session's public key
      std::string pubkey_hex;
      for (uint8_t byte : my_public_key) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", byte);
        pubkey_hex += buf;
      }
      net::send_line(client_socket, pubkey_hex + "\n");
    } else {
      std::cout << "Unknown command\n";
      continue;
    }

    std::string reply = net::read_line(client_socket);
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

        bool ok = net::recv_all_nb(client_socket, receiver.buffer, sizeof(Header));
        if (!ok) {
          std::cout << "Failed to read header from socket" << std::endl;
          return;
        }

        std::memcpy(&receiver.header, receiver.buffer.data(), sizeof(Header));

        receiver.buffer.clear();
        receiver.buffer.reserve(receiver.header.length);
        receiver.has_header = true;
      }

      // Step 2: Payload
      bool ok2 = net::recv_all_nb(client_socket, receiver.buffer, receiver.header.length);
      if (!ok2) {
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

          std::string plain = aes_gcm_decrypt(receiver.buffer, keys.aes);
          std::cout << "[" << sender_id << "] " << plain;
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
      if (!send_chat_to_first_peer(client_socket, user_id, peer_public_keys, my_private_key, line)) {
        return;
      }
    }
  }
}
