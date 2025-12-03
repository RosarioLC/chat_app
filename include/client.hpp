// Simple interactive TCP client for chat server
//
// Responsibilities:
// - Connect to the chat server over TCP
// - Handle interactive authentication (/register or /login)
// - Switch to non-blocking I/O and process incoming/outgoing frames
// - Display received messages tagged with the sender id
#pragma once
#include "crypto.hpp"
#include <map>
#include <unistd.h>
#include <vector>

class Client {
  int client_socket;
  std::vector<uint8_t> my_private_key;                  // My long-term private key
  std::vector<uint8_t> my_public_key;                   // My long-term public key
  std::map<int, std::vector<uint8_t>> peer_public_keys; // user_id -> public_key

  int authenticate();

public:
  // Connect to server and prepare client socket.
  Client();
  // Interactive event loop (authenticate, send/receive).
  // Blocks on user input and socket polling until terminated.
  void run();
  ~Client() {
    close(client_socket);
  }
};
