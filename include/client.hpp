// Simple interactive TCP client for chat server
//
// Responsibilities:
// - Connect to the chat server over TCP
// - Handle interactive authentication (/register or /login)
// - Switch to non-blocking I/O and process incoming/outgoing frames
// - Display received messages tagged with the sender id
#pragma once
#include <unistd.h>

class Client {
  int client_socket;

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
