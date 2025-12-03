#pragma once
// Server module: accepts connections, handles authentication handshake,
// distributes public keys, and blind-relays chat frames.
// TCP chat server handling clients and messages
//
// Responsibilities:
// - Accept incoming TCP connections and track per-client state
// - Run a simple handshake for registration/login
// - Broadcast messages to all connected clients
// - Persist user records via `Database`
//
// Concurrency:
// - Uses non-blocking sockets + polling within a single-threaded loop
// - Minimal sleeps to reduce CPU spin; suitable for small demos/tests
#pragma once
#include "crypto.hpp"
#include "database.hpp"
#include "protocol.hpp"
#include <string>
#include <vector>
// Client connection state.
// HANDSHAKE: Pre-authentication (register/login exchange)
// CHATTING: Authenticated; user_id populated; normal messaging
enum class ChatState { HANDSHAKE, CHATTING };

// Per-connection state tracked by the server.
// `buffer` accumulates bytes; `pending_header` stores a parsed header
// when only part of a frame has been received.
struct Client {
  int fd;
  int user_id = 0;
  ChatState state = ChatState::HANDSHAKE;
  std::vector<uint8_t> buffer = {};
  Header pending_header = {};
  bool hdr_ready = false;
};
class Server {
  int server_socket;
  Database* database;
  std::vector<Client> clients;
  bool running = true;
  uint16_t listen_port;
  // Send a message to all connected clients.
  void broadcast_message(const Message& m);
  // Assemble a complete frame from non-blocking socket.
  // Returns true when a full `Message` is ready in `out`.
  bool assemble_frame(Client& c, Message& out);
  // Registration/login handshake.
  // Drives the flow to move a client from HANDSHAKE to CHATTING.
  void handshake_step(Client& c);
  // Handle I/O and state for a single connected client.
  void handle_client(Client& c);
  // Accept any pending inbound connections.
  void accept_new_connections();
  // Send user's public key to a socket as a KEY frame.
  void send_user_pubkey(int fd, int user_id);
  // Common success path for registration/login.
  void finish_auth(Client& c, const std::string& username, const char* action);

public:
  // Bind/listen on `port` and initialize database.
  Server(uint16_t port = 6969);
  // Main event loop.
  void run();
  // Request server shutdown.
  void stop();
  ~Server();
};
