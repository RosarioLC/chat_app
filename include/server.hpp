#pragma once
#include "database.hpp"
#include "protocol.hpp"
#include <string>
#include <vector>
enum class ChatState { HANDSHAKE, CHATTING };

struct Client {
  int fd;
  int user_id = 0;
  ChatState state = ChatState::HANDSHAKE;
  std::string buffer = "";
  Header pending_header = {};
  bool hdr_ready = false;
};
class Server {
  int server_socket;
  Database* database;
  std::vector<Client> clients;
  void broadcast_message(const Message& m);
  bool assemble_frame(Client& c, Message& out); // non-blocking re-assembly
  void handshake_step(Client& c);               //
  // text-mode REG/LOGIN
public:
  Server();
  void run();
};
