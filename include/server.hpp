#pragma once
#ifndef SERVER_HPP
#define SERVER_HPP

#include "protocol.hpp"
#include <iostream>
#include <vector>

struct Client {
  int fd;
  std::string buffer;
};

class Server {
private:
  int server_socket;
  std::vector<Client> clients;

  void broadcast_message(Header header, std::vector<uint8_t> payload);

  std::string receive_message();

public:
  Server();
  void run();
};

#endif // SERVER_HPP
