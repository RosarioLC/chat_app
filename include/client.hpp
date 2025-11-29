#pragma once
#ifndef CLIENT_HPP
#define CLIENT_HPP
#include <unistd.h>

class Client {
private:
  int client_socket;

public:
  Client();

  void run();

  ~Client() {
    close(client_socket);
  }
};
#endif // CLIENT_HPP
