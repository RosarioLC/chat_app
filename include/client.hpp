#pragma once
#include <unistd.h>

class Client {
  int client_socket;

public:
  Client();
  void run();
  ~Client() {
    close(client_socket);
  }
};
