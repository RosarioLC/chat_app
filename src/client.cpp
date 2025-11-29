#include "client.hpp"
#include "../include/protocol.hpp"
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>

Client::Client() {
  client_socket = socket(AF_INET, SOCK_STREAM, 0);
  check(client_socket, "socket");

  sockaddr_in server_address{};
  server_address.sin_family = AF_INET;
  server_address.sin_port = htons(6969);
  server_address.sin_addr.s_addr = INADDR_ANY;

  check(connect(client_socket, (struct sockaddr*)&server_address, sizeof(server_address)),
        "connect");

  std::cout << "Connected to server.\n";
}

void Client::run() {
  pollfd fds[2];

  // socket → check for messages from server
  fds[0].fd = client_socket;
  fds[0].events = POLLIN;

  // stdin → check for user input
  fds[1].fd = STDIN_FILENO;
  fds[1].events = POLLIN;

  char buffer[16 * 1024];

  while (true) {
    int ret = poll(fds, 2, -1);
    check(ret, "poll");

    // Server sent something
    if (fds[0].revents & POLLIN) {
      Header header;
      if (!read_exact(client_socket, &header, sizeof(Header))) {
        break;
      }

      if (header.length > sizeof(buffer)) {
        std::cerr << "Message too large" << std::endl;
        break;
      }

      if (!read_exact(client_socket, buffer, header.length)) {
        break;
      }

      buffer[header.length] = '\0';

      std::cout << "[Server] type=" << header.type << " from=" << header.sender
                << " time=" << header.timestamp << " | msg: " << buffer;
    }

    // User typed something
    if (fds[1].revents & POLLIN) {
      if (!fgets(buffer, sizeof(buffer), stdin)) {
        break;
      }
      std::string line = buffer;
      auto frame = build_frame(1, client_socket, line.data(), line.size());
      check(send(client_socket, frame.data(), frame.size(), 0), "send");
    }
  }

  close(client_socket);
}
