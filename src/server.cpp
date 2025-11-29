#include "server.hpp"
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>

void Server::broadcast_message(Header header, std::vector<uint8_t> payload) {
  for (auto& client : clients) {
    send(client.fd, &header, sizeof(header), MSG_NOSIGNAL);
    send(client.fd, payload.data(), header.length, MSG_NOSIGNAL);
  }
}

std::string Server::receive_message() {
  if (clients.empty()) {
    return "";
  }

  std::vector<pollfd> fds(clients.size());
  for (size_t i = 0; i < clients.size(); i++) {
    fds[i].fd = clients[i].fd;
    fds[i].events = POLLIN;
    fds[i].revents = 0;
  }

  int ret = poll(fds.data(), fds.size(), 10);
  if (ret <= 0) {
    return "";
  }

  for (size_t i = 0; i < fds.size(); i++) {
    if (!fds[i].revents & POLLIN) {
      continue;
    }

    char temp[16 * 1024];

    Header header;
    if (!read_exact(clients[i].fd, &header, sizeof(Header))) {
      break;
    }

    if (header.length > sizeof(temp)) {
      std::cerr << "Message too large" << std::endl;
      break;
    }

    if (!read_exact(clients[i].fd, temp, header.length)) {
      break;
    }
  }
  return "";
}

Server::Server() {
  server_socket = socket(AF_INET, SOCK_STREAM, 0);
  check(server_socket, "socket");

  sockaddr_in server_address;
  server_address.sin_family = AF_INET;
  server_address.sin_port = htons(6969);
  server_address.sin_addr.s_addr = INADDR_ANY;

  int opt = 1;
  check(setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)), "setsockopt");

  check(bind(server_socket, (struct sockaddr*)&server_address, sizeof(server_address)), "bind");

  check(listen(server_socket, 1), "listen");
}

void Server::run() {
  while (1) {
    pollfd listen_fd{server_socket, POLLIN, 0};
    if (poll(&listen_fd, 1, 0) > 0) {
      int cli = accept(server_socket, nullptr, nullptr);
      if (cli >= 0) {
        fcntl(cli, F_SETFL, O_NONBLOCK);
        clients.emplace_back(Client{cli, {}});
        std::cout << "client connected\n";
      }
    }

    if (clients.empty()) {
      continue;
    }

    std::vector<pollfd> fds(clients.size());
    for (size_t i = 0; i < clients.size(); i++) {
      fds[i].fd = clients[i].fd;
      fds[i].events = POLLIN;
    }

    int ret = poll(fds.data(), fds.size(), 10);
    if (ret <= 0)
      continue;

    for (size_t i = 0; i < fds.size(); i++) {
      if (!(fds[i].revents & POLLIN))
        continue;

      Header header;
      if (!read_exact(clients[i].fd, &header, sizeof(header))) {
        close(clients[i].fd);
        clients.erase(clients.begin() + i);
      }

      if (header.length > 16 * 1024) {
        std::cerr << "Frame too big.\n";
        close(clients[i].fd);
        clients.erase(clients.begin() + i);
      }

      std::vector<uint8_t> payload(header.length);
      if (!read_exact(clients[i].fd, payload.data(), header.length)) {
        close(clients[i].fd);
        clients.erase(clients.begin() + i);
      }

      broadcast_message(header, payload);
    }
  }
}
