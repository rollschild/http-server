#include <arpa/inet.h>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <netdb.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int main(/*int argc, char **argv*/) {
  // Flush the buffer after every output operation: std::cout / std::cerr
  // output appears immediately rather than being buffered
  std::cout << std::unitbuf;
  std::cerr << std::unitbuf;

  // socket creation
  // AF_INET: ipv4 address family
  // SOCK_STREAM: TCP
  int server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd < 0) {
    std::cerr << "Failed to create server socket\n";
    return 1;
  }

  // SO_REUSEADDR allows socket to bind to an address that's in TIME_WAIT state
  // if not using this, restarting server quickly would fail with 'Address
  // already in use' because OS holds the port briefly after close
  int reuse = 1;
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) <
      0) {
    std::cerr << "setsockopt failed\n";
    return 1;
  }

  struct sockaddr_in server_addr;
  server_addr.sin_family = AF_INET; // ipv4
  server_addr.sin_addr.s_addr =
      INADDR_ANY; // bind to all network interfaces (0.0.0.0)
  server_addr.sin_port =
      htons(4221); // converted to network byte order (big-endian)

  if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) !=
      0) {
    std::cerr << "Failed to bind to port 4221\n";
    return 1;
  }

  // max number of pending connections in queue before new ones are refused
  int connection_backlog = 5;
  // mark socket as passive - accepting connections
  if (listen(server_fd, connection_backlog) != 0) {
    std::cerr << "listen failed\n";
    return 1;
  }

  struct sockaddr_in client_addr;
  int client_addr_len = sizeof(client_addr);

  std::cout << "Waiting for a client to connect...\n";

  // _BLOCKS_ until a client connects
  accept(server_fd, (struct sockaddr *)&client_addr,
         (socklen_t *)&client_addr_len);
  std::cout << "Client connected\n";

  close(server_fd);

  return 0;
}
