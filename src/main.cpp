#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>

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

    // SO_REUSEADDR allows socket to bind to an address that's in TIME_WAIT
    // state if not using this, restarting server quickly would fail with
    // 'Address already in use' because OS holds the port briefly after close
    int reuse = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) <
        0) {
        std::cerr << "setsockopt failed\n";
        return 1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;  // ipv4
    server_addr.sin_addr.s_addr =
        INADDR_ANY;  // bind to all network interfaces (0.0.0.0)
    server_addr.sin_port =
        htons(4221);  // converted to network byte order (big-endian)

    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) !=
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
    int client_fd = accept(server_fd, (struct sockaddr*)&client_addr,
                           (socklen_t*)&client_addr_len);
    if (client_fd < 0) {
        std::cerr << "Failed to accept a connection!\n";
        return 1;
    }
    std::cout << "Client connected\n";

    // Read http request from client
    char buffer[1024] = {0};
    auto bytes_read = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (bytes_read < 0) {
        std::cerr << "Failed to read request from client: " << client_fd
                  << std::endl;
        close(client_fd);
        close(server_fd);
        return 1;
    }

    // Parse
    std::string request(buffer);
    size_t method_end = request.find(' ');
    size_t path_end = request.find(' ', method_end + 1);
    std::string path =
        request.substr(method_end + 1, path_end - 1 - method_end);
    std::string response;
    std::string user_agent;
    size_t ua_pos = request.find("User-Agent: ");
    if (ua_pos != std::string::npos) {
        // found User-Agent
        auto ua_start = ua_pos + 12;  // 12 is length of "User-Agent: "
        auto ua_end = request.find("\r\n", ua_start);
        user_agent = request.substr(ua_start, ua_end - ua_start);
    }

    if (path == "/") {
        response = "HTTP/1.1 200 OK\r\n\r\n";
    } else if (path.starts_with("/echo/")) {
        // extract string after `/echo/`
        std::string str_to_echo = path.substr(6);
        response =
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " +
            std::to_string(str_to_echo.size()) + "\r\n\r\n" + str_to_echo;
    } else if (path.starts_with("/user-agent")) {
        response =
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " +
            std::to_string(user_agent.size()) + "\r\n\r\n" + user_agent;
    } else {
        response = "HTTP/1.1 404 Not Found\r\n\r\n";
    }

    /*
    switch (path) {
        case "/":
            break;
        default:
            response = "HTTP/1.1 404 Not Found\r\n\r\n";
    }
    */

    send(client_fd, response.data(), response.size(), 0);

    close(client_fd);

    close(server_fd);

    return 0;
}
