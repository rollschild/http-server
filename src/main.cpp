#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <zlib.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <condition_variable>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <ios>
#include <iostream>
#include <mutex>
#include <queue>
#include <sstream>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>

// global shutdown flag
std::atomic<bool> g_shutdown_requested{false};

const std::string TMP_DIR = "/tmp";
std::string g_files_dir{};

constexpr int KEEP_ALIVE_TIMEOUT_MS = 60000;      // 60 seconds
constexpr size_t MAX_REQUEST_SIZE = 1024 * 1024;  // 1MB limit

// Signal handler
// signal handlers are called by OS kernel, which uses C calling conventions
// `extern "C"` avoids C++ name mangling so kernel can find the function
extern "C" void signal_handler(int) {
    g_shutdown_requested.store(true, std::memory_order_relaxed);
}

void setup_signal_handlers() {
    // sigaction is POSIX
    struct sigaction sa{};
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);   // Ctrl+C
    sigaction(SIGTERM, &sa, nullptr);  // kill or system shutdown
}

void handle_client(int client_fd);

/**
 * Each thread blocks on recv()/send()/poll()
 */
class ThreadPool {
   private:
    std::atomic<bool> shutdown_requested;
    std::vector<std::jthread> workers;
    std::queue<int> task_queue;
    std::mutex queue_mutex;
    std::condition_variable_any queue_cv;

    void worker_loop(std::stop_token stop_token) {
        while (!stop_token.stop_requested()) {
            int client_fd = -1;

            {
                std::unique_lock<std::mutex> lock(queue_mutex);
                bool has_work = queue_cv.wait(
                    lock, stop_token, [this] { return !task_queue.empty(); });
                if (!has_work) break;
                client_fd = task_queue.front();
                task_queue.pop();
            }

            if (client_fd >= 0) {
                handle_client(client_fd);
                close(client_fd);
            }
        }
    }

   public:
    explicit ThreadPool(
        std::size_t num_threads = std::thread::hardware_concurrency())
        : shutdown_requested(false) {
        if (num_threads == 0) num_threads = 1;
        workers.reserve(num_threads);
        for (std::size_t i = 0; i < num_threads; ++i) {
            workers.emplace_back(
                [this](std::stop_token st) { worker_loop(st); });
        }
    }

    ~ThreadPool() { shutdown(); }

    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

    void shutdown() {
        bool expected = false;
        if (!shutdown_requested.compare_exchange_strong(expected, true)) return;

        for (auto& worker : workers) {
            // request stop on _ALL_ threads
            // this should happen _BEFORE_ the `notify_all()` below
            // **State first, signal second**
            worker.request_stop();
        }
        queue_cv.notify_all();
        workers.clear();

        // close unhandled client connections
        std::lock_guard<std::mutex> lock(queue_mutex);
        while (!task_queue.empty()) {
            close(task_queue.front());
            task_queue.pop();
        }
    }

    void submit(int client_fd) {
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            if (shutdown_requested.load()) {
                close(client_fd);
                return;
            }
            task_queue.push(client_fd);
        }
        queue_cv.notify_one();
    }
};

std::string gzip_compress(const std::string& data) {
    z_stream zs{};
    // initializes with 15 + 16 window bits
    // +16 tells zlib to produce gzip format (not raw deflate)
    if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8,
                     Z_DEFAULT_STRATEGY) != Z_OK) {
        return "";
    }

    zs.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(data.data()));
    zs.avail_in = data.size();

    std::string compressed;
    // compress in 4096 chunks until completion
    char buffer[4096];

    do {
        // points next_out to start of the buffer
        zs.next_out = reinterpret_cast<Bytef*>(buffer);
        // how many bytes are available in the output buffer
        zs.avail_out = sizeof(buffer);
        // compress; Z_FINISH signals this is the final (only) call
        // zlib should flush everything
        deflate(&zs, Z_FINISH);
        // `sizeof(buffer) - zs.avail_out` calculates how many bytes were
        // actually written 4096 minus remaining space
        compressed.append(buffer, sizeof(buffer) - zs.avail_out);

    } while (zs.avail_out == 0);

    deflateEnd(&zs);
    return compressed;
}

/**
 * Send al data, handling partial writes
 */
bool send_all(int fd, const std::string& data) {
    size_t total_sent = 0;
    while (total_sent < data.size()) {
        ssize_t sent =
            send(fd, data.data() + total_sent, data.size() - total_sent, 0);
        if (sent < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (sent == 0) return false;
        total_sent += sent;
    }
    return true;
}

bool process_single_request(int client_fd, const std::string& request) {
    size_t method_end = request.find(' ');
    std::string method = request.substr(0, method_end);
    size_t path_end = request.find(' ', method_end + 1);
    std::string path =
        request.substr(method_end + 1, path_end - 1 - method_end);

    // parse HTTP version
    size_t version_end = request.find("\r\n");
    std::string http_version =
        request.substr(path_end + 1, version_end - 1 - path_end);
    bool is_http_11 = (http_version.compare("HTTP/1.1") == 0);

    bool keep_alive = is_http_11;  // HTTP/1.1 defaults to keep-alive

    // parse Connection header
    size_t conn_pos = request.find("Connection: ");
    if (conn_pos != std::string::npos) {
        size_t conn_start = conn_pos + 12;
        size_t conn_end = request.find("\r\n", conn_start);
        std::string conn_value =
            request.substr(conn_start, conn_end - conn_start);
        std::transform(conn_value.begin(), conn_value.end(), conn_value.begin(),
                       ::tolower);
        if (conn_value.find("close") != std::string::npos) {
            keep_alive = false;
        } else if (conn_value.find("keep-alive") != std::string::npos) {
            keep_alive = true;
        }
    }

    std::string conn_header =
        keep_alive ? "Connection: keep-alive\r\n" : "Connection: close\r\n";

    std::string response;
    std::string user_agent;
    size_t ua_pos = request.find("User-Agent: ");
    if (ua_pos != std::string::npos) {
        // found User-Agent
        auto ua_start = ua_pos + 12;  // 12 is length of "User-Agent: "
        auto ua_end = request.find("\r\n", ua_start);
        user_agent = request.substr(ua_start, ua_end - ua_start);
    }

    std::vector<std::string> encodings;
    size_t ae_pos = request.find("Accept-Encoding: ");
    if (ae_pos != std::string::npos) {
        size_t ae_start = ae_pos + 17;
        size_t ae_end = request.find("\r\n", ae_start);
        std::string ae_value = request.substr(ae_start, ae_end - ae_start);

        // split by comma
        std::istringstream ss(ae_value);
        std::string encoding{};
        while (std::getline(ss, encoding, ',')) {
            // trim whitespaces
            size_t start = encoding.find_first_not_of(' ');
            if (start == std::string::npos) continue;
            encodings.push_back(encoding.substr(start));
        }
    }

    // Parse Content-Length for POST requests
    size_t content_len = 0;
    size_t cl_pos = request.find("Content-Length: ");
    if (cl_pos != std::string::npos) {
        auto cl_start = cl_pos + 16;
        auto cl_end = request.find("\r\n", cl_start);
        content_len = std::stoul(request.substr(cl_start, cl_end - cl_start));
    }

    // Extract request body
    std::string body{};
    size_t body_pre_start = request.find("\r\n\r\n");
    if (body_pre_start != std::string::npos) {
        body = request.substr(body_pre_start + 4, content_len);
    }

    if (path == "/") {
        response = "HTTP/1.1 200 OK\r\n" + conn_header + "\r\n";
    } else if (path.starts_with("/echo/")) {
        // extract string after `/echo/`
        std::string str_to_echo = path.substr(6);
        // check encoding
        bool supports_gzip = std::find(encodings.begin(), encodings.end(),
                                       "gzip") != encodings.end();
        if (supports_gzip) {
            // compress the body
            std::string compressed = gzip_compress(str_to_echo);
            response = "HTTP/1.1 200 OK\r\n" + conn_header +
                       "Content-Encoding: gzip\r\nContent-Type: "
                       "text/plain\r\nContent-Length: " +
                       std::to_string(compressed.size()) + "\r\n\r\n" +
                       compressed;
        } else {
            response = "HTTP/1.1 200 OK\r\n" + conn_header +
                       "Content-Type: "
                       "text/plain\r\nContent-Length: " +
                       std::to_string(str_to_echo.size()) + "\r\n\r\n" +
                       str_to_echo;
        }
    } else if (path.starts_with("/user-agent")) {
        response = "HTTP/1.1 200 OK\r\n" + conn_header +
                   "Content-Type: text/plain\r\nContent-Length: " +
                   std::to_string(user_agent.size()) + "\r\n\r\n" + user_agent;
    } else if (path.starts_with("/files/")) {
        // return file, located at hardcoded path for now, `/tmp/`
        std::string filename = path.substr(7);
        // security: reject path traversal attempts
        if (filename.find("..") != std::string::npos) {
            response = "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n";
        } else if (g_files_dir.empty()) {
            response = "HTTP/1.1 404 Not Found\r\n" + conn_header + "\r\n";
        } else {
            std::string filepath = g_files_dir + filename;
            if (method.compare("GET") == 0) {
                // GET
                std::ifstream file(filepath, std::ios::binary);

                if (!file) {
                    response =
                        "HTTP/1.1 404 Not Found\r\n" + conn_header + "\r\n";
                } else {
                    // read entire file into string
                    std::ostringstream ss;
                    ss << file.rdbuf();  // associated stream buffer
                    std::string content = ss.str();
                    response = "HTTP/1.1 200 OK\r\n" + conn_header +
                               "Content-Type: "
                               "application/octet-stream\r\nContent-Length: " +
                               std::to_string(content.size()) + "\r\n\r\n" +
                               content;
                }
            } else if (method.compare("POST") == 0) {
                // POST
                std::ofstream file(filepath, std::ios::binary);
                if (!file) {
                    response =
                        "HTTP/1.1 500 Server Error\r\nConnection: "
                        "close\r\n\r\n";
                } else {
                    file.write(body.data(), body.size());
                    response =
                        "HTTP/1.1 201 Created\r\n" + conn_header + "\r\n";
                }
            }
        }
    } else {
        response = "HTTP/1.1 404 Not Found\r\n" + conn_header + "\r\n";
    }

    send_all(client_fd, response);

    return keep_alive;
}

// HTTP request handler
void handle_client(int client_fd) {
    // Read http request from client
    std::string buffer;
    buffer.reserve(4096);
    bool keep_alive = true;

    while (keep_alive && !g_shutdown_requested.load()) {
        // wait for data with 60-second timeout
        struct pollfd pfd;
        pfd.fd = client_fd;
        pfd.events = POLLIN;

        int poll_result = poll(&pfd, 1, KEEP_ALIVE_TIMEOUT_MS);
        if (poll_result == 0) {
            // timeout - close connection
            break;
        } else if (poll_result < 0) {
            if (errno == EINTR) continue;  // interrupted by signal; retry
            break;                         // other error
        } else if (pfd.events & (POLLERR | POLLHUP | POLLNVAL)) {
            // socket error or client closed
            break;
        }

        // read available data
        char temp[1024];
        auto bytes_read = recv(client_fd, temp, sizeof(temp) - 1, 0);
        if (bytes_read <= 0) {
            break;
        }

        buffer.append(temp, bytes_read);

        if (buffer.size() > MAX_REQUEST_SIZE) {
            std::string error =
                "HTTP/1.1 413 Payload Too Large\r\nConnection: close\r\n\r\n";
            send_all(client_fd, error);
            break;
        }

        // process complete requests from buffer
        while (!buffer.empty()) {
            size_t header_end = buffer.find("\r\n\r\n");
            if (header_end == std::string::npos)
                break;  // need more data for headers

            // Parse Content-Length for POST requests
            size_t content_len = 0;
            size_t cl_pos = buffer.find("Content-Length: ");
            if (cl_pos != std::string::npos && cl_pos < header_end) {
                auto cl_start = cl_pos + 16;
                auto cl_end = buffer.find("\r\n", cl_start);
                content_len =
                    std::stoul(buffer.substr(cl_start, cl_end - cl_start));
            }

            size_t total_size = header_end + 4 + content_len;

            if (buffer.size() < total_size) {
                break;  // need more data for body
            }

            // extract complete request
            std::string request = buffer.substr(0, total_size);
            buffer.erase(0, total_size);

            // process request
            keep_alive = process_single_request(client_fd, request);
            if (!keep_alive) {
                break;
            }
        }
    }
}

int main(int argc, char** argv) {
    // Flush the buffer after every output operation: std::cout / std::cerr
    // output appears immediately rather than being buffered
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    if (argc > 2 && (std::string(argv[1]).compare("--directory") == 0)) {
        g_files_dir = argv[2];
        std::cout << "files dir: " << g_files_dir << std::endl;
    }

    std::size_t num_threads = std::thread::hardware_concurrency();

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

    struct sockaddr_in server_addr{};
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
    int connection_backlog = 128;
    // mark socket as passive - accepting connections
    if (listen(server_fd, connection_backlog) != 0) {
        std::cerr << "listen failed\n";
        return 1;
    }

    setup_signal_handlers();
    ThreadPool pool(num_threads);
    std::cout << "Server listening on 4221 with " << num_threads
              << " worker threads\n";

    while (!g_shutdown_requested.load()) {
        struct sockaddr_in client_addr{};
        socklen_t client_addr_len = sizeof(client_addr);
        // _BLOCKS_ main loop until a client connects
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr,
                               (socklen_t*)&client_addr_len);
        if (client_fd < 0) {
            // errno: EINTR
            std::cerr << "Failed to accept a connection: " << strerror(errno)
                      << std::endl;
            continue;
        }

        pool.submit(client_fd);
    }

    close(server_fd);

    return 0;
}
