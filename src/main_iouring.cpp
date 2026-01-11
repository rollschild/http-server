#include <liburing.h>
#include <liburing/io_uring.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <zlib.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

/**
 * Global State
 */

// global shutdown flag
std::atomic<bool> g_shutdown_requested{false};

const std::string TMP_DIR = "/tmp";
std::string g_files_dir{};

constexpr int PORT = 4221;
constexpr int QUEUE_DEPTH =
    256;  // io_uring queue size - max number of in-flight I/O operations
constexpr int RECV_BUFFER_SIZE = 4096;            // per-recv buffer size
constexpr int KEEP_ALIVE_TIMEOUT_MS = 60000;      // 60 seconds
constexpr size_t MAX_REQUEST_SIZE = 1024 * 1024;  // 1MB limit
constexpr int KEEP_ALIVE_TIMEOUT_SEC = 60;

/**
 * Signal Handling
 */

// Signal handler
// signal handlers are called by OS kernel, which uses C calling conventions
// `extern "C"` avoids C++ name mangling so kernel can find the function
extern "C" void signal_handler(int) {
    g_shutdown_requested.store(true, std::memory_order_relaxed);
}

void setup_signal_handlers() {
    // sigaction is POSIX
    // more reliable than `signal()`
    struct sigaction sa{};
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);   // Ctrl+C
    sigaction(SIGTERM, &sa, nullptr);  // kill or system shutdown
}

/**
 * GZIP Compression
 */
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
 * IO Operation Types
 */

// `: uint8_t` - specifies underlying type of the enum
// by default `enum class` uses int as underlying type
// sizeof(IoOp) == 1
enum class IoOp : uint8_t { Accept, Recv, Send, Close };

/**
 * Connection State
 */

struct Connection {
    int fd;                   // client's socket fd
    std::string recv_buffer;  // _accumulates_ incoming data
    std::string send_buffer;  // data _waiting_ to be sent
    size_t bytes_sent = 0;    // tracks partial sends
    bool keep_alive = true;
    char temp_recv[RECV_BUFFER_SIZE];  // buffer for individual recv operations
                                       // io_uring needs a stable memory address
                                       // for async reads data is copied to
                                       // recv_buffer after completion

    // explicit: prevents implicit conversion from int to Connection
    explicit Connection(int fd_) : fd{fd_} {}
};

/**
 * User Data for io_uring
 */

// recv/send/close allocate new UserData that must be deleted
// to identify it after completion
struct UserData {
    IoOp op;
    Connection* conn;  // nullptr for accept, since no conneciton yet

    UserData(IoOp op_, Connection* conn_ = nullptr) : op(op_), conn(conn_) {}
};

/**
 * HTTP Request Processing
 */

/**
 * Returns: {response_string, keep_alive}
 */
std::pair<std::string, bool> process_http_request(const std::string& request) {
    // parse method, path, version
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

    return {response, keep_alive};
}

/**
 * IO_URING Server Class
 */

class IoUringServer {
   private:
    // the io_uring instance
    // contains submission & completion queues
    struct io_uring ring;

    int server_fd;
    std::unordered_map<int, std::unique_ptr<Connection>> connections;

    // pre-allocated UserData for accept (reused)
    UserData accept_data{IoOp::Accept, nullptr};

    /**
     * SQE Submission helpers
     */

    void submit_accept() {
        // get a FREE **Submission Queue Entry**
        struct io_uring_sqe* sqe = io_uring_get_sqe(&ring);
        if (!sqe) {
            std::cerr << "Failed to get SQE for accept" << std::endl;
            return;
        }

        // prepares async accept operation
        io_uring_prep_accept(sqe, server_fd, nullptr, nullptr, 0);
        // attaches UserData
        // when CQE arrives, we can identify this was an Accept
        io_uring_sqe_set_data(sqe, &accept_data);
    }

    void submit_recv(Connection* conn) {
        struct io_uring_sqe* sqe = io_uring_get_sqe(&ring);
        if (!sqe) {
            std::cerr << "Failed to get SQE for recv" << std::endl;
            submit_close(conn);
            return;
        }

        // prepares async receive
        io_uring_prep_recv(sqe, conn->fd, conn->temp_recv, RECV_BUFFER_SIZE, 0);
        io_uring_sqe_set_data(sqe, new UserData(IoOp::Recv, conn));
    }

    void submit_send(Connection* conn) {
        struct io_uring_sqe* sqe = io_uring_get_sqe(&ring);
        if (!sqe) {
            std::cerr << "Failed to get SQE for send" << std::endl;
            submit_close(conn);
            return;
        }

        // partial send handling
        // pointer arithmetic
        const char* data = conn->send_buffer.data() + conn->bytes_sent;
        size_t len = conn->send_buffer.size() - conn->bytes_sent;

        io_uring_prep_send(sqe, conn->fd, data, len, 0);
        io_uring_sqe_set_data(sqe, new UserData(IoOp::Send, conn));
    }

    void submit_close(Connection* conn) {
        struct io_uring_sqe* sqe = io_uring_get_sqe(&ring);
        if (!sqe) {
            // fallback: sync close
            close(conn->fd);
            connections.erase(conn->fd);
            return;
        }

        io_uring_prep_close(sqe, conn->fd);
        io_uring_sqe_set_data(sqe, new UserData(IoOp::Close, conn));
    }

    /**
     * CQE handlers
     */

    void handle_accept(struct io_uring_cqe* cqe) {
        int client_fd = cqe->res;

        // ALWAYS re-submit accept for next connection
        submit_accept();

        if (client_fd < 0) {
            if (client_fd != -EAGAIN && client_fd != -EINTR) {
                // EAGAIN and EINTR are _transient_, no need to log them
                std::cerr << "accept failed: " << strerror(-client_fd)
                          << std::endl;
            }
            return;
        }

        // create connection state
        auto conn = std::make_unique<Connection>(client_fd);
        Connection* conn_ptr = conn.get();
        connections[client_fd] = std::move(conn);

        // start receiving
        submit_recv(conn_ptr);
    }

    void handle_recv(struct io_uring_cqe* cqe, Connection* conn) {
        int bytes = cqe->res;
        if (bytes <= 0) {
            // connection closed or error
            submit_close(conn);
            return;
        }

        // append to buffer
        conn->recv_buffer.append(conn->temp_recv, bytes);

        // check size limit
        if (conn->recv_buffer.size() > MAX_REQUEST_SIZE) {
            conn->send_buffer =
                "HTTP/1.1 413 Payload Too Large\r\nConnection: close\r\n\r\n";
            conn->bytes_sent = 0;
            conn->keep_alive = false;
            submit_send(conn);
            return;
        }

        // try to parse complete request
        if (!try_process_request(conn)) {
            // need more data
            submit_recv(conn);
        }
    }

    bool try_process_request(Connection* conn) {
        // look for end of headers
        size_t header_end = conn->recv_buffer.find("\r\n\r\n");
        if (header_end == std::string::npos) {
            return false;  // need more data for headers
        }

        // Parse Content-Length for POST requests
        size_t content_len = 0;
        size_t cl_pos = conn->recv_buffer.find("Content-Length: ");
        if (cl_pos != std::string::npos && cl_pos < header_end) {
            auto cl_start = cl_pos + 16;
            auto cl_end = conn->recv_buffer.find("\r\n", cl_start);
            content_len = std::stoul(
                conn->recv_buffer.substr(cl_start, cl_end - cl_start));
        }

        size_t total_size = header_end + 4 + content_len;

        if (conn->recv_buffer.size() < total_size) {
            return false;  // need more data for body
        }

        // extract complete request
        std::string request = conn->recv_buffer.substr(0, total_size);
        conn->recv_buffer.erase(0, total_size);  // supports pipelining

        // process request
        auto [response, keep_alive] = process_http_request(request);
        conn->send_buffer = std::move(response);
        conn->bytes_sent = 0;
        conn->keep_alive = keep_alive;

        // start sending
        submit_send(conn);
        return true;
    }

    void handle_send(struct io_uring_cqe* cqe, Connection* conn) {
        int bytes = cqe->res;
        if (bytes < 0) {
            // send error
            submit_close(conn);
            return;
        }

        conn->bytes_sent += bytes;

        if (conn->bytes_sent < conn->send_buffer.size()) {
            // partial send, continue
            submit_send(conn);
            return;
        }

        // send complete
        conn->send_buffer.clear();
        conn->bytes_sent = 0;

        if (conn->keep_alive) {
            // check if there's more data in buffer
            // pipelining
            if (!conn->recv_buffer.empty() && try_process_request(conn)) {
                return;  // processing next request
            }
            // wait for more data
            // keep-alive
            submit_recv(conn);
        } else {
            submit_close(conn);
        }
    }

    void handle_close(struct io_uring_cqe* cqe, Connection* conn) {
        // result not needed
        // silences the "unused parameter" warning
        (void)cqe;
        connections.erase(conn->fd);
    }

   public:
    IoUringServer() : server_fd(-1) {}

    ~IoUringServer() {
        if (server_fd >= 0) {
            close(server_fd);
        }
        // frees io_uring resources
        io_uring_queue_exit(&ring);
    }

    bool init() {
        // initialize io_uring
        // creates io_uring instance
        int ret = io_uring_queue_init(QUEUE_DEPTH, &ring, 0);
        if (ret < 0) {
            // strerror can only accept non-negative integers???
            std::cerr << "io_uring_queue_init failed: " << strerror(-ret)
                      << std::endl;
            return false;
        }

        // create server socket
        server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd < 0) {
            std::cerr << "socket failed: " << strerror(errno) << std::endl;
            return false;
        }

        // set SO_REUSEADDR
        // allows immediate rebind after restart
        // without this, "Address already in use" error for ~60 sec
        int reuse = 1;
        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse,
                       sizeof(reuse)) < 0) {
            std::cerr << "setsockopt failed: " << strerror(errno) << std::endl;
            return false;
        }

        // bind
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;  // ipv4
        addr.sin_addr.s_addr =
            INADDR_ANY;  // bind to all network interfaces (0.0.0.0)
        addr.sin_port =
            htons(4221);  // converted to network byte order (big-endian)

        if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
            std::cerr << "Failed to bind to port " << PORT << ": "
                      << strerror(errno) << std::endl;
            return false;
        }

        // listen
        // 128: max pending connections
        // if 129 clients try to connect before `accept()` runs, the 129th gets
        // ECONNREFUSED
        if (listen(server_fd, 128) < 0) {
            std::cerr << "listen failed: " << strerror(errno) << std::endl;
            return false;
        }

        std::cout << "io_uring server listening on port " << PORT << std::endl;
        return true;
    }

    // This is the main **Event Loop**
    void run() {
        // submit initial accept
        submit_accept();

        while (!g_shutdown_requested.load()) {
            // push _all_ pending SQEs to kernel
            io_uring_submit(&ring);

            // wait for completions
            // with timeout for shutdown checking
            struct __kernel_timespec ts;
            ts.tv_sec = 1;
            ts.tv_nsec = 0;

            struct io_uring_cqe* cqe;
            // wait with 1-sec timeout: allows periodic shutdown check
            int ret = io_uring_wait_cqe_timeout(&ring, &cqe, &ts);

            if (ret == -ETIME) {
                continue;  // timeout, check shutdown flag
            }

            if (ret < 0) {
                if (ret != -EINTR) {
                    std::cerr << "io_uring_wait_cqe_timeout: " << strerror(-ret)
                              << std::endl;
                }
                continue;
            }

            // process all available CQEs
            unsigned head{};  // internal iterator state
            unsigned count{};

            // it's a macro
            // iterates all available CQEs
            io_uring_for_each_cqe(&ring, head, cqe) {
                // retrieve the UserData attached
                UserData* data =
                    static_cast<UserData*>(io_uring_cqe_get_data(cqe));

                switch (data->op) {
                    case IoOp::Accept:
                        handle_accept(cqe);
                        break;
                    case IoOp::Recv:
                        handle_recv(cqe, data->conn);
                        delete data;  // free per-operation UserData
                        break;
                    case IoOp::Send:
                        handle_send(cqe, data->conn);
                        delete data;
                        break;
                    case IoOp::Close:
                        handle_close(cqe, data->conn);
                        delete data;
                        break;
                }

                // tracks how many CQEs are processed
                // so that we can tell kernel to reclaim those slots
                ++count;
            }

            // mark CQEs as consumed (frees slots)
            // advances the completion queue head pointer by `count` entries
            // telling the kernel, "I'm done with these N entries, you can reuse
            // them"
            io_uring_cq_advance(&ring, count);
        }

        // cleanup: close all connections
        for (auto& [fd, conn] : connections) {
            close(fd);
        }
        connections.clear();
    }
};

int main(int argc, char* argv[]) {
    // Flush the buffer after every output operation: std::cout / std::cerr
    // output appears immediately rather than being buffered
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    if (argc > 2 && (std::string(argv[1]).compare("--directory") == 0)) {
        g_files_dir = argv[2];
        std::cout << "files dir: " << g_files_dir << std::endl;
    }

    setup_signal_handlers();

    IoUringServer server;
    if (!server.init()) {
        return 1;
    }

    server.run();

    std::cout << "Server shutdown complete!" << std::endl;

    return 0;
}
