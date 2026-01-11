# HTTP Server: io_uring Implementation Plan

## Current Architecture (Thread Pool)

The existing implementation uses a **thread-per-connection** model:

```
Main Thread                    Worker Thread Pool (N threads)
     │                         ┌─────────────────────────┐
     │ accept()                │ Thread 1: handle_client │
     │───────────────────────►│ Thread 2: handle_client │
     │ (blocking)              │ Thread 3: handle_client │
     │                         │ ...                     │
     ▼                         └─────────────────────────┘
```

**Characteristics:**
- N worker threads handle N concurrent connections
- Each thread blocks on `recv()`/`send()`/`poll()`
- Context switching overhead scales with connections
- Thread stack memory (~8MB each) limits scalability

---

## Proposed Architecture (io_uring)

io_uring uses an **async event-driven** model:

```
                    ┌─────────────────────────────────────┐
                    │           Linux Kernel              │
                    │  ┌─────────────────────────────┐   │
   Userspace        │  │       io_uring Core         │   │
       │            │  │  - Processes SQEs async     │   │
       │            │  │  - Handles network I/O      │   │
       │ submit     │  │  - Posts CQEs on completion │   │
       ▼            │  └─────────────────────────────┘   │
  ┌─────────┐       │              │                      │
  │  SQ     │───────┼──────────────┘                      │
  │ (Submit)│       │                                     │
  └─────────┘       │              │                      │
       ▲            │              ▼                      │
       │            │       ┌─────────┐                   │
   Event Loop       │       │   CQ    │◄──────────────────┘
       │            │       │(Complete)│
       │◄───────────┼───────┴─────────┘
       │            └─────────────────────────────────────┘
       │
  Single Thread
  (or few threads)
```

**Key Differences:**
| Aspect | Thread Pool | io_uring |
|--------|-------------|----------|
| Threads | N workers | 1 (or few) |
| I/O Model | Blocking | Async (kernel-driven) |
| Syscalls | 1 per operation | Batched |
| Memory | N × 8MB stacks | Minimal (buffers only) |
| C10K+ | Limited | Excellent |

---

## io_uring Core Concepts

### 1. Ring Buffers (Shared Memory)

**Submission Queue (SQ):** Application → Kernel
```c
struct io_uring_sqe {
    __u8  opcode;      // IORING_OP_ACCEPT, IORING_OP_RECV, etc.
    __u8  flags;       // Modifiers (linked, fixed file, etc.)
    __u16 ioprio;      // I/O priority
    __s32 fd;          // File descriptor
    __u64 off;         // Offset (for files)
    __u64 addr;        // Buffer address
    __u32 len;         // Buffer length
    __u64 user_data;   // Returned in CQE (for correlation)
    // ... more fields
};
```

**Completion Queue (CQ):** Kernel → Application
```c
struct io_uring_cqe {
    __u64 user_data;   // From SQE (identifies the operation)
    __s32 res;         // Result (bytes transferred or error)
    __u32 flags;       // Additional flags
};
```

### 2. Operations We Need

| Operation | Purpose | Replaces |
|-----------|---------|----------|
| `IORING_OP_ACCEPT` | Accept new connection | `accept()` |
| `IORING_OP_RECV` | Receive data | `recv()` |
| `IORING_OP_SEND` | Send response | `send()` |
| `IORING_OP_CLOSE` | Close connection | `close()` |
| `IORING_OP_TIMEOUT` | Keep-alive timeout | `poll()` timeout |

### 3. Workflow

```
┌──────────────────────────────────────────────────────────────┐
│                      Event Loop                              │
│                                                              │
│  1. Submit accept SQE (rearm after each accept)              │
│                          │                                   │
│                          ▼                                   │
│  2. io_uring_submit_and_wait() ──────────────────────┐      │
│                          │                            │      │
│                          ▼                            │      │
│  3. Process CQEs:                                     │      │
│     ┌─────────────────────────────────────────────┐  │      │
│     │ Accept CQE:                                  │  │      │
│     │   - Store new client_fd                      │  │      │
│     │   - Create Connection state                  │  │      │
│     │   - Submit RECV SQE for this fd              │  │      │
│     │   - Re-submit ACCEPT SQE                     │  │      │
│     └─────────────────────────────────────────────┘  │      │
│     ┌─────────────────────────────────────────────┐  │      │
│     │ Recv CQE:                                    │  │      │
│     │   - Append data to Connection buffer         │  │      │
│     │   - Parse HTTP request                       │  │      │
│     │   - If complete: build response, submit SEND │  │      │
│     │   - Else: submit another RECV               │  │      │
│     └─────────────────────────────────────────────┘  │      │
│     ┌─────────────────────────────────────────────┐  │      │
│     │ Send CQE:                                    │  │      │
│     │   - If keep-alive: submit RECV              │  │      │
│     │   - Else: submit CLOSE                       │  │      │
│     └─────────────────────────────────────────────┘  │      │
│     ┌─────────────────────────────────────────────┐  │      │
│     │ Close CQE:                                   │  │      │
│     │   - Free Connection state                    │  │      │
│     └─────────────────────────────────────────────┘  │      │
│                          │                            │      │
│                          └────────────────────────────┘      │
└──────────────────────────────────────────────────────────────┘
```

---

## Implementation Design

### File Structure

```
src/
├── main.cpp           # Current implementation (keep as fallback)
├── main_iouring.cpp   # New io_uring implementation
└── CMakeLists.txt     # Add io_uring build option
```

### Core Components

#### 1. Connection State

```cpp
enum class IoOperation : uint8_t {
    Accept,
    Recv,
    Send,
    Close,
    Timeout
};

struct Connection {
    int fd;
    std::string recv_buffer;
    std::string send_buffer;
    size_t bytes_sent = 0;
    bool keep_alive = true;

    // For timeout handling
    std::chrono::steady_clock::time_point last_activity;
};

// Encode operation type + connection pointer in user_data
struct UserData {
    IoOperation op;
    Connection* conn;  // nullptr for Accept
};
```

#### 2. IoUringServer Class

```cpp
class IoUringServer {
private:
    struct io_uring ring;
    int server_fd;
    std::unordered_map<int, std::unique_ptr<Connection>> connections;
    std::string files_directory;

public:
    IoUringServer(int port, size_t queue_depth = 256);
    ~IoUringServer();

    void run();  // Main event loop

private:
    // SQE submission helpers
    void submit_accept();
    void submit_recv(Connection* conn);
    void submit_send(Connection* conn);
    void submit_close(Connection* conn);

    // CQE handlers
    void handle_accept(io_uring_cqe* cqe);
    void handle_recv(io_uring_cqe* cqe, Connection* conn);
    void handle_send(io_uring_cqe* cqe, Connection* conn);
    void handle_close(io_uring_cqe* cqe, Connection* conn);

    // HTTP processing (reuse from original)
    bool process_request(Connection* conn);
};
```

#### 3. Main Event Loop

```cpp
void IoUringServer::run() {
    submit_accept();  // Initial accept

    while (!g_shutdown_requested.load()) {
        io_uring_submit(&ring);

        io_uring_cqe* cqe;
        int ret = io_uring_wait_cqe_timeout(&ring, &cqe, &timeout);

        if (ret == -ETIME) {
            // Handle timeouts for idle connections
            cleanup_idle_connections();
            continue;
        }

        if (ret < 0) continue;

        // Process all available CQEs
        unsigned head;
        io_uring_for_each_cqe(&ring, head, cqe) {
            UserData* data = (UserData*)io_uring_cqe_get_data(cqe);

            switch (data->op) {
                case IoOperation::Accept:
                    handle_accept(cqe);
                    break;
                case IoOperation::Recv:
                    handle_recv(cqe, data->conn);
                    break;
                case IoOperation::Send:
                    handle_send(cqe, data->conn);
                    break;
                case IoOperation::Close:
                    handle_close(cqe, data->conn);
                    break;
            }
        }

        io_uring_cq_advance(&ring, count);
    }
}
```

---

## Implementation Steps

### Phase 1: Core Infrastructure
1. Add liburing dependency to CMakeLists.txt
2. Create `IoUringServer` class skeleton
3. Implement ring initialization and cleanup
4. Implement `submit_accept()` and `handle_accept()`

### Phase 2: Connection Handling
5. Implement `Connection` struct and management
6. Implement `submit_recv()` and `handle_recv()`
7. Implement `submit_send()` and `handle_send()`
8. Implement `submit_close()` and `handle_close()`

### Phase 3: HTTP Processing
9. Port HTTP parsing from original (minimal changes needed)
10. Port response building and gzip compression
11. Implement keep-alive connection reuse

### Phase 4: Robustness
12. Add timeout handling for idle connections
13. Add graceful shutdown
14. Add error handling and logging

### Phase 5: Testing
15. Test with existing endpoints
16. Test keep-alive behavior
17. Benchmark vs thread pool version

---

## Key Files to Modify

| File | Changes |
|------|---------|
| `CMakeLists.txt` | Add liburing, add build option for io_uring version |
| `src/main_iouring.cpp` | **NEW** - Complete io_uring implementation |
| `flake.nix` | Add liburing to dependencies (if needed) |

---

## Dependencies

```cmake
# CMakeLists.txt addition
find_package(PkgConfig REQUIRED)
pkg_check_modules(URING REQUIRED liburing)
target_link_libraries(main_iouring ${URING_LIBRARIES})
```

---

## Tradeoffs

**Advantages of io_uring:**
- Handles 10,000+ concurrent connections with single thread
- Minimal memory overhead (no thread stacks)
- Fewer context switches
- Batched syscalls reduce overhead

**Disadvantages:**
- Linux 5.1+ only (not portable)
- More complex state management
- Debugging async code is harder
- Newer API, less mature ecosystem

---

## User Preferences (Confirmed)

- **File strategy:** Separate file (`main_iouring.cpp`) with CMake flag to choose
- **Scaling:** Single io_uring ring (simpler implementation)

---

## Complete io_uring Implementation Code

Below is the full implementation that will be created in `src/main_iouring.cpp`:

```cpp
#include <arpa/inet.h>
#include <liburing.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#include <zlib.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

// ============================================================================
// GLOBAL STATE
// ============================================================================

std::atomic<bool> g_shutdown_requested{false};
std::string g_files_dir{};

constexpr int PORT = 4221;
constexpr int QUEUE_DEPTH = 256;           // io_uring queue size
constexpr int RECV_BUFFER_SIZE = 4096;     // Per-recv buffer size
constexpr size_t MAX_REQUEST_SIZE = 1024 * 1024;  // 1MB limit
constexpr int KEEP_ALIVE_TIMEOUT_SEC = 60;

// ============================================================================
// SIGNAL HANDLING
// ============================================================================

extern "C" void signal_handler(int) {
    g_shutdown_requested.store(true, std::memory_order_relaxed);
}

void setup_signal_handlers() {
    struct sigaction sa{};
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
}

// ============================================================================
// GZIP COMPRESSION (same as original)
// ============================================================================

std::string gzip_compress(const std::string& data) {
    z_stream zs{};
    if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8,
                     Z_DEFAULT_STRATEGY) != Z_OK) {
        return "";
    }

    zs.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(data.data()));
    zs.avail_in = data.size();

    std::string compressed;
    char buffer[4096];

    do {
        zs.next_out = reinterpret_cast<Bytef*>(buffer);
        zs.avail_out = sizeof(buffer);
        deflate(&zs, Z_FINISH);
        compressed.append(buffer, sizeof(buffer) - zs.avail_out);
    } while (zs.avail_out == 0);

    deflateEnd(&zs);
    return compressed;
}

// ============================================================================
// IO OPERATION TYPES
// ============================================================================

enum class IoOp : uint8_t {
    Accept,
    Recv,
    Send,
    Close
};

// ============================================================================
// CONNECTION STATE
// ============================================================================

struct Connection {
    int fd;
    std::string recv_buffer;      // Accumulates incoming data
    std::string send_buffer;      // Data waiting to be sent
    size_t bytes_sent = 0;        // Tracks partial sends
    bool keep_alive = true;
    char temp_recv[RECV_BUFFER_SIZE];  // Buffer for individual recv operations

    explicit Connection(int fd_) : fd(fd_) {}
};

// ============================================================================
// USER DATA FOR io_uring (encode operation + connection)
// ============================================================================

struct UserData {
    IoOp op;
    Connection* conn;  // nullptr for Accept

    UserData(IoOp op_, Connection* conn_ = nullptr) : op(op_), conn(conn_) {}
};

// ============================================================================
// HTTP REQUEST PROCESSING
// ============================================================================

// Returns: {response_string, keep_alive}
std::pair<std::string, bool> process_http_request(const std::string& request) {
    // Parse method, path, version
    size_t method_end = request.find(' ');
    if (method_end == std::string::npos) {
        return {"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n", false};
    }
    std::string method = request.substr(0, method_end);

    size_t path_end = request.find(' ', method_end + 1);
    if (path_end == std::string::npos) {
        return {"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n", false};
    }
    std::string path = request.substr(method_end + 1, path_end - method_end - 1);

    size_t version_end = request.find("\r\n");
    std::string http_version = request.substr(path_end + 1, version_end - path_end - 1);
    bool is_http_11 = (http_version == "HTTP/1.1");

    // Parse Connection header
    bool keep_alive = is_http_11;  // HTTP/1.1 defaults to keep-alive
    size_t conn_pos = request.find("Connection: ");
    if (conn_pos != std::string::npos) {
        size_t conn_start = conn_pos + 12;
        size_t conn_end = request.find("\r\n", conn_start);
        std::string conn_value = request.substr(conn_start, conn_end - conn_start);
        std::transform(conn_value.begin(), conn_value.end(), conn_value.begin(), ::tolower);
        if (conn_value.find("close") != std::string::npos) {
            keep_alive = false;
        } else if (conn_value.find("keep-alive") != std::string::npos) {
            keep_alive = true;
        }
    }

    std::string conn_header = keep_alive ? "Connection: keep-alive\r\n" : "Connection: close\r\n";

    // Parse User-Agent
    std::string user_agent;
    size_t ua_pos = request.find("User-Agent: ");
    if (ua_pos != std::string::npos) {
        size_t ua_start = ua_pos + 12;
        size_t ua_end = request.find("\r\n", ua_start);
        user_agent = request.substr(ua_start, ua_end - ua_start);
    }

    // Parse Accept-Encoding
    std::vector<std::string> encodings;
    size_t ae_pos = request.find("Accept-Encoding: ");
    if (ae_pos != std::string::npos) {
        size_t ae_start = ae_pos + 17;
        size_t ae_end = request.find("\r\n", ae_start);
        std::string ae_value = request.substr(ae_start, ae_end - ae_start);
        std::istringstream ss(ae_value);
        std::string encoding;
        while (std::getline(ss, encoding, ',')) {
            size_t start = encoding.find_first_not_of(' ');
            if (start != std::string::npos) {
                encodings.push_back(encoding.substr(start));
            }
        }
    }

    // Parse Content-Length and body
    size_t content_len = 0;
    size_t cl_pos = request.find("Content-Length: ");
    if (cl_pos != std::string::npos) {
        size_t cl_start = cl_pos + 16;
        size_t cl_end = request.find("\r\n", cl_start);
        content_len = std::stoul(request.substr(cl_start, cl_end - cl_start));
    }

    std::string body;
    size_t body_start = request.find("\r\n\r\n");
    if (body_start != std::string::npos) {
        body = request.substr(body_start + 4, content_len);
    }

    // Route request
    std::string response;

    if (path == "/") {
        response = "HTTP/1.1 200 OK\r\n" + conn_header + "\r\n";
    }
    else if (path.starts_with("/echo/")) {
        std::string str_to_echo = path.substr(6);
        bool supports_gzip = std::find(encodings.begin(), encodings.end(), "gzip") != encodings.end();

        if (supports_gzip) {
            std::string compressed = gzip_compress(str_to_echo);
            response = "HTTP/1.1 200 OK\r\n" + conn_header +
                       "Content-Encoding: gzip\r\nContent-Type: text/plain\r\nContent-Length: " +
                       std::to_string(compressed.size()) + "\r\n\r\n" + compressed;
        } else {
            response = "HTTP/1.1 200 OK\r\n" + conn_header +
                       "Content-Type: text/plain\r\nContent-Length: " +
                       std::to_string(str_to_echo.size()) + "\r\n\r\n" + str_to_echo;
        }
    }
    else if (path.starts_with("/user-agent")) {
        response = "HTTP/1.1 200 OK\r\n" + conn_header +
                   "Content-Type: text/plain\r\nContent-Length: " +
                   std::to_string(user_agent.size()) + "\r\n\r\n" + user_agent;
    }
    else if (path.starts_with("/files/")) {
        std::string filename = path.substr(7);

        if (filename.find("..") != std::string::npos) {
            response = "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n";
            keep_alive = false;
        } else if (g_files_dir.empty()) {
            response = "HTTP/1.1 404 Not Found\r\n" + conn_header + "\r\n";
        } else {
            std::string filepath = g_files_dir + filename;

            if (method == "GET") {
                std::ifstream file(filepath, std::ios::binary);
                if (!file) {
                    response = "HTTP/1.1 404 Not Found\r\n" + conn_header + "\r\n";
                } else {
                    std::ostringstream ss;
                    ss << file.rdbuf();
                    std::string content = ss.str();
                    response = "HTTP/1.1 200 OK\r\n" + conn_header +
                               "Content-Type: application/octet-stream\r\nContent-Length: " +
                               std::to_string(content.size()) + "\r\n\r\n" + content;
                }
            } else if (method == "POST") {
                std::ofstream file(filepath, std::ios::binary);
                if (!file) {
                    response = "HTTP/1.1 500 Server Error\r\nConnection: close\r\n\r\n";
                    keep_alive = false;
                } else {
                    file.write(body.data(), body.size());
                    response = "HTTP/1.1 201 Created\r\n" + conn_header + "\r\n";
                }
            } else {
                response = "HTTP/1.1 405 Method Not Allowed\r\n" + conn_header + "\r\n";
            }
        }
    }
    else {
        response = "HTTP/1.1 404 Not Found\r\n" + conn_header + "\r\n";
    }

    return {response, keep_alive};
}

// ============================================================================
// IO_URING SERVER CLASS
// ============================================================================

class IoUringServer {
private:
    struct io_uring ring;
    int server_fd;
    std::unordered_map<int, std::unique_ptr<Connection>> connections;

    // Pre-allocated UserData for accept (reused)
    UserData accept_data{IoOp::Accept, nullptr};

public:
    IoUringServer() : server_fd(-1) {}

    ~IoUringServer() {
        if (server_fd >= 0) {
            close(server_fd);
        }
        io_uring_queue_exit(&ring);
    }

    bool init() {
        // Initialize io_uring
        int ret = io_uring_queue_init(QUEUE_DEPTH, &ring, 0);
        if (ret < 0) {
            std::cerr << "io_uring_queue_init failed: " << strerror(-ret) << std::endl;
            return false;
        }

        // Create server socket
        server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd < 0) {
            std::cerr << "socket failed: " << strerror(errno) << std::endl;
            return false;
        }

        // Set SO_REUSEADDR
        int reuse = 1;
        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
            std::cerr << "setsockopt failed: " << strerror(errno) << std::endl;
            return false;
        }

        // Bind
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(PORT);

        if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            std::cerr << "bind failed: " << strerror(errno) << std::endl;
            return false;
        }

        // Listen
        if (listen(server_fd, 128) < 0) {
            std::cerr << "listen failed: " << strerror(errno) << std::endl;
            return false;
        }

        std::cout << "io_uring server listening on port " << PORT << std::endl;
        return true;
    }

    void run() {
        // Submit initial accept
        submit_accept();

        while (!g_shutdown_requested.load()) {
            // Submit any pending SQEs
            io_uring_submit(&ring);

            // Wait for completions (with timeout for shutdown checking)
            struct __kernel_timespec ts;
            ts.tv_sec = 1;
            ts.tv_nsec = 0;

            struct io_uring_cqe* cqe;
            int ret = io_uring_wait_cqe_timeout(&ring, &cqe, &ts);

            if (ret == -ETIME) {
                continue;  // Timeout, check shutdown flag
            }

            if (ret < 0) {
                if (ret != -EINTR) {
                    std::cerr << "io_uring_wait_cqe_timeout: " << strerror(-ret) << std::endl;
                }
                continue;
            }

            // Process all available CQEs
            unsigned head;
            unsigned count = 0;
            io_uring_for_each_cqe(&ring, head, cqe) {
                UserData* data = static_cast<UserData*>(io_uring_cqe_get_data(cqe));

                switch (data->op) {
                    case IoOp::Accept:
                        handle_accept(cqe);
                        break;
                    case IoOp::Recv:
                        handle_recv(cqe, data->conn);
                        delete data;  // Free per-operation UserData
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
                ++count;
            }

            io_uring_cq_advance(&ring, count);
        }

        // Cleanup: close all connections
        for (auto& [fd, conn] : connections) {
            close(fd);
        }
        connections.clear();
    }

private:
    // ========================================================================
    // SQE SUBMISSION HELPERS
    // ========================================================================

    void submit_accept() {
        struct io_uring_sqe* sqe = io_uring_get_sqe(&ring);
        if (!sqe) {
            std::cerr << "Failed to get SQE for accept" << std::endl;
            return;
        }

        io_uring_prep_accept(sqe, server_fd, nullptr, nullptr, 0);
        io_uring_sqe_set_data(sqe, &accept_data);
    }

    void submit_recv(Connection* conn) {
        struct io_uring_sqe* sqe = io_uring_get_sqe(&ring);
        if (!sqe) {
            std::cerr << "Failed to get SQE for recv" << std::endl;
            submit_close(conn);
            return;
        }

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

        const char* data = conn->send_buffer.data() + conn->bytes_sent;
        size_t len = conn->send_buffer.size() - conn->bytes_sent;

        io_uring_prep_send(sqe, conn->fd, data, len, 0);
        io_uring_sqe_set_data(sqe, new UserData(IoOp::Send, conn));
    }

    void submit_close(Connection* conn) {
        struct io_uring_sqe* sqe = io_uring_get_sqe(&ring);
        if (!sqe) {
            // Fallback: synchronous close
            close(conn->fd);
            connections.erase(conn->fd);
            return;
        }

        io_uring_prep_close(sqe, conn->fd);
        io_uring_sqe_set_data(sqe, new UserData(IoOp::Close, conn));
    }

    // ========================================================================
    // CQE HANDLERS
    // ========================================================================

    void handle_accept(struct io_uring_cqe* cqe) {
        int client_fd = cqe->res;

        // Always re-submit accept for next connection
        submit_accept();

        if (client_fd < 0) {
            if (client_fd != -EAGAIN && client_fd != -EINTR) {
                std::cerr << "accept failed: " << strerror(-client_fd) << std::endl;
            }
            return;
        }

        // Create connection state
        auto conn = std::make_unique<Connection>(client_fd);
        Connection* conn_ptr = conn.get();
        connections[client_fd] = std::move(conn);

        // Start receiving
        submit_recv(conn_ptr);
    }

    void handle_recv(struct io_uring_cqe* cqe, Connection* conn) {
        int bytes = cqe->res;

        if (bytes <= 0) {
            // Connection closed or error
            submit_close(conn);
            return;
        }

        // Append to buffer
        conn->recv_buffer.append(conn->temp_recv, bytes);

        // Check size limit
        if (conn->recv_buffer.size() > MAX_REQUEST_SIZE) {
            conn->send_buffer = "HTTP/1.1 413 Payload Too Large\r\nConnection: close\r\n\r\n";
            conn->bytes_sent = 0;
            conn->keep_alive = false;
            submit_send(conn);
            return;
        }

        // Try to parse complete request
        if (!try_process_request(conn)) {
            // Need more data
            submit_recv(conn);
        }
    }

    bool try_process_request(Connection* conn) {
        // Look for end of headers
        size_t header_end = conn->recv_buffer.find("\r\n\r\n");
        if (header_end == std::string::npos) {
            return false;  // Incomplete headers
        }

        // Parse Content-Length to determine body size
        size_t content_len = 0;
        size_t cl_pos = conn->recv_buffer.find("Content-Length: ");
        if (cl_pos != std::string::npos && cl_pos < header_end) {
            size_t cl_start = cl_pos + 16;
            size_t cl_end = conn->recv_buffer.find("\r\n", cl_start);
            content_len = std::stoul(conn->recv_buffer.substr(cl_start, cl_end - cl_start));
        }

        size_t total_size = header_end + 4 + content_len;

        if (conn->recv_buffer.size() < total_size) {
            return false;  // Body not complete
        }

        // Extract complete request
        std::string request = conn->recv_buffer.substr(0, total_size);
        conn->recv_buffer.erase(0, total_size);

        // Process and build response
        auto [response, keep_alive] = process_http_request(request);
        conn->send_buffer = std::move(response);
        conn->bytes_sent = 0;
        conn->keep_alive = keep_alive;

        // Start sending
        submit_send(conn);
        return true;
    }

    void handle_send(struct io_uring_cqe* cqe, Connection* conn) {
        int bytes = cqe->res;

        if (bytes < 0) {
            // Send error
            submit_close(conn);
            return;
        }

        conn->bytes_sent += bytes;

        if (conn->bytes_sent < conn->send_buffer.size()) {
            // Partial send, continue
            submit_send(conn);
            return;
        }

        // Send complete
        conn->send_buffer.clear();
        conn->bytes_sent = 0;

        if (conn->keep_alive) {
            // Check if there's more data in buffer (pipelining)
            if (!conn->recv_buffer.empty() && try_process_request(conn)) {
                return;  // Processing next request
            }
            // Wait for more data
            submit_recv(conn);
        } else {
            // Close connection
            submit_close(conn);
        }
    }

    void handle_close(struct io_uring_cqe* cqe, Connection* conn) {
        (void)cqe;  // Result not needed
        connections.erase(conn->fd);
    }
};

// ============================================================================
// MAIN
// ============================================================================

int main(int argc, char* argv[]) {
    // Parse arguments
    if (argc > 2 && std::string(argv[1]) == "--directory") {
        g_files_dir = argv[2];
        if (!g_files_dir.empty() && g_files_dir.back() != '/') {
            g_files_dir += '/';
        }
        std::cout << "Files directory: " << g_files_dir << std::endl;
    }

    setup_signal_handlers();

    IoUringServer server;
    if (!server.init()) {
        return 1;
    }

    server.run();

    std::cout << "Server shutdown complete" << std::endl;
    return 0;
}
```

---

## CMakeLists.txt Changes

Add to `src/CMakeLists.txt`:

```cmake
# Option to build io_uring version
option(USE_IOURING "Build io_uring-based server" OFF)

if(USE_IOURING)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(URING REQUIRED liburing)

    add_executable(main_iouring main_iouring.cpp)
    target_compile_features(main_iouring PRIVATE cxx_std_23)
    target_include_directories(main_iouring PRIVATE ${URING_INCLUDE_DIRS})
    target_link_libraries(main_iouring ${URING_LIBRARIES} z)
endif()
```

Build command:
```bash
cmake -DUSE_IOURING=ON -B build
cmake --build build
./build/src/main_iouring --directory /path/to/files
```

---

## Files to Create/Modify

| File | Action |
|------|--------|
| `src/main_iouring.cpp` | **CREATE** - Full io_uring implementation (~400 lines) |
| `src/CMakeLists.txt` | **MODIFY** - Add io_uring build option |
| `flake.nix` | **MODIFY** - Add liburing to dependencies |
