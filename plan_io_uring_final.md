# io_uring HTTP Server - Line-by-Line Code Explanation

This document provides a detailed explanation of every section and line in `src/main_iouring.cpp`.

---

## Table of Contents

1. [Includes and Headers](#includes-and-headers)
2. [Global State](#global-state)
3. [Signal Handling](#signal-handling)
4. [GZIP Compression](#gzip-compression)
5. [Core Data Structures](#core-data-structures)
6. [HTTP Request Processing](#http-request-processing)
7. [IoUringServer Class](#iouringserver-class)
8. [Main Function](#main-function)

---

## Includes and Headers (Lines 1-21)

```cpp
#include <liburing.h>
#include <liburing/io_uring.h>
```
- **liburing.h**: The main liburing header providing the C API wrapper around io_uring
- **liburing/io_uring.h**: Low-level io_uring structures (SQE, CQE definitions)

```cpp
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
```
- **netinet/in.h**: Internet address structures (`sockaddr_in`, `INADDR_ANY`, `htons`)
- **sys/socket.h**: Socket API (`socket()`, `bind()`, `listen()`, `setsockopt()`)
- **unistd.h**: POSIX API (`close()`, file descriptor operations)

```cpp
#include <zlib.h>
```
- **zlib.h**: Compression library for gzip support (deflate algorithm)

```cpp
#include <algorithm>      // std::find, std::transform
#include <atomic>          // std::atomic for thread-safe shutdown flag
#include <cerrno>          // errno for error codes
#include <csignal>         // sigaction for signal handling
#include <cstdint>         // uint8_t, size_t
#include <cstring>         // strerror()
#include <fstream>         // file I/O for /files/ endpoint
#include <iostream>        // std::cout, std::cerr
#include <memory>          // std::unique_ptr
#include <sstream>         // std::istringstream for parsing
#include <string>          // std::string
#include <unordered_map>   // connection storage
#include <utility>         // std::pair, std::move
#include <vector>          // encoding list
```

---

## Global State (Lines 23-38)

```cpp
std::atomic<bool> g_shutdown_requested{false};
```
- **Purpose**: Thread-safe flag to signal graceful shutdown
- **Why atomic?**: Signal handlers run asynchronously; atomics prevent data races
- **Initial value**: `false` - server runs until set to `true`

```cpp
const std::string TMP_DIR = "/tmp";
std::string g_files_dir{};
```
- **TMP_DIR**: Unused constant (leftover from development)
- **g_files_dir**: Base directory for `/files/` endpoint, set via `--directory` CLI arg

```cpp
constexpr int PORT = 4221;
```
- **Compile-time constant**: The server listens on port 4221

```cpp
constexpr int QUEUE_DEPTH = 256;
```
- **io_uring queue size**: Maximum number of in-flight I/O operations
- **Why 256?**: Good balance between memory usage and concurrency
- Larger = more concurrent ops, but more kernel memory

```cpp
constexpr int RECV_BUFFER_SIZE = 4096;
```
- **Per-recv buffer**: Each recv operation reads up to 4KB
- Matches typical network MTU and page size

```cpp
constexpr int KEEP_ALIVE_TIMEOUT_MS = 60000;
constexpr int KEEP_ALIVE_TIMEOUT_SEC = 60;
```
- **Connection timeout**: Idle connections are kept for 60 seconds
- *Note*: `KEEP_ALIVE_TIMEOUT_MS` is currently unused in this implementation

```cpp
constexpr size_t MAX_REQUEST_SIZE = 1024 * 1024;  // 1MB
```
- **Request size limit**: Prevents memory exhaustion from large requests
- If exceeded, returns HTTP 413 (Payload Too Large)

---

## Signal Handling (Lines 40-59)

```cpp
extern "C" void signal_handler(int) {
    g_shutdown_requested.store(true, std::memory_order_relaxed);
}
```
- **`extern "C"`**: Uses C linkage (no C++ name mangling)
  - Required because the Linux kernel calls this function using C conventions
- **Parameter `int`**: The signal number (SIGINT=2, SIGTERM=15) - unused here
- **`std::memory_order_relaxed`**: No synchronization needed; just sets the flag
  - The main loop will eventually see the change

```cpp
void setup_signal_handlers() {
    struct sigaction sa{};
```
- **`sigaction`**: POSIX structure for signal handling (more reliable than `signal()`)
- **`{}`**: Zero-initializes all fields

```cpp
    sa.sa_handler = signal_handler;
```
- Points to our handler function

```cpp
    sigemptyset(&sa.sa_mask);
```
- Clears the signal mask (no signals blocked during handler execution)

```cpp
    sa.sa_flags = 0;
```
- No special flags (SA_RESTART, SA_NODEFER, etc.)

```cpp
    sigaction(SIGINT, &sa, nullptr);   // Ctrl+C
    sigaction(SIGTERM, &sa, nullptr);  // kill command
}
```
- **SIGINT** (2): Sent when user presses Ctrl+C
- **SIGTERM** (15): Sent by `kill` command or system shutdown
- **Third param `nullptr`**: We don't need the old handler

---

## GZIP Compression (Lines 61-96)

```cpp
std::string gzip_compress(const std::string& data) {
    z_stream zs{};
```
- **`z_stream`**: zlib's compression state structure
- **`{}`**: Zero-initializes all fields

```cpp
    if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8,
                     Z_DEFAULT_STRATEGY) != Z_OK) {
```
- **`deflateInit2`**: Initializes compression with specific parameters
- **`Z_DEFAULT_COMPRESSION`**: Level 6 (balance of speed/ratio)
- **`Z_DEFLATED`**: Use DEFLATE algorithm
- **`15 + 16`**: Window bits
  - `15` = maximum window size (32KB)
  - `+16` = **gzip format** (adds gzip header/trailer, not raw deflate)
- **`8`**: Memory level (1-9, higher = more memory, better compression)
- **`Z_DEFAULT_STRATEGY`**: General-purpose compression

```cpp
    zs.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(data.data()));
    zs.avail_in = data.size();
```
- **`next_in`**: Pointer to input data
- **`avail_in`**: Number of bytes available to compress
- **`reinterpret_cast<Bytef*>`**: zlib uses `unsigned char*` (Bytef)
- **`const_cast`**: Required because zlib API isn't const-correct

```cpp
    std::string compressed;
    char buffer[4096];
```
- **`compressed`**: Accumulates output
- **`buffer`**: Temporary 4KB chunk for each deflate call

```cpp
    do {
        zs.next_out = reinterpret_cast<Bytef*>(buffer);
        zs.avail_out = sizeof(buffer);
```
- **`next_out`**: Where to write compressed data
- **`avail_out`**: Space available in output buffer

```cpp
        deflate(&zs, Z_FINISH);
```
- **`deflate`**: Performs compression
- **`Z_FINISH`**: Signals this is the final (and only) call - flush everything

```cpp
        compressed.append(buffer, sizeof(buffer) - zs.avail_out);
    } while (zs.avail_out == 0);
```
- **`sizeof(buffer) - zs.avail_out`**: Bytes actually written
- **Loop condition**: If `avail_out == 0`, the buffer filled; there may be more data

```cpp
    deflateEnd(&zs);
    return compressed;
}
```
- **`deflateEnd`**: Frees zlib's internal state
- Returns the gzip-compressed data

---

## Core Data Structures (Lines 98-131)

### IoOp Enum (Lines 102-105)

```cpp
enum class IoOp : uint8_t { Accept, Recv, Send, Close };
```
- **`enum class`**: Strongly-typed enum (not implicitly convertible to int)
- **`: uint8_t`**: Uses 1 byte instead of default 4 bytes (int)
- **Operations**:
  - `Accept`: Waiting to accept a new connection
  - `Recv`: Waiting to receive data from client
  - `Send`: Waiting to send data to client
  - `Close`: Waiting to close a connection

### Connection Struct (Lines 107-120)

```cpp
struct Connection {
    int fd;
```
- **`fd`**: The client's socket file descriptor

```cpp
    std::string recv_buffer;  // accumulates incoming data
```
- **Purpose**: HTTP requests may arrive in multiple TCP segments
- Data is appended here until a complete request is received

```cpp
    std::string send_buffer;  // data waiting to be sent
```
- **Purpose**: Holds the HTTP response
- May require multiple send operations if large

```cpp
    size_t bytes_sent = 0;
```
- **Purpose**: Tracks progress for partial sends
- If send() returns less than buffer size, continue from this offset

```cpp
    bool keep_alive = true;
```
- **Purpose**: HTTP/1.1 persistent connections
- If true, connection stays open for more requests

```cpp
    char temp_recv[RECV_BUFFER_SIZE];
```
- **Purpose**: Fixed-size buffer for each recv operation
- io_uring needs a stable memory address for async reads
- Data is copied to `recv_buffer` after completion

```cpp
    explicit Connection(int fd_) : fd{fd_} {}
```
- **`explicit`**: Prevents implicit conversion from `int` to `Connection`
- Initializes `fd` only; other members use default values

### UserData Struct (Lines 122-131)

```cpp
struct UserData {
    IoOp op;
    Connection* conn;  // nullptr for Accept
```
- **Purpose**: Attached to each io_uring operation to identify it on completion
- **`op`**: Which operation type completed
- **`conn`**: Which connection it belongs to (nullptr for Accept since no connection yet)

```cpp
    UserData(IoOp op_, Connection* conn_ = nullptr) : op(op_), conn(conn_) {}
};
```
- Constructor with default `conn = nullptr` for Accept operations

---

## HTTP Request Processing (Lines 133-293)

### Function Signature

```cpp
std::pair<std::string, bool> process_http_request(const std::string& request) {
```
- **Returns**: `{response_string, keep_alive_flag}`
- **Input**: Complete HTTP request as a string

### Parsing the Request Line (Lines 141-152)

```cpp
    size_t method_end = request.find(' ');
    std::string method = request.substr(0, method_end);
```
- HTTP format: `GET /path HTTP/1.1\r\n`
- Finds first space, extracts method (GET, POST, etc.)

```cpp
    size_t path_end = request.find(' ', method_end + 1);
    std::string path = request.substr(method_end + 1, path_end - 1 - method_end);
```
- Finds second space, extracts path (`/`, `/echo/hello`, etc.)

```cpp
    size_t version_end = request.find("\r\n");
    std::string http_version = request.substr(path_end + 1, version_end - 1 - path_end);
    bool is_http_11 = (http_version.compare("HTTP/1.1") == 0);
```
- Extracts HTTP version
- **`is_http_11`**: Used for keep-alive default behavior

### Parsing Connection Header (Lines 154-173)

```cpp
    bool keep_alive = is_http_11;  // HTTP/1.1 defaults to keep-alive
```
- **HTTP/1.1**: Keep-alive by default
- **HTTP/1.0**: Close by default

```cpp
    size_t conn_pos = request.find("Connection: ");
    if (conn_pos != std::string::npos) {
        // ... extract and parse value
        std::transform(conn_value.begin(), conn_value.end(), conn_value.begin(), ::tolower);
```
- **`std::transform` with `::tolower`**: Case-insensitive comparison
- Looks for "close" or "keep-alive" in the header value

### Building Connection Header

```cpp
    std::string conn_header = keep_alive ? "Connection: keep-alive\r\n" : "Connection: close\r\n";
```
- Included in every response to confirm connection behavior

### Parsing Other Headers (Lines 175-217)

```cpp
    // User-Agent header (lines 176-183)
    size_t ua_pos = request.find("User-Agent: ");
    // ... extract value
```
- Used for `/user-agent` endpoint

```cpp
    // Accept-Encoding header (lines 185-201)
    std::vector<std::string> encodings;
    // ... parse comma-separated list
```
- Parses `Accept-Encoding: gzip, deflate` into a vector
- Used to determine if response can be gzip-compressed

```cpp
    // Content-Length header (lines 203-210)
    size_t content_len = 0;
    // ... extract numeric value
```
- Needed for POST requests to know body size

```cpp
    // Request body (lines 212-217)
    std::string body{};
    size_t body_pre_start = request.find("\r\n\r\n");
    // ... extract body after double CRLF
```
- Body starts after `\r\n\r\n` (end of headers)

### Route Handling (Lines 219-290)

**Root path `/`:**
```cpp
    if (path == "/") {
        response = "HTTP/1.1 200 OK\r\n" + conn_header + "\r\n";
    }
```
- Returns empty 200 OK response

**Echo path `/echo/<string>`:**
```cpp
    else if (path.starts_with("/echo/")) {
        std::string str_to_echo = path.substr(6);
        bool supports_gzip = std::find(encodings.begin(), encodings.end(), "gzip") != encodings.end();
```
- Extracts string after `/echo/`
- Checks if client accepts gzip compression
- If gzip supported, compresses the response body

**User-Agent path `/user-agent`:**
```cpp
    else if (path.starts_with("/user-agent")) {
        // ... return User-Agent header value as body
    }
```

**Files path `/files/<filename>`:**
```cpp
    else if (path.starts_with("/files/")) {
        std::string filename = path.substr(7);
        if (filename.find("..") != std::string::npos) {
            response = "HTTP/1.1 403 Forbidden\r\n...";
        }
```
- **Security check**: Rejects path traversal (`../`)
- **GET**: Reads and returns file content
- **POST**: Writes request body to file

**404 fallback:**
```cpp
    } else {
        response = "HTTP/1.1 404 Not Found\r\n" + conn_header + "\r\n";
    }
```

---

## IoUringServer Class (Lines 295-625)

### Private Members (Lines 300-306)

```cpp
    struct io_uring ring;
```
- **The io_uring instance**: Contains submission and completion queues

```cpp
    int server_fd;
```
- **Server socket**: Listening for new connections

```cpp
    std::unordered_map<int, std::unique_ptr<Connection>> connections;
```
- **Connection storage**: Maps file descriptor → Connection object
- `unique_ptr` for automatic cleanup

```cpp
    UserData accept_data{IoOp::Accept, nullptr};
```
- **Reusable UserData for Accept**: No need to allocate/free for each accept

### SQE Submission Helpers (Lines 308-362)

#### submit_accept() (Lines 312-321)

```cpp
    void submit_accept() {
        struct io_uring_sqe* sqe = io_uring_get_sqe(&ring);
```
- **`io_uring_get_sqe`**: Gets a free Submission Queue Entry
- Returns nullptr if queue is full

```cpp
        io_uring_prep_accept(sqe, server_fd, nullptr, nullptr, 0);
```
- **`io_uring_prep_accept`**: Prepares async accept operation
- **server_fd**: The listening socket
- **nullptr, nullptr**: Don't need client address info
- **0**: No flags

```cpp
        io_uring_sqe_set_data(sqe, &accept_data);
```
- **Attaches UserData**: When CQE arrives, we can identify this was an Accept

#### submit_recv() (Lines 323-333)

```cpp
    void submit_recv(Connection* conn) {
        struct io_uring_sqe* sqe = io_uring_get_sqe(&ring);
        if (!sqe) {
            submit_close(conn);  // Can't continue, close connection
            return;
        }
```

```cpp
        io_uring_prep_recv(sqe, conn->fd, conn->temp_recv, RECV_BUFFER_SIZE, 0);
```
- **`io_uring_prep_recv`**: Prepares async receive
- **conn->fd**: Client socket
- **conn->temp_recv**: Buffer to store received data
- **RECV_BUFFER_SIZE**: Maximum bytes to read
- **0**: No flags (MSG_DONTWAIT not needed - io_uring is inherently async)

```cpp
        io_uring_sqe_set_data(sqe, new UserData(IoOp::Recv, conn));
```
- **`new UserData`**: Each recv gets its own UserData
- Must be freed when CQE is processed

#### submit_send() (Lines 335-349)

```cpp
        const char* data = conn->send_buffer.data() + conn->bytes_sent;
        size_t len = conn->send_buffer.size() - conn->bytes_sent;
```
- **Handles partial sends**: If previous send didn't complete, start from offset

```cpp
        io_uring_prep_send(sqe, conn->fd, data, len, 0);
```
- Prepares async send operation

#### submit_close() (Lines 351-362)

```cpp
    void submit_close(Connection* conn) {
        struct io_uring_sqe* sqe = io_uring_get_sqe(&ring);
        if (!sqe) {
            close(conn->fd);  // Fallback: synchronous close
            connections.erase(conn->fd);
            return;
        }
        io_uring_prep_close(sqe, conn->fd);
```
- Prepares async close operation
- **Fallback**: If no SQE available, close synchronously

### CQE Handlers (Lines 364-494)

#### handle_accept() (Lines 368-389)

```cpp
    void handle_accept(struct io_uring_cqe* cqe) {
        int client_fd = cqe->res;
```
- **`cqe->res`**: The result of the accept operation
- For accept, this is the new client file descriptor (or negative error)

```cpp
        submit_accept();  // ALWAYS re-submit for next connection
```
- **Critical**: Must rearm accept to continue accepting connections
- Done immediately, even before processing this connection

```cpp
        if (client_fd < 0) {
            if (client_fd != -EAGAIN && client_fd != -EINTR) {
                std::cerr << "accept failed: " << strerror(-client_fd) << std::endl;
            }
            return;
        }
```
- **Error handling**: EAGAIN/EINTR are transient, don't log them

```cpp
        auto conn = std::make_unique<Connection>(client_fd);
        Connection* conn_ptr = conn.get();
        connections[client_fd] = std::move(conn);
        submit_recv(conn_ptr);
```
- Create connection state
- Store in map (ownership transferred)
- Start receiving data from client

#### handle_recv() (Lines 391-417)

```cpp
    void handle_recv(struct io_uring_cqe* cqe, Connection* conn) {
        int bytes = cqe->res;
        if (bytes <= 0) {
            submit_close(conn);
            return;
        }
```
- **bytes <= 0**: Connection closed by client, or error

```cpp
        conn->recv_buffer.append(conn->temp_recv, bytes);
```
- Append received data to connection's receive buffer

```cpp
        if (conn->recv_buffer.size() > MAX_REQUEST_SIZE) {
            conn->send_buffer = "HTTP/1.1 413 Payload Too Large\r\n...";
            conn->keep_alive = false;
            submit_send(conn);
            return;
        }
```
- **Security**: Reject requests larger than 1MB

```cpp
        if (!try_process_request(conn)) {
            submit_recv(conn);  // Need more data
        }
```
- If request not complete, continue receiving

#### try_process_request() (Lines 419-455)

```cpp
    bool try_process_request(Connection* conn) {
        size_t header_end = conn->recv_buffer.find("\r\n\r\n");
        if (header_end == std::string::npos) {
            return false;  // Headers not complete
        }
```
- HTTP headers end with `\r\n\r\n`

```cpp
        size_t content_len = 0;
        // ... parse Content-Length
        size_t total_size = header_end + 4 + content_len;
        if (conn->recv_buffer.size() < total_size) {
            return false;  // Body not complete
        }
```
- Calculate total request size and check if all data received

```cpp
        std::string request = conn->recv_buffer.substr(0, total_size);
        conn->recv_buffer.erase(0, total_size);
```
- Extract complete request
- **Important**: Erase processed request from buffer (supports pipelining)

```cpp
        auto [response, keep_alive] = process_http_request(request);
        conn->send_buffer = std::move(response);
        conn->bytes_sent = 0;
        conn->keep_alive = keep_alive;
        submit_send(conn);
        return true;
```
- Process request, prepare response, start sending

#### handle_send() (Lines 457-488)

```cpp
        conn->bytes_sent += bytes;
        if (conn->bytes_sent < conn->send_buffer.size()) {
            submit_send(conn);  // Partial send, continue
            return;
        }
```
- Track progress; if not all data sent, continue

```cpp
        conn->send_buffer.clear();
        conn->bytes_sent = 0;

        if (conn->keep_alive) {
            if (!conn->recv_buffer.empty() && try_process_request(conn)) {
                return;  // Pipelining: process next request
            }
            submit_recv(conn);  // Wait for more requests
        } else {
            submit_close(conn);
        }
```
- **Pipelining**: If more data in buffer, try to process immediately
- **Keep-alive**: Wait for next request
- **Close**: End connection

#### handle_close() (Lines 490-494)

```cpp
    void handle_close(struct io_uring_cqe* cqe, Connection* conn) {
        (void)cqe;  // Suppress unused warning
        connections.erase(conn->fd);
    }
```
- Removes connection from map
- `unique_ptr` destructor frees the Connection object

### Public Interface (Lines 496-624)

#### Constructor/Destructor (Lines 497-504)

```cpp
    IoUringServer() : server_fd(-1) {}
```
- Initialize server_fd to invalid value

```cpp
    ~IoUringServer() {
        if (server_fd >= 0) {
            close(server_fd);
        }
        io_uring_queue_exit(&ring);
    }
```
- Close server socket if open
- **`io_uring_queue_exit`**: Frees io_uring resources

#### init() (Lines 506-553)

```cpp
        int ret = io_uring_queue_init(QUEUE_DEPTH, &ring, 0);
```
- **`io_uring_queue_init`**: Creates io_uring instance
- **QUEUE_DEPTH**: 256 entries
- **0**: No special flags

```cpp
        server_fd = socket(AF_INET, SOCK_STREAM, 0);
```
- **AF_INET**: IPv4
- **SOCK_STREAM**: TCP

```cpp
        int reuse = 1;
        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
```
- **SO_REUSEADDR**: Allow immediate rebind after restart
- Without this, "Address already in use" error for ~60 seconds

```cpp
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;  // 0.0.0.0
        addr.sin_port = htons(4221);
```
- **INADDR_ANY**: Accept connections on all network interfaces
- **htons**: Convert port to network byte order (big-endian)

```cpp
        bind(server_fd, (struct sockaddr*)&addr, sizeof(addr));
        listen(server_fd, 128);
```
- **bind**: Associate socket with address/port
- **listen**: Mark socket as accepting connections
- **128**: Backlog (max pending connections)

#### run() - Main Event Loop (Lines 555-624)

```cpp
        submit_accept();  // Initial accept
```
- Start by submitting the first accept operation

```cpp
        while (!g_shutdown_requested.load()) {
            io_uring_submit(&ring);
```
- **`io_uring_submit`**: Push all pending SQEs to kernel

```cpp
            struct __kernel_timespec ts;
            ts.tv_sec = 1;
            ts.tv_nsec = 0;
            int ret = io_uring_wait_cqe_timeout(&ring, &cqe, &ts);
```
- **Wait with 1-second timeout**: Allows periodic shutdown check
- **`__kernel_timespec`**: Kernel's timespec structure (64-bit on all platforms)

```cpp
            if (ret == -ETIME) {
                continue;  // Timeout, loop to check shutdown
            }
```
- **-ETIME**: Timeout expired, no completions

```cpp
            unsigned head{};
            unsigned count{};
            io_uring_for_each_cqe(&ring, head, cqe) {
```
- **`io_uring_for_each_cqe`**: Macro that iterates all available CQEs
- **head**: Internal iterator state

```cpp
                UserData* data = static_cast<UserData*>(io_uring_cqe_get_data(cqe));
                switch (data->op) {
                    // ... dispatch to handlers
                    delete data;  // Free per-operation UserData
                }
                ++count;
            }
            io_uring_cq_advance(&ring, count);
```
- **`io_uring_cqe_get_data`**: Retrieves the UserData we attached
- **`io_uring_cq_advance`**: Mark CQEs as consumed (frees slots)

```cpp
        // Cleanup after shutdown
        for (auto& [fd, conn] : connections) {
            close(fd);
        }
        connections.clear();
```
- Close all open connections on shutdown

---

## Main Function (Lines 627-650)

```cpp
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;
```
- **unitbuf**: Flush after every output operation
- Ensures logs appear immediately (important for debugging)

```cpp
    if (argc > 2 && (std::string(argv[1]).compare("--directory") == 0)) {
        g_files_dir = argv[2];
    }
```
- Parse `--directory /path/to/files` argument

```cpp
    setup_signal_handlers();
    IoUringServer server;
    if (!server.init()) {
        return 1;
    }
    server.run();
```
- Setup signals
- Initialize server (socket, io_uring)
- Enter main event loop

---

## Key io_uring Concepts Summary

| Function | Purpose |
|----------|---------|
| `io_uring_queue_init` | Create the io_uring instance |
| `io_uring_get_sqe` | Get a free Submission Queue Entry |
| `io_uring_prep_*` | Prepare an operation (accept/recv/send/close) |
| `io_uring_sqe_set_data` | Attach user data for identification |
| `io_uring_submit` | Push SQEs to kernel |
| `io_uring_wait_cqe_timeout` | Wait for completions |
| `io_uring_for_each_cqe` | Iterate completed operations |
| `io_uring_cqe_get_data` | Retrieve attached user data |
| `io_uring_cq_advance` | Mark CQEs as consumed |
| `io_uring_queue_exit` | Cleanup io_uring |

---

## Flow Diagram

```
                    ┌─────────────────────────────────────┐
                    │            Main Loop                │
                    └─────────────────────────────────────┘
                                    │
          ┌─────────────────────────┼─────────────────────────┐
          │                         │                         │
          ▼                         ▼                         ▼
   submit_accept()           submit_recv()             submit_send()
          │                         │                         │
          ▼                         ▼                         ▼
   ┌──────────────┐         ┌──────────────┐         ┌──────────────┐
   │   Kernel     │         │   Kernel     │         │   Kernel     │
   │  processes   │         │  processes   │         │  processes   │
   │   accept     │         │    recv      │         │    send      │
   └──────────────┘         └──────────────┘         └──────────────┘
          │                         │                         │
          ▼                         ▼                         ▼
   handle_accept()           handle_recv()             handle_send()
          │                         │                         │
          │                         ▼                         │
          │                try_process_request()              │
          │                         │                         │
          │                         ▼                         │
          │              process_http_request()               │
          │                         │                         │
          └─────────────────────────┴─────────────────────────┘
```

---

## Verification

To test the implementation:

```bash
# Build
cmake -DUSE_IOURING=ON -B build
cmake --build build

# Run server
./build/src/main_iouring --directory /tmp/files

# Test endpoints
curl http://localhost:4221/
curl http://localhost:4221/echo/hello
curl http://localhost:4221/user-agent
curl -X POST http://localhost:4221/files/test.txt -d "content"
curl http://localhost:4221/files/test.txt

# Test compression
curl -H "Accept-Encoding: gzip" http://localhost:4221/echo/hello | gunzip

# Test keep-alive
curl -v --keepalive-time 5 http://localhost:4221/
```
