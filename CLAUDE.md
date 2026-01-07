# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Context

Whenever working with this codebase (or any codebase), ALWAYS ask me first about any changes or modifications you are trying to make, and do NOT make those changes without me explicitly allowing so.

ALWAYS show me the code/implemention without me having to type `/plan` myself.

## Project Overview

C++23 HTTP server with multi-threaded connection handling. Uses a thread pool pattern with `std::jthread` and `std::stop_token` for graceful shutdown.

## Build Commands

```bash
# Enter Nix development environment
nix develop

# Build with CMake
cmake . -B build
cmake --build build

# Run the server (listens on port 4221)
./build/src/main

# Run with file serving enabled
./build/src/main --directory /path/to/files

# Enable and run tests (GTest)
cmake -DENABLE_TESTING=ON -B build
cmake --build build
ctest --test-dir build
```

## Architecture

**Threading Model**: Main thread accepts connections → ThreadPool distributes to worker threads → Each worker calls `handle_client()`

**HTTP Endpoints** (in `src/main.cpp`):

- `/` - Returns 200 OK
- `/echo/<string>` - Echoes back the path segment
- `/user-agent` - Returns the User-Agent header value
- `/files/<filename>` - Serves files from `--directory` path (rejects path traversal)

**Key Components** (all in `src/main.cpp`):

- `ThreadPool` class (lines 48-125): Worker thread pool with task queue
- `handle_client()` (lines 128-196): HTTP request parsing and routing
- `main()` (lines 198-275): Socket setup, accept loop, signal handling

## Development Environment

- **Language**: C++23 (required standard)
- **Build System**: CMake 3.29+
- **Package Manager**: Nix Flakes
- **Test Framework**: Google Test (GTest), Catch2 v3 available
- **Code Style**: Google style, 4-space indent (see `.clang-format`)

## Compiler Configuration

- Compiler: GCC
- Flags: `-Wall -Wfatal-errors -Wextra -Werror -g -O1`

## Dependencies

Available via Nix flake: Boost, SDL2 (with image/gfx/ttf/mixer), Lua 5.4, Sol2 (Lua C++ bindings)
