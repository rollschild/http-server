# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

C++23 HTTP server project in early development. Build infrastructure is configured but source implementation is pending.

## Build Commands

```bash
# Enter Nix development environment
nix develop

# Build with CMake
# this will create the `build/` folder for you
cmake . -B build
cmake --build build

# Enable and run tests (GTest)
cmake -DENABLE_TESTING=ON ..
cmake --build .
ctest
```

## Development Environment

- **Language**: C++23 (required standard)
- **Build System**: CMake 3.29+
- **Package Manager**: Nix Flakes
- **Test Framework**: Google Test (GTest), Catch2 v3 available

## Compiler Configuration

- Compiler: GCC
- Flags: `-Wall -Wfatal-errors -Wextra -Werror -g -O1`

## Dependencies

Available via Nix flake: Boost, SDL2 (with image/gfx/ttf/mixer), Lua 5.4, Sol2 (Lua C++ bindings)
