# HTTP Server

## Build

```bash
# To use io_uring based implementation
cmake -DUSE_IOURING=ON -B build
# To use thread pool based implementation
cmake -DUSE_IOURING=OFF -B build

cmake --build build
```

## Run

```
# run the io_uring version
./build/src/main_iouring --directory /path/to/files

# run the threadpool-based version
./build/src/main --directory /path/to/files
```
