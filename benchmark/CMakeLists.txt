cmake_minimum_required(VERSION 3.15)
project(Falcon VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_FLAGS "-O3 -march=native -Wall -Wextra")

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBXDP REQUIRED IMPORTED_TARGET libxdp)
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)
find_program(CLANG_EXECUTABLE clang REQUIRED)

set(FALCON_XDP_OBJECT ${CMAKE_CURRENT_BINARY_DIR}/af_xdp.bpf.o)
add_custom_command(
    OUTPUT ${FALCON_XDP_OBJECT}
    COMMAND ${CLANG_EXECUTABLE} -target bpf -O2 -g -c
            -I/usr/include/${CMAKE_LIBRARY_ARCHITECTURE}
            ${CMAKE_CURRENT_SOURCE_DIR}/src/backend/af_xdp.bpf.c
            -o ${FALCON_XDP_OBJECT}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/backend/af_xdp.bpf.c
)
add_custom_target(falcon-xdp-program DEPENDS ${FALCON_XDP_OBJECT})

# ── Falcon core library ────────────────────────────────────────────────────────
#
#  Backend-agnostic packet I/O framework.
#  Public API lives in include/falcon; headers are installed/exported so the
#  bench + demo tools only consume the public interface.
add_library(falcon STATIC
    src/core/stats.cpp
    src/backend/socket.cpp
    src/backend/af_packet.cpp
    src/backend/af_xdp.cpp
)

add_dependencies(falcon falcon-xdp-program)

target_include_directories(falcon PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(falcon PUBLIC PkgConfig::LIBXDP PkgConfig::LIBBPF)
target_compile_definitions(falcon PRIVATE FALCON_XDP_OBJECT_PATH="${FALCON_XDP_OBJECT}")

# ── falcon-bench ──────────────────────────────────────────────────────────────
#
#  xdp-bench-style benchmark harness: measures pps + latency over a stats
#  window for any PacketIO backend. Benchmarks are wired in Milestone 4.
add_executable(falcon-bench
    bench/bench_main.cpp
)

target_include_directories(falcon-bench PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(falcon-bench PRIVATE falcon)

# ── falcon-rxbench ───────────────────────────────────────────────────────────
#
# Throughput-only receiver for external generators such as xdp-trafficgen.
add_executable(falcon-rxbench
    bench/rx_bench.cpp
)

target_link_libraries(falcon-rxbench PRIVATE falcon)

add_executable(falcon-validate
    bench/validate.cpp
)

target_link_libraries(falcon-validate PRIVATE falcon)

# ── falcon-rxbench-mq ─────────────────────────────────────────────────────────
#
# Multi-queue throughput benchmark with CPU metrics.
add_executable(falcon-rxbench-mq
    bench/rx_bench_mq.cpp
)

target_link_libraries(falcon-rxbench-mq PRIVATE falcon)

message(STATUS "Targets: falcon | falcon-bench | falcon-rxbench | falcon-rxbench-mq | falcon-validate")
