// Throughput-only receiver for controlled external packet generators.
// It intentionally does not parse, timestamp, retain, or copy received frames.

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <type_traits>

#include "falcon/backend/af_packet.hpp"
#include "falcon/backend/af_xdp.hpp"
#include "falcon/backend/socket.hpp"

namespace {

using Clock = std::chrono::steady_clock;
constexpr size_t kBatchSize = 2048;

template <typename Backend>
int run(const std::string& target, double seconds, uint64_t expected_packets,
        falcon::AfXdpMode xdp_mode = falcon::AfXdpMode::kCopy) {
    Backend backend = [&] {
        if constexpr (std::is_same_v<Backend, falcon::SocketBackend>) {
            return Backend(static_cast<uint16_t>(std::strtoul(target.c_str(), nullptr, 10)));
        } else if constexpr (std::is_same_v<Backend, falcon::AfXdpBackend>) {
            return Backend(target, xdp_mode);
        } else {
            return Backend(target);
        }
    }();

    std::array<falcon::Frame, kBatchSize> frames;
    uint64_t packets = 0;
    uint64_t bytes = 0;
    uint64_t window_packets = 0;
    uint64_t window_bytes = 0;
    bool started = false;
    Clock::time_point start;
    Clock::time_point window_start;

    while (true) {
        const size_t received = backend.recv(frames.data(), frames.size());
        if (received != 0 && !started) {
            started = true;
            start = Clock::now();
            window_start = start;
        }
        if (!started) {
            continue;
        }
        packets += received;
        window_packets += received;
        for (size_t i = 0; i < received; ++i) {
            bytes += frames[i].len_;
            window_bytes += frames[i].len_;
        }

        const auto now = Clock::now();
        const double window_seconds = std::chrono::duration<double>(now - window_start).count();
        if (window_seconds >= 1.0) {
            std::printf("%.3f,%.0f,%.3f\n", std::chrono::duration<double>(now - start).count(),
                        window_packets / window_seconds,
                        window_bytes * 8.0 / window_seconds / 1e9);
            window_packets = 0;
            window_bytes = 0;
            window_start = now;
        }
        if ((expected_packets != 0 && packets >= expected_packets) ||
            std::chrono::duration<double>(now - start).count() >= seconds) {
            const double elapsed = std::chrono::duration<double>(now - start).count();
            uint64_t kernel_drops = 0;
            if constexpr (!std::is_same_v<Backend, falcon::SocketBackend>) {
                kernel_drops = backend.kernelDrops();
            }
            std::printf("total,%.0f,%.3f\n", packets / elapsed, bytes * 8.0 / elapsed / 1e9);
            std::printf("packets,%llu\nbytes,%llu\nkernel_drops,%llu\n",
                        static_cast<unsigned long long>(packets),
                        static_cast<unsigned long long>(bytes),
                        static_cast<unsigned long long>(kernel_drops));
            if (expected_packets != 0) {
                std::printf("offered_packets,%llu\nlost_packets,%llu\n",
                            static_cast<unsigned long long>(expected_packets),
                            static_cast<unsigned long long>(expected_packets > packets
                                ? expected_packets - packets : 0));
            }
            return 0;
        }
    }
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 4 && argc != 5) {
        std::fprintf(stderr, "usage: falcon-rxbench socket <port> <seconds>\n"
                             "       falcon-rxbench packet <interface> <seconds>\n"
                             "       falcon-rxbench xdp <interface> <seconds>\n"
                             "       falcon-rxbench xdp-zc <interface> <seconds>\n"
                             "       append [expected_packets] for a controlled finite run\n");
        return 1;
    }

    const std::string backend = argv[1];
    const std::string target = argv[2];
    const double seconds = std::atof(argv[3]);
    const uint64_t expected_packets = argc == 5 ? std::strtoull(argv[4], nullptr, 10) : 0;
    if (seconds <= 0.0) {
        std::fprintf(stderr, "seconds must be positive\n");
        return 1;
    }

    try {
        std::puts("elapsed_s,pps,gbit_s");
        if (backend == "socket") {
            return run<falcon::SocketBackend>(target, seconds, expected_packets);
        }
        if (backend == "packet") {
            return run<falcon::AfPacketBackend>(target, seconds, expected_packets);
        }
        if (backend == "xdp") {
            return run<falcon::AfXdpBackend>(target, seconds, expected_packets);
        }
        if (backend == "xdp-zc") {
            return run<falcon::AfXdpBackend>(target, seconds, expected_packets,
                                             falcon::AfXdpMode::kZeroCopy);
        }
        std::fprintf(stderr, "unknown backend: %s\n", backend.c_str());
        return 1;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "falcon-rxbench: %s\n", error.what());
        return 1;
    }
}
