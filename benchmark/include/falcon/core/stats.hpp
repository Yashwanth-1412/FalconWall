#pragma once

#include <cstdint>

namespace falcon {

// Per-backend packet counters. Every PacketIO implementation updates these so
// the benchmark harness can compute pps and byte throughput without knowing
// which backend it is talking to.
struct PacketStats {
    std::uint64_t packets{0};
    std::uint64_t bytes{0};
    std::uint64_t drops{0};
};

} // namespace falcon
