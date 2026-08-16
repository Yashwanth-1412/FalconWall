#pragma once

#include <cstdint>

namespace falcon {

// At what layer does a backend hand you packet bytes? This is the deepest
// insight of the benchmark matrix: the higher the level, the more the kernel
// already parsed for you.
//
//   POSIX UDP socket  → kL4Payload   (kernel stripped eth+ip+udp; you get data)
//   AF_PACKET         → kL2Ethernet  (raw L2 frame; you parse everything)
//   AF_XDP            → kL2Ethernet  (raw L2 frame; you parse everything)
//
// The pipeline selects its parser at COMPILE TIME via this constant, so
// swapping backends is the only change that matters.
enum class FrameLayer : uint8_t {
    kL2Ethernet = 0,   // raw frame: parse Ethernet → IPv4 → TCP/UDP
    kL4Payload  = 1,   // app payload: nothing left to parse
};

} // namespace falcon
