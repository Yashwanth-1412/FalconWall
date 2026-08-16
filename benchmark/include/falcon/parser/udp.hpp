#pragma once

#include <cstdint>
#include <cstddef>

namespace falcon {

// UDP header — 8 bytes. Simple: two ports, a length, a checksum.
//
//   ┌───────────┬───────────┬─────────┬──────────┐
//   │ src_port  │ dst_port  │  len    │ checksum │
//   └───────────┴───────────┴─────────┴──────────┘
//
// len = UDP header (8) + payload. checksum is 0 if not computed (common for
// loopback / IPv4). All multi-byte fields are big-endian.
struct UdpHdr {
    uint16_t src_port;         // source port, big-endian → ntohs()
    uint16_t dst_port;         // dest port, big-endian → ntohs()
    uint16_t len;              // header + payload length, big-endian
    uint16_t checksum;         // optional; 0 = unused

    static constexpr size_t kSize = 8;

    size_t payload_len(size_t total) const {
        return total > kSize ? total - kSize : 0;
    }
};

// Zero-copy parse, same contract as before. Returns pointer to the UDP payload.
inline const uint8_t* parse_udp(const uint8_t* data, size_t len, const UdpHdr*& out) {
    if (len < UdpHdr::kSize)
        return nullptr;
    out = reinterpret_cast<const UdpHdr*>(data);
    return data + UdpHdr::kSize;
}

} // namespace falcon
