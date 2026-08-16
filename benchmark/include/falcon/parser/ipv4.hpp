#pragma once

#include <cstdint>
#include <cstddef>

namespace falcon {

// IPv4 header — 20 bytes minimum, followed by 0-40 bytes of options (rare).
//
//   ┌──────┬──────┬─────────┬─────────┬──────────┬─────┬──────────┬─────────┐
//   │ v|ihl│ tos  │tot_len  │   id    │ frag_off │ ttl │ protocol │ checksum│
//   ├──────┴──────┴─────────┴─────────┴──────────┴─────┴──────────┴─────────┤
//   │                         src address (4)                              │
//   ├──────────────────────────────────────────────────────────────────────┤
//   │                         dst address (4)                              │
//   └──────────────────────────────────────────────────────────────────────┘
//
// The first byte is really TWO nibbles (4 bits each):
//   version = high nibble (must be 4)
//   ihl     = low nibble  (header length in 32-bit words, so ×4 = bytes)
// ihl is always 5 (→ 20 bytes) unless options are present.
struct Ipv4Hdr {
    uint8_t version_ihl;       // upper 4 bits: version (4); lower 4 bits: ihl (×4 = header len)
    uint8_t tos;               // type of service (QoS/dscp) — mostly ignored in practice
    uint16_t total_len;        // whole datagram length incl. header, big-endian
    uint16_t id;               // fragment id, big-endian
    uint16_t frag_off;         // flags (3 bits) + fragment offset (13 bits), big-endian
    uint8_t ttl;               // time to live, decremented per hop; 0 = drop
    uint8_t protocol;          // payload protocol: 6 = TCP, 17 = UDP, 1 = ICMP
    uint16_t checksum;         // header checksum, big-endian
    uint32_t src;              // source address, big-endian (e.g. 127.0.0.1)
    uint32_t dst;              // dest address, big-endian

    static constexpr size_t kSize = 20;  // fixed header; options would extend this

    uint8_t version() const { return version_ihl >> 4; }
    uint8_t ihl() const      { return version_ihl & 0x0F; }
    size_t  header_len() const { return size_t(ihl()) * 4; }
};

// Well-known protocol numbers (IPv4 "protocol" field).
constexpr uint8_t kProtoIcmp = 1;
constexpr uint8_t kProtoTcp  = 6;
constexpr uint8_t kProtoUdp  = 17;

// Zero-copy parse, same contract as parse_ethernet. Returns pointer to the
// L4 payload (data + header_len), or nullptr if truncated.
inline const uint8_t* parse_ipv4(const uint8_t* data, size_t len, const Ipv4Hdr*& out) {
    if (len < Ipv4Hdr::kSize)
        return nullptr;
    out = reinterpret_cast<const Ipv4Hdr*>(data);
    return data + out->header_len();
}

} // namespace falcon
