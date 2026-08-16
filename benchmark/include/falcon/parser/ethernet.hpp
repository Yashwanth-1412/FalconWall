#pragma once

#include <cstdint>
#include <cstddef>

namespace falcon {

// Ethernet II header — 14 bytes, the first thing on every L2 frame.
//
// Wire layout (network byte order for multi-byte fields):
//
//   ┌───────────────┬───────────────┬─────────────┐
//   │ dst MAC (6)   │ src MAC (6)   │ ethertype(2)│
//   └───────────────┴───────────────┴─────────────┘
//
// MAC addresses are 6 raw bytes (no endianness — they're an address, not a number).
// ethertype says what the payload is: 0x0800 = IPv4, 0x0806 = ARP, 0x86DD = IPv6.
struct EtherHdr {
    uint8_t dst_mac[6];        // destination MAC, e.g. ff:ff:ff:ff:ff:ff = broadcast
    uint8_t src_mac[6];        // source MAC
    uint16_t ethertype;        // payload type, big-endian → read with ntohs()

    static constexpr size_t kSize = 14;  // 6 + 6 + 2, no padding
};

// Well-known ethertype values (host byte order, as you'd compare after ntohs()).
constexpr uint16_t kEthTypeIpv4 = 0x0800;
constexpr uint16_t kEthTypeArp  = 0x0806;
constexpr uint16_t kEthTypeIpv6 = 0x86DD;

// Zero-copy parse. On success: out points at the header *in place* (no copy),
// returns a pointer to the payload (data + 14) for the next layer to parse.
// Returns nullptr if the buffer is too short — never read past what you have.
inline const uint8_t* parse_ethernet(const uint8_t* data, size_t len, const EtherHdr*& out) {
    if (len < EtherHdr::kSize)
        return nullptr;
    out = reinterpret_cast<const EtherHdr*>(data);
    return data + EtherHdr::kSize;
}

} // namespace falcon
