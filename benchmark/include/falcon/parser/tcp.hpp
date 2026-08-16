#pragma once

#include <cstdint>
#include <cstddef>

namespace falcon {

// TCP header — 20 bytes minimum, followed by 0-40 bytes of options.
//
//   ┌─────────┬─────────┬──────────────┬──────────────┐
//   │src_port │dst_port │    seq #     │    ack #     │
//   ├─────────┴─────────┴──────────────┴──────────────┤
//   │ offset │ flags(2)│   window      │  checksum    │
//   ├─────────────────────────────────────────────────┤
//   │                     urgent ptr                  │
//   └─────────────────────────────────────────────────┘
//
// Byte 12 holds TWO things: high nibble = data offset (×4 = header length,
// min 5 → 20 bytes), low nibble = reserved(3 bits) + NS flag(1 bit).
// Byte 13 = the 8 control flags: CWR ECE URG ACK PSH RST SYN FIN.
struct TcpHdr {
    uint16_t src_port;         // source port, big-endian
    uint16_t dst_port;         // dest port, big-endian
    uint32_t seq;              // sequence number, big-endian
    uint32_t ack;              // acknowledgment number, big-endian
    uint8_t  offset_ns;        // high nibble = data offset (×4); low bit = NS flag
    uint8_t  flags;            // CWR ECE URG ACK PSH RST SYN FIN (bit0..bit7 order)
    uint16_t window;           // receive window size, big-endian
    uint16_t checksum;         // covers header + payload + pseudo-header
    uint16_t urg_ptr;          // urgent data pointer, big-endian

    static constexpr size_t kSize = 20;

    // Bit masks for the flags byte.
    static constexpr uint8_t kFin = 0x01;
    static constexpr uint8_t kSyn = 0x02;
    static constexpr uint8_t kRst = 0x04;
    static constexpr uint8_t kPsh = 0x08;
    static constexpr uint8_t kAck = 0x10;
    static constexpr uint8_t kUrg = 0x20;

    uint8_t  data_offset() const { return offset_ns >> 4; }
    size_t   header_len() const  { return size_t(data_offset()) * 4; }
};

// Zero-copy parse, same contract as before.
inline const uint8_t* parse_tcp(const uint8_t* data, size_t len, const TcpHdr*& out) {
    if (len < TcpHdr::kSize)
        return nullptr;
    out = reinterpret_cast<const TcpHdr*>(data);
    return data + out->header_len();
}

} // namespace falcon
