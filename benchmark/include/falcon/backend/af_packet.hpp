#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "falcon/core/backend.hpp"
#include "falcon/core/layer.hpp"

namespace falcon {

// AF_PACKET backend: raw layer-2 socket. Every frame is a full Ethernet frame
// (MACs + ethertype + IP + TCP/UDP), so kFrameLayer = kL2Ethernet and the
// shared parser finally runs live.
class AfPacketBackend : public PacketIO<AfPacketBackend> {
public:
    static constexpr FrameLayer kFrameLayer = FrameLayer::kL2Ethernet;

    explicit AfPacketBackend(const std::string& ifname);
    ~AfPacketBackend();

    AfPacketBackend(const AfPacketBackend&) = delete;
    AfPacketBackend& operator=(const AfPacketBackend&) = delete;

    size_t recvImpl(Frame* out, size_t max);
    const PacketStats& statsImpl() const;
    uint64_t kernelDrops() const;

private:
    static constexpr size_t kBlockSize = 1 << 20;
    static constexpr size_t kBlockCount = 64;
    static constexpr size_t kFrameSize = 2048;
    static constexpr uint32_t kBlockRetireMs = 0;

    int fd_ = -1;
    int epoll_fd_ = -1;
    uint8_t* ring_ = nullptr;
    size_t ring_len_ = 0;
    size_t block_index_ = 0;
    uint32_t packet_index_ = 0;
    uint32_t packets_in_block_ = 0;
    uint32_t packet_offset_ = 0;
    bool release_block_ = false;

    PacketStats stats_;
};

} // namespace falcon
