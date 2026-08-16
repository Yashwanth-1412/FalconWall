#pragma once

#include <string>
#include <vector>
#include <xdp/xsk.h>

#include "falcon/core/backend.hpp"
#include "falcon/core/layer.hpp"

namespace falcon {

enum class AfXdpMode {
    kCopy,
    kZeroCopy,
};

class AfXdpBackend : public PacketIO<AfXdpBackend> {
public:
    static constexpr FrameLayer kFrameLayer = FrameLayer::kL2Ethernet;

    explicit AfXdpBackend(const std::string& ifname, AfXdpMode mode = AfXdpMode::kCopy,
                          bool generic = false, uint32_t queue_id = 0);
    ~AfXdpBackend();

    AfXdpBackend(const AfXdpBackend&) = delete;
    AfXdpBackend& operator=(const AfXdpBackend&) = delete;

    size_t recvImpl(Frame* out, size_t max);
    const PacketStats& statsImpl() const;
    uint64_t kernelDrops() const;

private:
    static constexpr size_t kChunks    = 8192;
    static constexpr size_t kChunkSize = 2048;
    static constexpr size_t kRingSize  = 8192;

    struct xsk_ring_prod fill_ring_{};
    struct xsk_ring_cons completion_ring_{};
    struct xsk_ring_cons rx_ring_{};
    struct xsk_ring_prod tx_ring_{};
    struct xsk_umem* umem_ = nullptr;
    struct xsk_socket* xsk_ = nullptr;
    void* umem_buf_ = nullptr;
    int ifindex_ = 0;
    int xdp_flags_ = 0;
    int xsk_map_fd_ = -1;
    bool xdp_attached_ = false;

    std::vector<uint64_t> recycle_addrs_;

    PacketStats stats_;
};

} // namespace falcon
