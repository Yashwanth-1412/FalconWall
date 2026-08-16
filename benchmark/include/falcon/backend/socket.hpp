#pragma once

#include <cstdint>
#include <vector>
#include <sys/socket.h>
#include <sys/epoll.h>

#include "falcon/core/backend.hpp"
#include "falcon/core/layer.hpp"

namespace falcon {

class SocketBackend : public PacketIO<SocketBackend> {
public:
    static constexpr FrameLayer kFrameLayer = FrameLayer::kL4Payload;
    explicit SocketBackend(uint16_t port);
    ~SocketBackend();

    SocketBackend(const SocketBackend&) = delete;
    SocketBackend& operator=(const SocketBackend&) = delete;

    size_t recvImpl(Frame* out, size_t max);
    const PacketStats& statsImpl() const;

private:
    static constexpr size_t kBATCH   = 64;
    static constexpr size_t kBUFSIZE = 2048;

    int fd_ = -1;
    int epoll_fd_ = -1;

    std::vector<uint8_t> buffer_;
    std::vector<struct iovec> iovs_;
    std::vector<struct mmsghdr> msgs_;

    PacketStats stats_;
};

} // namespace falcon
