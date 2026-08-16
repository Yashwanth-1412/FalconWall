#include "falcon/backend/socket.hpp"

#include <algorithm>
#include <cstring>
#include <cerrno>
#include <stdexcept>
#include <string>
#include <fcntl.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

namespace falcon {

SocketBackend::SocketBackend(uint16_t port) {
    
    // UDP SOCKET
    fd_ = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd_ < 0){
        throw std::runtime_error("socket() failed: " + std::string(std::strerror(errno)));
    }

    int flags = fcntl(fd_, F_GETFL, 0);
    fcntl(fd_, F_SETFL, flags | O_NONBLOCK);

    // BIND
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd_, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) < 0) {
        throw std::runtime_error("bind() failed: " + std::string(std::strerror(errno)));
    }

    // EPOLL
    epoll_fd_ = epoll_create1(0);
    if (epoll_fd_ < 0){
        throw std::runtime_error("epoll_create1() failed: " + std::string(std::strerror(errno)));
    }

    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = fd_;
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd_, &ev) < 0) {
        throw std::runtime_error("epoll_ctl() failed: " + std::string(std::strerror(errno)));
    }

    // ── 4. one contiguous slab, sliced into kBATCH slots ───────────────────
    buffer_.resize(kBATCH * kBUFSIZE);

    iovs_.resize(kBATCH);
    msgs_.resize(kBATCH);
    for (size_t i = 0; i < kBATCH; ++i) {
        iovs_[i].iov_base = buffer_.data() + i * kBUFSIZE;
        iovs_[i].iov_len  = kBUFSIZE;
        msgs_[i].msg_hdr.msg_iov = &iovs_[i];
        msgs_[i].msg_hdr.msg_iovlen = 1;
    }
}

SocketBackend::~SocketBackend() {
    if (epoll_fd_ >= 0) close(epoll_fd_);
    if (fd_ >= 0) close(fd_);
}

size_t SocketBackend::recvImpl(Frame* out, size_t max) {
    const size_t n = std::min(max, kBATCH);

    epoll_event events[1];
    int ready = epoll_wait(epoll_fd_, events, 1, 100);  // block up to 100ms
    if (ready <= 0){
        return 0;
    }

    // recvmmsg until the socket is empty (EAGAIN) 
    size_t total = 0;
    for (;;) {
        int got = recvmmsg(fd_, msgs_.data(), n, 0, nullptr);
        if (got < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK){
                break;                    // drained
            }
            throw std::runtime_error("recvmmsg() failed: " + std::string(std::strerror(errno)));
        }
        for (int i = 0; i < got; ++i) {
            out[total + i] = Frame(static_cast<uint8_t*>(msgs_[i].msg_hdr.msg_iov[0].iov_base),
                                   msgs_[i].msg_len);
        }
        total += got;
        stats_.packets += got;
        for (int i = 0; i < got; ++i)
            stats_.bytes += msgs_[i].msg_len;
        if (static_cast<size_t>(got) < n){
            break;                        // short read → no more queued
        }
        if (total >= max){
            break;
        }
    }
    return total;
}

const PacketStats& SocketBackend::statsImpl() const {
    return stats_;
}

} // namespace falcon
