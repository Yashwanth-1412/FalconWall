#include "falcon/backend/af_xdp.hpp"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <poll.h>
#include <stdexcept>
#include <string>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <net/if.h>

#ifndef FALCON_XDP_OBJECT_PATH
#error "FALCON_XDP_OBJECT_PATH must name the compiled XDP program"
#endif

namespace falcon {

AfXdpBackend::AfXdpBackend(const std::string& ifname, AfXdpMode mode, bool generic, uint32_t queue_id) {
    ifindex_ = static_cast<int>(if_nametoindex(ifname.c_str()));
    if (ifindex_ == 0) {
        throw std::runtime_error("bad interface name: " + ifname);
    }

    xdp_flags_ = generic ? XDP_FLAGS_SKB_MODE : XDP_FLAGS_DRV_MODE;

    bpf_object* object = bpf_object__open_file(FALCON_XDP_OBJECT_PATH, nullptr);
    const long open_error = libbpf_get_error(object);
    if (open_error != 0) {
        throw std::runtime_error("open XDP program failed: " + std::to_string(-open_error));
    }

    if (bpf_object__load(object) != 0) {
        const int error = errno;
        bpf_object__close(object);
        throw std::runtime_error("load XDP program failed: " + std::string(std::strerror(error)));
    }

    bpf_program* program = bpf_object__find_program_by_name(object, "falcon_xdp_redirect");
    bpf_map* xsk_map = bpf_object__find_map_by_name(object, "falcon_xsks");
    if (!program || !xsk_map) {
        bpf_object__close(object);
        throw std::runtime_error("XDP program is missing falcon_xdp_redirect or falcon_xsks");
    }

    int ret = bpf_xdp_attach(ifindex_, bpf_program__fd(program), xdp_flags_, nullptr);
    if (ret != 0) {
        bpf_object__close(object);
        throw std::runtime_error("attach XDP program failed: " + std::string(std::strerror(-ret)));
    }
    xdp_attached_ = true;
    xsk_map_fd_ = bpf_map__fd(xsk_map);

    if (posix_memalign(&umem_buf_, getpagesize(), kChunks * kChunkSize) != 0) {
        bpf_xdp_detach(ifindex_, xdp_flags_, nullptr);
        xdp_attached_ = false;
        bpf_object__close(object);
        throw std::runtime_error("allocate AF_XDP UMEM failed");
    }

    xsk_umem_config umem_config{};
    umem_config.fill_size = kRingSize;
    umem_config.comp_size = kRingSize;
    umem_config.frame_size = kChunkSize;
    ret = xsk_umem__create(&umem_, umem_buf_, kChunks * kChunkSize,
                           &fill_ring_, &completion_ring_, &umem_config);
    if (ret != 0) {
        std::free(umem_buf_);
        umem_buf_ = nullptr;
        bpf_xdp_detach(ifindex_, xdp_flags_, nullptr);
        xdp_attached_ = false;
        bpf_object__close(object);
        throw std::runtime_error("create AF_XDP UMEM failed: " + std::string(std::strerror(-ret)));
    }

    xsk_socket_config config{};
    config.rx_size = kRingSize;
    config.tx_size = kRingSize;
    config.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD;
    config.xdp_flags = xdp_flags_;
    config.bind_flags = (mode == AfXdpMode::kCopy ? XDP_COPY : XDP_ZEROCOPY) | XDP_USE_NEED_WAKEUP;
    ret = xsk_socket__create(&xsk_, ifname.c_str(), queue_id, umem_, &rx_ring_, &tx_ring_, &config);
    if (ret != 0) {
        xsk_umem__delete(umem_);
        umem_ = nullptr;
        std::free(umem_buf_);
        umem_buf_ = nullptr;
        bpf_xdp_detach(ifindex_, xdp_flags_, nullptr);
        xdp_attached_ = false;
        bpf_object__close(object);
        throw std::runtime_error("create AF_XDP socket failed: " + std::string(std::strerror(-ret)));
    }

    ret = xsk_socket__update_xskmap(xsk_, xsk_map_fd_);
    if (ret != 0) {
        xsk_socket__delete(xsk_);
        xsk_ = nullptr;
        xsk_umem__delete(umem_);
        umem_ = nullptr;
        std::free(umem_buf_);
        umem_buf_ = nullptr;
        bpf_xdp_detach(ifindex_, xdp_flags_, nullptr);
        xdp_attached_ = false;
        bpf_object__close(object);
        throw std::runtime_error("register AF_XDP socket in XSKMAP failed: " + std::string(std::strerror(-ret)));
    }

    uint32_t index = 0;
    if (xsk_ring_prod__reserve(&fill_ring_, kChunks, &index) != kChunks) {
        throw std::runtime_error("reserve AF_XDP fill ring failed");
    }
    for (size_t i = 0; i < kChunks; ++i) {
        *xsk_ring_prod__fill_addr(&fill_ring_, index + i) = i * kChunkSize;
    }
    xsk_ring_prod__submit(&fill_ring_, kChunks);

    // libbpf retains object resources through the loaded program and map fds.
    bpf_object__close(object);
}

AfXdpBackend::~AfXdpBackend() {
    if (xsk_) {
        xsk_socket__delete(xsk_);
    }
    if (umem_) {
        xsk_umem__delete(umem_);
    }
    if (umem_buf_) {
        std::free(umem_buf_);
    }
    if (xdp_attached_) {
        bpf_xdp_detach(ifindex_, xdp_flags_, nullptr);
    }
}

size_t AfXdpBackend::recvImpl(Frame* out, size_t max) {
    if (!recycle_addrs_.empty()) {
        uint32_t fill_index = 0;
        const size_t count = xsk_ring_prod__reserve(&fill_ring_, recycle_addrs_.size(), &fill_index);
        for (size_t i = 0; i < count; ++i) {
            *xsk_ring_prod__fill_addr(&fill_ring_, fill_index + i) = recycle_addrs_[i];
        }
        if (count != 0) {
            xsk_ring_prod__submit(&fill_ring_, count);
            recycle_addrs_.erase(recycle_addrs_.begin(), recycle_addrs_.begin() + count);
        }
    }

    uint32_t rx_index = 0;
    const size_t limit = std::min(max, kRingSize);
    size_t received = xsk_ring_cons__peek(&rx_ring_, limit, &rx_index);
    if (received == 0) {
        pollfd poll_fd{};
        poll_fd.fd = xsk_socket__fd(xsk_);
        poll_fd.events = POLLIN;
        if (poll(&poll_fd, 1, 100) <= 0) {
            return 0;
        }
        received = xsk_ring_cons__peek(&rx_ring_, limit, &rx_index);
    }

    recycle_addrs_.reserve(received);
    for (size_t i = 0; i < received; ++i) {
        const xdp_desc* descriptor = xsk_ring_cons__rx_desc(&rx_ring_, rx_index + i);
        out[i] = Frame(static_cast<uint8_t*>(xsk_umem__get_data(umem_buf_, descriptor->addr)),
                       descriptor->len);
        recycle_addrs_.push_back(descriptor->addr);
        stats_.packets++;
        stats_.bytes += descriptor->len;
    }
    xsk_ring_cons__release(&rx_ring_, received);
    return received;
}

const PacketStats& AfXdpBackend::statsImpl() const {
    return stats_;
}

uint64_t AfXdpBackend::kernelDrops() const {
    xdp_statistics statistics{};
    socklen_t length = sizeof(statistics);
    if (getsockopt(xsk_socket__fd(xsk_), SOL_XDP, XDP_STATISTICS, &statistics, &length) < 0) {
        throw std::runtime_error("get AF_XDP statistics failed: " + std::string(std::strerror(errno)));
    }
    return statistics.rx_dropped + statistics.rx_invalid_descs;
}

} // namespace falcon
