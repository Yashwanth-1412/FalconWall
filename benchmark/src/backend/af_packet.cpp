#include "falcon/backend/af_packet.hpp"

#include <cerrno>
#include <cstring>
#include <atomic>
#include <stdexcept>
#include <string>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/filter.h>

namespace falcon {

AfPacketBackend::AfPacketBackend(const std::string& ifname) {
    fd_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd_ < 0) {
        throw std::runtime_error("socket(AF_PACKET) failed: " + std::string(std::strerror(errno)));
    }

    int flags = fcntl(fd_, F_GETFL, 0);
    fcntl(fd_, F_SETFL, flags | O_NONBLOCK);

    int version = TPACKET_V3;
    if (setsockopt(fd_, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) < 0) {
        throw std::runtime_error("PACKET_VERSION failed: " + std::string(std::strerror(errno)));
    }

    int ifindex = if_nametoindex(ifname.c_str());
    if (ifindex == 0) {
        throw std::runtime_error("bad interface name: " + ifname);
    }

    sockaddr_ll addr{};
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = ifindex;
    if (bind(fd_, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) < 0) {
        throw std::runtime_error("bind() failed: " + std::string(std::strerror(errno)));
    }

    // Keep AF_PACKET saturation counts comparable with UDP socket and AF_XDP.
    // Match IPv4/IPv6 UDP packets with destination port 9100 in the kernel.
    const sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IP, 0, 4),
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 23),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, 0, 7),
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 36),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 9100, 6, 5),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IPV6, 0, 4),
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 20),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, 0, 2),
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 56),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 9100, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, 0),
        BPF_STMT(BPF_RET | BPF_K, 0xFFFFFFFF),
    };
    const sock_fprog program{static_cast<unsigned short>(std::size(filter)),
                             const_cast<sock_filter*>(filter)};
    if (setsockopt(fd_, SOL_SOCKET, SO_ATTACH_FILTER, &program, sizeof(program)) < 0) {
        throw std::runtime_error("SO_ATTACH_FILTER failed: " + std::string(std::strerror(errno)));
    }

    tpacket_req3 req{};
    req.tp_block_size = kBlockSize;
    req.tp_block_nr = kBlockCount;
    req.tp_frame_size = kFrameSize;
    req.tp_frame_nr = (kBlockSize * kBlockCount) / kFrameSize;
    req.tp_retire_blk_tov = kBlockRetireMs;
    if (setsockopt(fd_, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0) {
        throw std::runtime_error("PACKET_RX_RING failed: " + std::string(std::strerror(errno)));
    }

    ring_len_ = kBlockSize * kBlockCount;
    ring_ = static_cast<uint8_t*>(mmap(nullptr, ring_len_, PROT_READ | PROT_WRITE,
                                       MAP_SHARED | MAP_POPULATE, fd_, 0));
    if (ring_ == MAP_FAILED) {
        ring_ = nullptr;
        throw std::runtime_error("mmap(PACKET_RX_RING) failed: " + std::string(std::strerror(errno)));
    }

    epoll_fd_ = epoll_create1(0);
    if (epoll_fd_ < 0) {
        throw std::runtime_error("epoll_create1() failed: " + std::string(std::strerror(errno)));
    }

    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = fd_;
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd_, &ev) < 0) {
        throw std::runtime_error("epoll_ctl() failed: " + std::string(std::strerror(errno)));
    }

}

AfPacketBackend::~AfPacketBackend() {
    if (epoll_fd_ >= 0) {
        close(epoll_fd_);
    }
    if (ring_) {
        munmap(ring_, ring_len_);
    }
    if (fd_ >= 0) {
        close(fd_);
    }
}

size_t AfPacketBackend::recvImpl(Frame* out, size_t max) {
    if (release_block_) {
        auto* block = reinterpret_cast<tpacket_block_desc*>(ring_ + block_index_ * kBlockSize);
        std::atomic_ref<uint32_t> status(block->hdr.bh1.block_status);
        status.store(TP_STATUS_KERNEL, std::memory_order_release);
        block_index_ = (block_index_ + 1) % kBlockCount;
        release_block_ = false;
    }

    size_t total = 0;
    while (total < max) {
        auto* block = reinterpret_cast<tpacket_block_desc*>(ring_ + block_index_ * kBlockSize);
        std::atomic_ref<uint32_t> status(block->hdr.bh1.block_status);
        if ((status.load(std::memory_order_acquire) & TP_STATUS_USER) == 0) {
            if (total != 0) {
                break;
            }

            epoll_event events[1];
            if (epoll_wait(epoll_fd_, events, 1, 100) <= 0) {
                break;
            }
            continue;
        }

        if (packet_index_ == 0) {
            packets_in_block_ = block->hdr.bh1.num_pkts;
            packet_offset_ = block->hdr.bh1.offset_to_first_pkt;
        }

        auto* packet = reinterpret_cast<tpacket3_hdr*>(
            reinterpret_cast<uint8_t*>(block) + packet_offset_);
        out[total++] = Frame(reinterpret_cast<uint8_t*>(packet) + packet->tp_mac,
                             packet->tp_snaplen);
        stats_.packets++;
        stats_.bytes += packet->tp_snaplen;

        packet_index_++;
        packet_offset_ += packet->tp_next_offset;
        if (packet_index_ == packets_in_block_) {
            // Keep Frame pointers valid for the caller until its next recv().
            release_block_ = true;
            packet_index_ = 0;
            packets_in_block_ = 0;
            packet_offset_ = 0;
            break;
        }
    }
    return total;
}

const PacketStats& AfPacketBackend::statsImpl() const {
    return stats_;
}

uint64_t AfPacketBackend::kernelDrops() const {
    tpacket_stats_v3 statistics{};
    socklen_t length = sizeof(statistics);
    if (getsockopt(fd_, SOL_PACKET, PACKET_STATISTICS, &statistics, &length) < 0) {
        throw std::runtime_error("get PACKET_STATISTICS failed: " + std::string(std::strerror(errno)));
    }
    return statistics.tp_drops;
}

} // namespace falcon
