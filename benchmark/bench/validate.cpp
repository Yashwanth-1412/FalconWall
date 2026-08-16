// Sequenced correctness validation. Keep this separate from falcon-rxbench.

#include <array>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <endian.h>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "falcon/backend/af_packet.hpp"
#include "falcon/backend/af_xdp.hpp"
#include "falcon/backend/socket.hpp"
#include "falcon/parser/ethernet.hpp"
#include "falcon/parser/ipv4.hpp"
#include "falcon/parser/udp.hpp"

namespace {

constexpr uint32_t kMagic = 0x46414C43;  // "FALC"
constexpr size_t kBatchSize = 256;

struct __attribute__((packed)) ValidationHeader {
    uint32_t magic;
    uint64_t sequence;
    uint32_t reserved;
};

const uint8_t* payload(const uint8_t* data, size_t length, falcon::FrameLayer layer,
                       size_t& payload_length) {
    if (layer == falcon::FrameLayer::kL4Payload) {
        payload_length = length;
        return data;
    }

    const falcon::EtherHdr* ethernet;
    const uint8_t* cursor = falcon::parse_ethernet(data, length, ethernet);
    if (!cursor || ntohs(ethernet->ethertype) != falcon::kEthTypeIpv4) {
        return nullptr;
    }
    const falcon::Ipv4Hdr* ip;
    cursor = falcon::parse_ipv4(cursor, length - falcon::EtherHdr::kSize, ip);
    if (!cursor || ip->protocol != falcon::kProtoUdp) {
        return nullptr;
    }
    const falcon::UdpHdr* udp;
    cursor = falcon::parse_udp(cursor, length - falcon::EtherHdr::kSize - ip->header_len(), udp);
    if (!cursor) {
        return nullptr;
    }
    payload_length = ntohs(udp->len) - falcon::UdpHdr::kSize;
    return cursor;
}

template <typename Backend>
int receive(const std::string& target, uint64_t expected, falcon::AfXdpMode mode) {
    Backend backend = [&] {
        if constexpr (std::is_same_v<Backend, falcon::SocketBackend>) {
            return Backend(static_cast<uint16_t>(std::strtoul(target.c_str(), nullptr, 10)));
        } else if constexpr (std::is_same_v<Backend, falcon::AfXdpBackend>) {
            return Backend(target, mode);
        } else {
            return Backend(target);
        }
    }();

    std::vector<bool> seen(expected);
    std::array<falcon::Frame, kBatchSize> frames;
    uint64_t valid = 0;
    uint64_t duplicates = 0;
    uint64_t reordered = 0;
    uint64_t invalid = 0;
    uint64_t highest = 0;
    bool have_highest = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);

    while (std::chrono::steady_clock::now() < deadline && valid < expected) {
        const size_t received = backend.recv(frames.data(), frames.size());
        for (size_t i = 0; i < received; ++i) {
            size_t payload_length = 0;
            const uint8_t* bytes = payload(frames[i].data_, frames[i].len_, Backend::kFrameLayer,
                                           payload_length);
            if (!bytes || payload_length < sizeof(ValidationHeader)) {
                ++invalid;
                continue;
            }
            ValidationHeader header{};
            std::memcpy(&header, bytes, sizeof(header));
            const uint64_t sequence = be64toh(header.sequence);
            if (ntohl(header.magic) != kMagic || sequence >= expected) {
                ++invalid;
                continue;
            }
            if (seen[sequence]) {
                ++duplicates;
                continue;
            }
            if (have_highest && sequence < highest) {
                ++reordered;
            }
            highest = have_highest ? std::max(highest, sequence) : sequence;
            have_highest = true;
            seen[sequence] = true;
            ++valid;
        }
    }

    const uint64_t missing = expected - valid;
    std::printf("expected,%llu\nreceived,%llu\nmissing,%llu\nduplicates,%llu\nreordered,%llu\ninvalid,%llu\n",
                static_cast<unsigned long long>(expected), static_cast<unsigned long long>(valid),
                static_cast<unsigned long long>(missing), static_cast<unsigned long long>(duplicates),
                static_cast<unsigned long long>(reordered), static_cast<unsigned long long>(invalid));
    return (missing == 0 && duplicates == 0 && invalid == 0) ? 0 : 2;
}

int transmit(const std::string& ifname, const std::string& source, const std::string& destination,
             uint64_t count, uint64_t pps) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        throw std::runtime_error("socket failed: " + std::string(std::strerror(errno)));
    }
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname.c_str(), ifname.size()) < 0) {
        throw std::runtime_error("SO_BINDTODEVICE failed: " + std::string(std::strerror(errno)));
    }
    sockaddr_in local{};
    local.sin_family = AF_INET;
    if (inet_pton(AF_INET, source.c_str(), &local.sin_addr) != 1 ||
        bind(fd, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) < 0) {
        throw std::runtime_error("bind source failed: " + std::string(std::strerror(errno)));
    }
    sockaddr_in remote{};
    remote.sin_family = AF_INET;
    remote.sin_port = htons(9100);
    if (inet_pton(AF_INET, destination.c_str(), &remote.sin_addr) != 1) {
        throw std::runtime_error("invalid destination address");
    }

    ValidationHeader header{};
    header.magic = htonl(kMagic);
    const auto interval = std::chrono::nanoseconds(1000000000ULL / pps);
    auto next = std::chrono::steady_clock::now();
    for (uint64_t sequence = 0; sequence < count; ++sequence) {
        header.sequence = htobe64(sequence);
        if (sendto(fd, &header, sizeof(header), 0, reinterpret_cast<const sockaddr*>(&remote),
                   sizeof(remote)) != static_cast<ssize_t>(sizeof(header))) {
            throw std::runtime_error("sendto failed: " + std::string(std::strerror(errno)));
        }
        next += interval;
        std::this_thread::sleep_until(next);
    }
    close(fd);
    std::printf("sent,%llu\n", static_cast<unsigned long long>(count));
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc == 6 && std::string(argv[1]) == "tx") {
            return transmit(argv[2], argv[3], argv[4], std::strtoull(argv[5], nullptr, 10), 10000);
        }
        if (argc != 4) {
            std::fprintf(stderr, "usage: falcon-validate tx <iface> <src-ip> <dst-ip> <count>\n"
                                 "       falcon-validate socket <port> <count>\n"
                                 "       falcon-validate packet|xdp|xdp-zc <iface> <count>\n");
            return 1;
        }
        const std::string backend = argv[1];
        const uint64_t count = std::strtoull(argv[3], nullptr, 10);
        if (backend == "socket") return receive<falcon::SocketBackend>(argv[2], count, falcon::AfXdpMode::kCopy);
        if (backend == "packet") return receive<falcon::AfPacketBackend>(argv[2], count, falcon::AfXdpMode::kCopy);
        if (backend == "xdp") return receive<falcon::AfXdpBackend>(argv[2], count, falcon::AfXdpMode::kCopy);
        if (backend == "xdp-zc") return receive<falcon::AfXdpBackend>(argv[2], count, falcon::AfXdpMode::kZeroCopy);
        std::fprintf(stderr, "unknown backend: %s\n", argv[1]);
        return 1;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "falcon-validate: %s\n", error.what());
        return 1;
    }
}
