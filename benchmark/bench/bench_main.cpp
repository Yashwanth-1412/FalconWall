// falcon-bench — xdp-bench-style benchmark harness.
//
// Runs the SAME workload against a backend selected at compile time and
// reports: throughput (pps), p50/p99 receive latency, and receiver CPU.
//
//   usage: falcon-bench [backend] [port|iface] [seconds] [burst]
//          [netns] [tx_iface] [src_ip] [dst_ip] [payload_bytes]
//          falcon-bench rx [socket|packet|xdp] [port|iface] [seconds] [burst]
//          falcon-bench tx [udp|raw] [port] [seconds] [burst] [iface] [src_ip] [dst_ip] [payload_bytes]
//     backend socket | packet | xdp    (default socket; combined RX + TX)
//     port/iface e.g. 9100, or "lo"    (default 9100)
//     seconds   run duration, default 3
//     burst     if >0: send exactly N packets and stop when all are received
//
// A sender thread embeds an 8-byte nanosecond timestamp in every payload; the
// receiver reads it back and computes per-packet latency = rx - tx. The frame
// layer decides where the timestamp sits (kL4Payload → byte 0; kL2Ethernet →
// after eth/ipv4/udp headers, walked via the shared parser).

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cerrno>
#include <string>
#include <type_traits>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <fcntl.h>
#include <sched.h>
#include <thread>
#include <vector>
#include <unistd.h>
#include <sys/wait.h>

#include "falcon/backend/socket.hpp"
#include "falcon/backend/af_packet.hpp"
#include "falcon/backend/af_xdp.hpp"
#include "falcon/core/frame.hpp"
#include "falcon/core/layer.hpp"
#include "falcon/parser/ethernet.hpp"
#include "falcon/parser/ipv4.hpp"
#include "falcon/parser/udp.hpp"

using Clock = std::chrono::steady_clock;

namespace {

struct BenchCfg {
    uint16_t port = 9100;
    std::string ifname = "lo";
    std::string tx_netns;                // optional network namespace for the sender thread
    std::string tx_iface;                // raw-send interface (veth peer); empty = UDP loopback
    std::string src_ip = "10.0.0.2";     // source IP used in crafted frames
    std::string dst_ip = "10.0.0.1";     // dest IP used in crafted frames
    size_t payload_size = 16;             // includes the 8-byte timestamp
    double seconds = 3.0;
    uint64_t burst = 0;          // 0 = continuous for `seconds`
    double window_sec = 1.0;     // print stats every window
    bool raw_tx = false;
};

struct BenchResult {
    uint64_t packets = 0;
    uint64_t bytes = 0;
    double seconds = 0;
    double pps = 0;
    double p50_ns = 0;
    double p99_ns = 0;
    double cpu_pct = 0;
};

uint64_t now_ns() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               Clock::now().time_since_epoch())
        .count();
}

double thread_cpu_ns() {
    timespec ts{};
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    return ts.tv_sec * 1e9 + ts.tv_nsec;
}

// Pull the sender's 8-byte nanosecond timestamp out of a frame. Where it
// lives depends on the backend's layer: at byte 0 (kL4Payload) or after the
// eth/ipv4/udp headers (kL2Ethernet). Returns 0 if it can't be located.
template <class Backend>
uint64_t frame_ts(const uint8_t* data, size_t len) {
    if constexpr (Backend::kFrameLayer == falcon::FrameLayer::kL4Payload) {
        uint64_t ts;
        std::memcpy(&ts, data, 8);
        return ts;
    } else {
        const falcon::EtherHdr* eth;
        const uint8_t* p = falcon::parse_ethernet(data, len, eth);
        if (!p) { return 0; }
        if (ntohs(eth->ethertype) != falcon::kEthTypeIpv4) { return 0; }

        const falcon::Ipv4Hdr* ip;
        p = falcon::parse_ipv4(p, len - falcon::EtherHdr::kSize, ip);
        if (!p || ip->protocol != falcon::kProtoUdp) { return 0; }

        const falcon::UdpHdr* udp;
        p = falcon::parse_udp(p, len - falcon::EtherHdr::kSize - ip->header_len(), udp);
        if (!p) { return 0; }

        uint64_t ts;
        std::memcpy(&ts, p, 8);
        return ts;
    }
}

// ── raw frame crafting for the veth path ────────────────────────────────────

uint16_t ip_checksum(const uint8_t* hdr, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2) {
        sum += (hdr[i] << 8) | hdr[i + 1];
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

// Build eth → ipv4 → udp → timestamp-prefixed payload.
size_t build_frame(uint8_t* buf, size_t payload_size, uint64_t ts, uint16_t port,
                   uint32_t src_ip, uint32_t dst_ip) {
    size_t off = 0;
    const uint8_t dst_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};  // broadcast
    const uint8_t src_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    std::memcpy(buf + off, dst_mac, 6); off += 6;
    std::memcpy(buf + off, src_mac, 6); off += 6;
    buf[off] = 0x08; buf[off + 1] = 0x00; off += 2;   // ethertype = IPv4

    const uint16_t total = 20 + 8 + payload_size;
    uint8_t* ip = buf + off;
    ip[0] = 0x45;                                      // ver 4, ihl 5
    ip[1] = 0;
    ip[2] = total >> 8; ip[3] = total & 0xFF;
    ip[4] = 0; ip[5] = 0;
    ip[6] = 0x40; ip[7] = 0;                           // DF, frag off 0
    ip[8] = 64;                                        // ttl
    ip[9] = falcon::kProtoUdp;
    ip[10] = 0; ip[11] = 0;
    std::memcpy(ip + 12, &src_ip, 4);
    std::memcpy(ip + 16, &dst_ip, 4);
    uint16_t csum = ip_checksum(ip, 20);
    ip[10] = csum >> 8; ip[11] = csum & 0xFF;
    off += 20;

    uint8_t* udp = buf + off;
    const uint16_t sport = 50000;
    udp[0] = sport >> 8; udp[1] = sport & 0xFF;
    udp[2] = port >> 8; udp[3] = port & 0xFF;
    const uint16_t ulen = 8 + payload_size;
    udp[4] = ulen >> 8; udp[5] = ulen & 0xFF;
    udp[6] = 0; udp[7] = 0;                            // csum 0 = allowed on IPv4
    off += 8;

    std::memcpy(buf + off, &ts, 8);
    std::memset(buf + off + 8, 0, payload_size - 8);
    return off + payload_size;
}

// Sender thread: embeds an 8-byte nanosecond timestamp in every payload.
// With cfg.tx_iface set it crafts raw L2 frames (veth path); otherwise it
// sends plain UDP to loopback.
void tx_thread(const BenchCfg& cfg, std::atomic<bool>& stop) {
    if (!cfg.tx_netns.empty()) {
        std::string path = "/var/run/netns/" + cfg.tx_netns;
        int netns_fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
        if (netns_fd < 0 || setns(netns_fd, CLONE_NEWNET) < 0) {
            std::fprintf(stderr, "enter network namespace %s failed: %s\n",
                         cfg.tx_netns.c_str(), std::strerror(errno));
            if (netns_fd >= 0) {
                close(netns_fd);
            }
            stop.store(true);
            return;
        }
        close(netns_fd);
    }

    auto t0 = Clock::now();
    uint64_t sent = 0;

    if (cfg.raw_tx) {
        int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (s < 0) { stop.store(true); return; }

        sockaddr_ll sa{};
        sa.sll_family = AF_PACKET;
        sa.sll_protocol = htons(ETH_P_IP);
        sa.sll_ifindex = static_cast<int>(if_nametoindex(cfg.tx_iface.c_str()));
        if (sa.sll_ifindex == 0) { close(s); stop.store(true); return; }

        uint32_t src_ip, dst_ip;
        inet_pton(AF_INET, cfg.src_ip.c_str(), &src_ip);
        inet_pton(AF_INET, cfg.dst_ip.c_str(), &dst_ip);

        std::vector<uint8_t> frame(14 + 20 + 8 + cfg.payload_size);
        while (!stop.load(std::memory_order_relaxed)) {
            uint64_t ts = now_ns();
            const size_t frame_size = build_frame(frame.data(), cfg.payload_size, ts, cfg.port,
                                                  src_ip, dst_ip);
            ssize_t written = sendto(s, frame.data(), frame_size, 0,
                                      reinterpret_cast<const sockaddr*>(&sa), sizeof(sa));
            if (written != static_cast<ssize_t>(frame_size)) {
                std::fprintf(stderr, "raw send on %s failed: %s\n",
                             cfg.tx_iface.c_str(), std::strerror(errno));
                break;
            }
            ++sent;
            if (cfg.burst > 0 && sent >= cfg.burst) { break; }
            if (cfg.burst == 0 &&
                std::chrono::duration<double>(Clock::now() - t0).count() >= cfg.seconds) {
                break;
            }
        }
        close(s);
        std::printf("  transmitted: %llu raw frames\n",
                    static_cast<unsigned long long>(sent));
        return;
    }

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { stop.store(true); return; }

    if (!cfg.tx_iface.empty()) {
        if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, cfg.tx_iface.c_str(),
                       cfg.tx_iface.size()) < 0) {
            std::fprintf(stderr, "bind UDP socket to %s failed: %s\n",
                         cfg.tx_iface.c_str(), std::strerror(errno));
            close(s);
            stop.store(true);
            return;
        }

        sockaddr_in src{};
        src.sin_family = AF_INET;
        if (inet_pton(AF_INET, cfg.src_ip.c_str(), &src.sin_addr) != 1 ||
            bind(s, reinterpret_cast<const sockaddr*>(&src), sizeof(src)) < 0) {
            std::fprintf(stderr, "bind UDP source %s failed: %s\n",
                         cfg.src_ip.c_str(), std::strerror(errno));
            close(s);
            stop.store(true);
            return;
        }
    }

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(cfg.port);
    if (inet_pton(AF_INET, cfg.tx_iface.empty() ? "127.0.0.1" : cfg.dst_ip.c_str(),
                  &dst.sin_addr) != 1) {
        std::fprintf(stderr, "invalid UDP destination: %s\n", cfg.dst_ip.c_str());
        close(s);
        stop.store(true);
        return;
    }

    std::vector<uint8_t> buf(cfg.payload_size);
    while (!stop.load(std::memory_order_relaxed)) {
        uint64_t ts = now_ns();
        std::memcpy(buf.data(), &ts, 8);
        std::memset(buf.data() + 8, 0, cfg.payload_size - 8);
        ssize_t written = sendto(s, buf.data(), buf.size(), 0,
                                 reinterpret_cast<const sockaddr*>(&dst), sizeof(dst));
        if (written != static_cast<ssize_t>(buf.size())) {
            std::fprintf(stderr, "UDP send to %s:%u failed: %s\n", cfg.dst_ip.c_str(),
                         cfg.port, std::strerror(errno));
            break;
        }
        ++sent;
        if (cfg.burst > 0 && sent >= cfg.burst) { break; }
        if (cfg.burst == 0 &&
            std::chrono::duration<double>(Clock::now() - t0).count() >= cfg.seconds) {
            break;
        }
    }
    close(s);
    std::printf("  transmitted: %llu UDP datagrams\n",
                static_cast<unsigned long long>(sent));
}

template <class Backend>
BenchResult run_bench(const BenchCfg& cfg, bool start_sender = true) {
    Backend backend = [&]() {
        if constexpr (std::is_same_v<Backend, falcon::SocketBackend>) {
            return Backend(cfg.port);
        } else if constexpr (std::is_same_v<Backend, falcon::AfXdpBackend>) {
            return Backend(cfg.ifname, falcon::AfXdpMode::kCopy, true);
        } else {
            return Backend(cfg.ifname);
        }
    }();

    std::atomic<bool> stop{false};
    std::thread tx;
    pid_t tx_pid = -1;
    if (start_sender && !cfg.tx_netns.empty()) {
        std::fflush(nullptr);
        tx_pid = fork();
        if (tx_pid == 0) {
            std::atomic<bool> child_stop{false};
            tx_thread(cfg, child_stop);
            std::fflush(nullptr);
            _exit(0);
        }
        if (tx_pid < 0) {
            throw std::runtime_error("fork() failed: " + std::string(std::strerror(errno)));
        }
    } else if (start_sender) {
        tx = std::thread(tx_thread, std::cref(cfg), std::ref(stop));
    }

    falcon::Frame frames[64];
    std::vector<uint64_t> latencies;
    latencies.reserve(cfg.burst > 0 ? cfg.burst : 1u << 20);

    const double cpu0 = thread_cpu_ns();
    auto t0 = Clock::now();
    auto win_start = t0;

    uint64_t win_packets = 0;
    BenchResult r;

    for (;;) {
        size_t got = backend.recv(frames, 64);
        for (size_t i = 0; i < got; ++i) {
            uint64_t ts = frame_ts<Backend>(frames[i].data_, frames[i].len_);
            if (ts != 0) {
                latencies.push_back(now_ns() - ts);
            }
            r.bytes += frames[i].len_;
        }
        r.packets += got;
        win_packets += got;

        // print the per-second stats window (xdp-bench style)
        auto now = Clock::now();
        double win_elapsed = std::chrono::duration<double>(now - win_start).count();
        if (win_elapsed >= cfg.window_sec) {
            std::printf("  window %5.1fs: %8llu pps | total %llu pkts %llu B\n",
                        std::chrono::duration<double>(now - t0).count(),
                        static_cast<unsigned long long>(win_packets / win_elapsed),
                        static_cast<unsigned long long>(r.packets),
                        static_cast<unsigned long long>(r.bytes));
            win_packets = 0;
            win_start = now;
        }

        double elapsed = std::chrono::duration<double>(now - t0).count();
        if (elapsed >= cfg.seconds)
            break;
        if (cfg.burst > 0 && latencies.size() >= cfg.burst)
            break;
    }

    stop.store(true);
    if (tx.joinable()) {
        tx.join();
    }
    if (tx_pid > 0) {
        int status = 0;
        waitpid(tx_pid, &status, 0);
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            throw std::runtime_error("transmitter process failed");
        }
    }

    const double cpu1 = thread_cpu_ns();
    r.seconds = std::chrono::duration<double>(Clock::now() - t0).count();
    r.pps = r.packets / r.seconds;
    r.cpu_pct = (cpu1 - cpu0) / (r.seconds * 1e9) * 100.0;  // % of one core

    if (!latencies.empty()) {
        std::sort(latencies.begin(), latencies.end());
        auto& v = latencies;
        r.p50_ns = v[v.size() / 2];
        r.p99_ns = v[static_cast<size_t>(v.size() * 0.99)];
    }
    return r;
}

} // namespace

int main(int argc, char** argv) {
    std::string backend_name = argc > 1 ? argv[1] : "socket";
    BenchCfg cfg;
    bool receiver_only = false;
    bool sender_only = false;
    int arg = 2;

    if (backend_name == "rx") {
        receiver_only = true;
        if (argc <= arg) {
            std::fprintf(stderr, "usage: falcon-bench rx [socket|packet|xdp] [port|iface] [seconds] [burst]\n");
            return 1;
        }
        backend_name = argv[arg++];
    } else if (backend_name == "tx") {
        sender_only = true;
    }

    if (sender_only) {
        std::string tx_kind = argc > arg ? argv[arg] : "udp";
        if (tx_kind == "udp" || tx_kind == "raw") {
            cfg.raw_tx = tx_kind == "raw";
            ++arg;
        }
        if (argc > arg) cfg.port = static_cast<uint16_t>(std::atoi(argv[arg++]));
        if (argc > arg) cfg.seconds = std::atof(argv[arg++]);
        if (argc > arg) cfg.burst = std::strtoull(argv[arg++], nullptr, 10);
        if (argc > arg) cfg.tx_iface = argv[arg++];
        if (argc > arg) cfg.src_ip = argv[arg++];
        if (argc > arg) cfg.dst_ip = argv[arg++];
        if (argc > arg) cfg.payload_size = std::strtoul(argv[arg++], nullptr, 10);
        if (cfg.tx_iface.empty()) {
            std::fprintf(stderr, "tx mode requires an interface\n");
            return 1;
        }
        std::atomic<bool> stop{false};
        std::printf("falcon-bench | mode=tx | transport=%s | port=%u | seconds=%.1f | burst=%llu | tx=%s %s->%s\n",
                    cfg.raw_tx ? "raw" : "udp",
                    cfg.port, cfg.seconds, static_cast<unsigned long long>(cfg.burst),
                    cfg.tx_iface.c_str(), cfg.src_ip.c_str(), cfg.dst_ip.c_str());
        tx_thread(cfg, stop);
        return 0;
    }

    if (backend_name == "socket") {
        if (argc > arg) cfg.port = static_cast<uint16_t>(std::atoi(argv[arg++]));
    } else if (backend_name == "packet" || backend_name == "xdp") {
        if (argc > arg) cfg.ifname = argv[arg++];
    } else {
        std::fprintf(stderr, "unknown backend: %s (use: socket | packet | xdp)\n", backend_name.c_str());
        return 1;
    }
    if (argc > arg) cfg.seconds = std::atof(argv[arg++]);
    if (argc > arg) cfg.burst = std::strtoull(argv[arg++], nullptr, 10);
    if (receiver_only) {
        if (argc > arg) cfg.payload_size = std::strtoul(argv[arg++], nullptr, 10);
    // With a network namespace, use a normal UDP sender from the veth peer.
    // Without one, retain the original raw-frame veth test syntax.
    } else if (argc > arg) {
        std::string netns_path = "/var/run/netns/" + std::string(argv[arg]);
        if (access(netns_path.c_str(), F_OK) == 0) {
            cfg.tx_netns = argv[arg++];
            if (argc > arg) cfg.tx_iface = argv[arg++];
            if (argc > arg) cfg.src_ip = argv[arg++];
            if (argc > arg) cfg.dst_ip = argv[arg++];
        } else {
            cfg.tx_iface = argv[arg++];
            if (argc > arg) cfg.src_ip = argv[arg++];
            if (argc > arg) cfg.dst_ip = argv[arg++];
            cfg.raw_tx = true;
        }
    }

    if (!receiver_only && argc > arg) cfg.payload_size = std::strtoul(argv[arg++], nullptr, 10);
    if (cfg.payload_size < 8 || cfg.payload_size > 1400) {
        std::fprintf(stderr, "payload size must be between 8 and 1400 bytes\n");
        return 1;
    }

    std::printf("falcon-bench | mode=%s | backend=%s | iface/port=%s | seconds=%.1f | burst=%llu | payload=%zu%s%s\n",
                 receiver_only ? "rx" : "combined",
                 backend_name.c_str(),
                backend_name == "socket" ? std::to_string(cfg.port).c_str() : cfg.ifname.c_str(),
                 cfg.seconds,
                 static_cast<unsigned long long>(cfg.burst),
                 cfg.payload_size,
                 cfg.tx_netns.empty() ? "" : (" | tx_netns=" + cfg.tx_netns).c_str(),
                 cfg.tx_iface.empty() ? "" : (" | tx=" + cfg.tx_iface + " " + cfg.src_ip + "->" + cfg.dst_ip).c_str());

    BenchResult r;
    if (backend_name == "socket") {
        r = run_bench<falcon::SocketBackend>(cfg, !receiver_only);
    } else if (backend_name == "packet") {
        r = run_bench<falcon::AfPacketBackend>(cfg, !receiver_only);
    } else {
        r = run_bench<falcon::AfXdpBackend>(cfg, !receiver_only);
    }

    std::printf("\n=== results ===\n");
    std::printf("  packets : %llu\n", static_cast<unsigned long long>(r.packets));
    std::printf("  bytes   : %llu\n", static_cast<unsigned long long>(r.bytes));
    std::printf("  seconds : %.3f\n", r.seconds);
    std::printf("  pps     : %.0f\n", r.pps);
    std::printf("  p50     : %.0f ns\n", r.p50_ns);
    std::printf("  p99     : %.0f ns\n", r.p99_ns);
    std::printf("  cpu     : %.1f%% (receiver thread, one core)\n", r.cpu_pct);
    return 0;
}
