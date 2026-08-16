// FalconWall XDP DDoS Mitigator — userspace control plane (C++).
//
// The BPF data plane (fw_prog.c) drops traffic in-kernel. This binary only
// manages state:
//   falconwall start <iface>   load + attach + pin maps + live stats
//   falconwall watch [sec]     run detector plugins, auto-ban offenders
//   falconwall block/unblock/range/unrange/ratelimit/enable/disable/stats
// The map commands open the pinned maps directly, so they work while the
// daemon is running.

#include "detector.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csignal>
#include <cerrno>
#include <ctime>
#include <string>
#include <iostream>

#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/stat.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#ifndef FW_OBJ_PATH
#define FW_OBJ_PATH "./fw_prog.o"
#endif

#define PIN_DIR "/sys/fs/bpf/falconwall"

#define MAP_BLOCK   "fw_blocklist"
#define MAP_RANGE   "fw_range_drop"
#define MAP_IPSTATS "fw_ip_stats"
#define MAP_CONFIG  "fw_config"
#define MAP_STATS   "fw_stats"

#define CFG_ENABLED 0
#define CFG_PPS 1

struct LpmKey {
    __u32 prefix_len;
    __u32 data;
};

struct Counters {
    __u64 rx;
    __u64 dropped;
    __u64 passed;
};

static const char* MAP_NAMES[] = { MAP_BLOCK, MAP_RANGE, MAP_IPSTATS, MAP_CONFIG, MAP_STATS };
constexpr int N_MAPS = (int)(sizeof(MAP_NAMES) / sizeof(MAP_NAMES[0]));

static volatile sig_atomic_t running = 1;

static void on_sig(int s) { (void)s; running = 0; }

static std::string pin_path(const char* name) {
    return std::string(PIN_DIR) + "/" + name;
}

static int get_map(const char* name) {
    int fd = bpf_obj_get(pin_path(name).c_str());
    if (fd < 0)
        std::cerr << "error: is the daemon running? (falconwall start <iface>)\n";
    return fd;
}

static __u64 now_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

static void usage() {
    std::cout <<
        "FalconWall XDP DDoS Mitigator\n\n"
        "Usage:\n"
        "  falconwall start <iface> [-o obj]   load + attach + pin + live stats\n"
        "  falconwall watch [sec]              run detector plugins, auto-ban (default 60s)\n"
        "  falconwall block <ip> [sec]         block an IP (sec=0 or omitted = permanent)\n"
        "  falconwall unblock <ip>             unblock an IP\n"
        "  falconwall range <cidr>             drop a subnet (e.g. 10.0.0.0/8)\n"
        "  falconwall unrange <cidr>           remove a dropped subnet\n"
        "  falconwall ratelimit <pps>          per-IP rate limit (0 = off)\n"
        "  falconwall enable                   enable mitigation\n"
        "  falconwall disable                  disable mitigation\n"
        "  falconwall stats                    print counters once\n";
}

static int parse_ip(const char* s, __u32* out) {
    struct in_addr a;
    if (inet_pton(AF_INET, s, &a) != 1)
        return -1;
    *out = a.s_addr;
    return 0;
}

static int parse_cidr(const char* s, __u32* prefix, __u32* net) {
    char ipstr[64];
    int pfx = 32;
    if (std::sscanf(s, "%63[^/]/%d", ipstr, &pfx) < 1)
        return -1;
    if (pfx < 0 || pfx > 32)
        return -1;
    __u32 ip;
    if (parse_ip(ipstr, &ip))
        return -1;
    __u32 mask = (pfx == 0) ? 0 : htonl(0xFFFFFFFFu << (32 - pfx));
    *prefix = (__u32)pfx;
    *net = ip & mask;
    return 0;
}

static std::string ip_to_str(__u32 ip) {
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, buf, sizeof(buf));
    return buf;
}

static int set_config(__u32 idx, __u64 val) {
    int fd = get_map(MAP_CONFIG);
    if (fd < 0)
        return -1;
    int ret = bpf_map_update_elem(fd, &idx, &val, BPF_ANY);
    close(fd);
    if (ret) {
        std::cerr << "error: update config[" << idx << "]: " << std::strerror(errno) << "\n";
        return -1;
    }
    return 0;
}

// Adds ip to the blocklist for `sec` seconds (sec <= 0 = permanent).
static int block_ip(int fd, __u32 ip, long sec) {
    __u64 expiry = 0;
    if (sec > 0)
        expiry = now_ns() + (__u64)sec * 1000000000ULL;
    return bpf_map_update_elem(fd, &ip, &expiry, BPF_ANY);
}

static void print_stats() {
    int fd = get_map(MAP_STATS);
    if (fd < 0)
        return;
    int ncpu = libbpf_num_possible_cpus();
    auto* vals = new Counters[ncpu]();
    __u32 k = 0;
    Counters total{};
    if (!bpf_map_lookup_elem(fd, &k, vals)) {
        for (int i = 0; i < ncpu; i++) {
            total.rx += vals[i].rx;
            total.dropped += vals[i].dropped;
            total.passed += vals[i].passed;
        }
    }
    std::cout << "rx=" << total.rx << " dropped=" << total.dropped
              << " passed=" << total.passed << "\n";
    delete[] vals;
    close(fd);
}

static int cmd_start(int argc, char** argv) {
    std::string ifname;
    std::string obj = FW_OBJ_PATH;

    for (int i = 0; i < argc; i++) {
        if (!std::strcmp(argv[i], "-o") && i + 1 < argc)
            obj = argv[++i];
        else if (ifname.empty())
            ifname = argv[i];
    }
    if (ifname.empty()) {
        usage();
        return 1;
    }

    int ifindex = if_nametoindex(ifname.c_str());
    if (!ifindex) {
        std::cerr << "error: no such interface '" << ifname << "'\n";
        return 1;
    }

    bpf_object* bobj = bpf_object__open_file(obj.c_str(), nullptr);
    if (libbpf_get_error(bobj)) {
        std::cerr << "error: open '" << obj << "' failed\n";
        return 1;
    }
    if (bpf_object__load(bobj)) {
        std::cerr << "error: load failed\n";
        bpf_object__close(bobj);
        return 1;
    }

    bpf_program* prog = bpf_object__find_program_by_name(bobj, "fw_prog");
    if (!prog) {
        std::cerr << "error: no 'fw_prog' section in object\n";
        bpf_object__close(bobj);
        return 1;
    }
    int pfd = bpf_program__fd(prog);

    __u32 flags = XDP_FLAGS_DRV_MODE;
    if (bpf_xdp_attach(ifindex, pfd, flags, nullptr)) {
        flags = XDP_FLAGS_SKB_MODE;
        if (bpf_xdp_attach(ifindex, pfd, flags, nullptr)) {
            std::cerr << "error: attach failed: " << std::strerror(errno) << "\n";
            bpf_object__close(bobj);
            return 1;
        }
        std::cout << "attached in SKB (generic) mode\n";
    } else {
        std::cout << "attached in DRV (native) mode\n";
    }

    mkdir(PIN_DIR, 0755);
    for (int i = 0; i < N_MAPS; i++) {
        bpf_map* m = bpf_object__find_map_by_name(bobj, MAP_NAMES[i]);
        if (!m) {
            std::cerr << "warning: map '" << MAP_NAMES[i] << "' missing\n";
            continue;
        }
        unlink(pin_path(MAP_NAMES[i]).c_str());
        if (bpf_map__pin(m, pin_path(MAP_NAMES[i]).c_str()))
            std::cerr << "warning: pin '" << MAP_NAMES[i] << "' failed: " << std::strerror(errno) << "\n";
    }

    set_config(CFG_ENABLED, 1);

    std::cout << "running on " << ifname << " — Ctrl+C to stop\n";
    std::signal(SIGINT, on_sig);
    std::signal(SIGTERM, on_sig);

    int sfd = bpf_object__find_map_fd_by_name(bobj, MAP_STATS);
    int ncpu = libbpf_num_possible_cpus();
    auto* vals = new Counters[ncpu]();

    while (running) {
        __u32 k = 0;
        Counters total{};
        if (sfd >= 0 && !bpf_map_lookup_elem(sfd, &k, vals)) {
            for (int i = 0; i < ncpu; i++) {
                total.rx += vals[i].rx;
                total.dropped += vals[i].dropped;
                total.passed += vals[i].passed;
            }
        }
        std::cout << "\rrx=" << total.rx << "  dropped=" << total.dropped
                  << "  passed=" << total.passed << "     " << std::flush;
        sleep(1);
    }

    std::cout << "\nstopping...\n";
    bpf_xdp_detach(ifindex, flags, nullptr);
    for (int i = 0; i < N_MAPS; i++)
        unlink(pin_path(MAP_NAMES[i]).c_str());
    bpf_object__close(bobj);
    delete[] vals;
    return 0;
}

// Runs every registered detector against the per-IP stats map and auto-bans
// offenders by writing to the blocklist map.
static int cmd_watch(int argc, char** argv) {
    long ban_sec = 60;
    if (argc > 0)
        ban_sec = std::strtol(argv[0], nullptr, 10);

    int stats_fd = get_map(MAP_IPSTATS);
    int block_fd = get_map(MAP_BLOCK);
    if (stats_fd < 0 || block_fd < 0)
        return 1;

    const auto& detectors = DetectorRegistry::get().all();
    std::cout << std::unitbuf; // flush each line (watch may log to a file)
    std::cout << "watching with " << detectors.size() << " detectors, ban=" << ban_sec << "s\n";
    for (const auto& d : detectors)
        std::cout << "  - " << d->name() << "\n";

    std::signal(SIGINT, on_sig);
    std::signal(SIGTERM, on_sig);

    while (running) {
        __u32 key = 0, next_key;
        int err = bpf_map_get_next_key(stats_fd, nullptr, &key);

        while (err == 0) {
            IpStats s{};
            if (!bpf_map_lookup_elem(stats_fd, &key, &s)) {
                __u64 exp;
                bool already_blocked = (bpf_map_lookup_elem(block_fd, &key, &exp) == 0);

                if (!already_blocked) {
                    for (const auto& d : detectors) {
                        if (d->match(key, s)) {
                            if (block_ip(block_fd, key, ban_sec) == 0)
                                std::cout << "ban " << ip_to_str(key) << " (" << d->name() << ")\n";
                            break;
                        }
                    }
                }
            }

            err = bpf_map_get_next_key(stats_fd, &key, &next_key);
            key = next_key;
        }
        sleep(1);
    }

    close(stats_fd);
    close(block_fd);
    return 0;
}

static int cmd_block(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "usage: falconwall block <ip> [sec]\n";
        return 1;
    }
    __u32 ip;
    if (parse_ip(argv[0], &ip)) {
        std::cerr << "error: bad ip '" << argv[0] << "'\n";
        return 1;
    }
    long sec = 0;
    if (argc > 1)
        sec = std::strtol(argv[1], nullptr, 10);

    int fd = get_map(MAP_BLOCK);
    if (fd < 0)
        return 1;
    int ret = block_ip(fd, ip, sec);
    close(fd);
    if (ret) {
        std::cerr << "error: " << std::strerror(errno) << "\n";
        return 1;
    }
    std::cout << "blocked " << argv[0] << (sec > 0 ? " temporarily\n" : " permanently\n");
    return 0;
}

static int cmd_unblock(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "usage: falconwall unblock <ip>\n";
        return 1;
    }
    __u32 ip;
    if (parse_ip(argv[0], &ip)) {
        std::cerr << "error: bad ip '" << argv[0] << "'\n";
        return 1;
    }
    int fd = get_map(MAP_BLOCK);
    if (fd < 0)
        return 1;
    int ret = bpf_map_delete_elem(fd, &ip);
    close(fd);
    if (ret) {
        std::cerr << "error: " << std::strerror(errno) << "\n";
        return 1;
    }
    std::cout << "unblocked " << argv[0] << "\n";
    return 0;
}

static int cmd_range(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "usage: falconwall range <cidr>\n";
        return 1;
    }
    __u32 prefix, net;
    if (parse_cidr(argv[0], &prefix, &net)) {
        std::cerr << "error: bad cidr '" << argv[0] << "'\n";
        return 1;
    }
    LpmKey k{ prefix, net };
    __u64 one = 1;
    int fd = get_map(MAP_RANGE);
    if (fd < 0)
        return 1;
    int ret = bpf_map_update_elem(fd, &k, &one, BPF_ANY);
    close(fd);
    if (ret) {
        std::cerr << "error: " << std::strerror(errno) << "\n";
        return 1;
    }
    std::cout << "dropping " << argv[0] << "\n";
    return 0;
}

static int cmd_unrange(int argc, char** argv) {
    if (argc < 1) {
        std::cerr << "usage: falconwall unrange <cidr>\n";
        return 1;
    }
    __u32 prefix, net;
    if (parse_cidr(argv[0], &prefix, &net)) {
        std::cerr << "error: bad cidr '" << argv[0] << "'\n";
        return 1;
    }
    LpmKey k{ prefix, net };
    int fd = get_map(MAP_RANGE);
    if (fd < 0)
        return 1;
    int ret = bpf_map_delete_elem(fd, &k);
    close(fd);
    if (ret) {
        std::cerr << "error: " << std::strerror(errno) << "\n";
        return 1;
    }
    std::cout << "stopped dropping " << argv[0] << "\n";
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        usage();
        return 1;
    }
    std::string cmd = argv[1];
    int a = argc - 2;
    char** v = argv + 2;

    if (cmd == "start")     return cmd_start(a, v);
    if (cmd == "watch")     return cmd_watch(a, v);
    if (cmd == "block")     return cmd_block(a, v);
    if (cmd == "unblock")   return cmd_unblock(a, v);
    if (cmd == "range")     return cmd_range(a, v);
    if (cmd == "unrange")   return cmd_unrange(a, v);
    if (cmd == "ratelimit") {
        if (a < 1) { std::cerr << "usage: falconwall ratelimit <pps>\n"; return 1; }
        __u64 pps = std::strtoull(v[0], nullptr, 10);
        set_config(CFG_PPS, pps);
        std::cout << "rate limit set to " << pps << " pps\n";
        return 0;
    }
    if (cmd == "enable")    { set_config(CFG_ENABLED, 1); std::cout << "mitigation enabled\n"; return 0; }
    if (cmd == "disable")   { set_config(CFG_ENABLED, 0); std::cout << "mitigation disabled\n"; return 0; }
    if (cmd == "stats")     { print_stats(); return 0; }
    if (cmd == "help" || cmd == "-h" || cmd == "--help") { usage(); return 0; }

    usage();
    return 1;
}
