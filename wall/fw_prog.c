// FalconWall XDP DDoS Mitigator — BPF data plane.
//
// Fast path, in order (each is a single cheap lookup):
//   1. blocklist   — per-IP LRU hash, drop if present and not expired.
//   2. range_drop  — LPM trie, drop if the source IP falls in a dropped subnet.
//   3. rate limit  — sliding-window counter per source IP (rich per-IP stats).
//   4. otherwise   — XDP_PASS.
//
// The per-IP stats map stores rich data (packets, bytes, syn/udp/icmp counts)
// so userspace detector plugins can be added later without touching this file.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define MAX_BLOCK 100000
#define MAX_RANGES 4096
#define MAX_IPS 100000

// LPM trie key: { prefix_len, address }.
struct lpm_key {
    __u32 prefix_len;
    __u32 data;
};

// Per-IP blocklist. key = IPv4 (network byte order), value = expiry (ns since
// boot, monotonic); 0 = permanent block.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_BLOCK);
    __type(key, __u32);
    __type(value, __u64);
} fw_blocklist SEC(".maps");

// CIDR drop ranges. LPM trie, key = {prefix_len, data}, value = 1.
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_RANGES);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key);
    __type(value, __u64);
} fw_range_drop SEC(".maps");

// Rich per-IP stats. Sliding window needs prev + current counts; the extra
// fields (syn/udp/icmp) are populated for future userspace detectors.
struct ip_stats {
    __u64 window_start;   // ns (monotonic) the current window began
    __u64 prev_packets;   // packets in the previous window
    __u64 packets;        // packets in the current window
    __u64 prev_bytes;     // bytes in the previous window
    __u64 bytes;          // bytes in the current window
    __u64 syn;            // TCP SYN packets (current window)
    __u64 udp;            // UDP packets (current window)
    __u64 icmp;           // ICMP packets (current window)
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_IPS);
    __type(key, __u32);
    __type(value, struct ip_stats);
} fw_ip_stats SEC(".maps");

// Runtime config: [0] = enabled, [1] = per-IP pps limit (0 = off).
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} fw_config SEC(".maps");

struct counters {
    __u64 rx;
    __u64 dropped;
    __u64 passed;
};

// Per-CPU counters (no atomic ops needed — each CPU has its own copy).
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct counters);
} fw_stats SEC(".maps");

#define CFG_ENABLED 0
#define CFG_PPS 1

// Sliding window constants. Window is 1<<30 ns (~1.0737s, chosen power-of-two
// so all weighting math is shifts, never division — BPF rejects 64-bit div).
#define WINDOW_NS (1ULL << 30)
#define FRAC_BITS 10
#define FRAC_STEP (1ULL << 20) // WINDOW_NS >> FRAC_BITS

static __always_inline __u64 cfg(__u32 i) {
    __u32 k = i;
    __u64 *v = bpf_map_lookup_elem(&fw_config, &k);
    return v ? *v : 0;
}

SEC("xdp")
int fw_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    __u32 k0 = 0;
    struct counters *c = bpf_map_lookup_elem(&fw_stats, &k0);
    if (c)
        c->rx++;

    // Only IPv4 is mitigated; everything else passes untouched.
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        if (c)
            c->passed++;
        return XDP_PASS;
    }

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) {
        if (c)
            c->dropped++;
        return XDP_DROP;
    }

    if (!cfg(CFG_ENABLED)) {
        if (c)
            c->passed++;
        return XDP_PASS;
    }

    __u32 src = ip->saddr;
    __u64 now = bpf_ktime_get_ns();
    __u32 len = (__u32)((long)data_end - (long)data);

    // 1. Blocklist (fast path).
    __u64 *exp = bpf_map_lookup_elem(&fw_blocklist, &src);
    if (exp) {
        if (*exp == 0 || now <= *exp) {
            if (c)
                c->dropped++;
            return XDP_DROP;
        }
        bpf_map_delete_elem(&fw_blocklist, &src); // expired
    }

    // 2. CIDR range drop (single LPM lookup covers all ranges).
    struct lpm_key lk = { .prefix_len = 32, .data = src };
    if (bpf_map_lookup_elem(&fw_range_drop, &lk)) {
        if (c)
            c->dropped++;
        return XDP_DROP;
    }

    // 3. Classify the L4 packet for rich stats (only common no-options case).
    __u8 proto = ip->protocol;
    __u8 is_syn = 0, is_udp = 0, is_icmp = 0;

    if (ip->ihl == 5) {
        if (proto == IPPROTO_TCP) {
            struct tcphdr *tcp = data + sizeof(struct ethhdr) + 20;
            if ((void *)(tcp + 1) <= data_end && tcp->syn)
                is_syn = 1;
        } else if (proto == IPPROTO_UDP) {
            is_udp = 1;
        } else if (proto == IPPROTO_ICMP) {
            is_icmp = 1;
        }
    }

    // 4. Sliding-window rate limit + record rich per-IP stats.
    struct ip_stats *s = bpf_map_lookup_elem(&fw_ip_stats, &src);
    __u64 rate = 0;

    if (s) {
        if (now - s->window_start >= WINDOW_NS) {
            s->prev_packets = s->packets;
            s->prev_bytes = s->bytes;
            s->packets = 0;
            s->bytes = 0;
            s->syn = 0;
            s->udp = 0;
            s->icmp = 0;
            s->window_start = now;
        }

        s->packets++;
        s->bytes += len;
        if (is_syn)
            s->syn++;
        else if (is_udp)
            s->udp++;
        else if (is_icmp)
            s->icmp++;

        // Weighted rate over the sliding window, all shifts (no division).
        __u64 slot = (now - s->window_start) >> 20; // 0 .. 1023
        rate = ((s->prev_packets * (1024 - slot)) + (s->packets << 10)) >> FRAC_BITS;
    } else {
        struct ip_stats n = {0};
        n.window_start = now;
        n.packets = 1;
        n.bytes = len;
        if (is_syn)
            n.syn = 1;
        else if (is_udp)
            n.udp = 1;
        else if (is_icmp)
            n.icmp = 1;
        rate = 1;
        bpf_map_update_elem(&fw_ip_stats, &src, &n, BPF_ANY);
    }

    __u64 pps = cfg(CFG_PPS);
    if (pps > 0 && rate > pps) {
        if (c)
            c->dropped++;
        return XDP_DROP;
    }

    if (c)
        c->passed++;
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
