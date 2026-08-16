#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} falcon_xsks SEC(".maps");

SEC("xdp")
int falcon_xdp_redirect(struct xdp_md* ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    struct ethhdr* ethernet = (void*)(long)ctx->data;
    if ((void*)(ethernet + 1) > data_end) {
        return XDP_PASS;
    }

    struct udphdr* udp;
    if (ethernet->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr* ip = (void*)(ethernet + 1);
        if ((void*)(ip + 1) > data_end || ip->protocol != IPPROTO_UDP || ip->ihl != 5) {
            return XDP_PASS;
        }
        udp = (void*)(ip + 1);
    } else if (ethernet->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr* ip = (void*)(ethernet + 1);
        if ((void*)(ip + 1) > data_end || ip->nexthdr != IPPROTO_UDP) {
            return XDP_PASS;
        }
        udp = (void*)(ip + 1);
    } else {
        return XDP_PASS;
    }

    if ((void*)(udp + 1) > data_end || udp->dest != bpf_htons(9100)) {
        return XDP_PASS;
    }

    return bpf_redirect_map(&falcon_xsks, ctx->rx_queue_index, XDP_PASS);
}

char LICENSE[] SEC("license") = "GPL";
