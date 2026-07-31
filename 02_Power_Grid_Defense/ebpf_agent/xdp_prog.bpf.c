#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>

struct event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 dst_port;
    __u32 packet_len;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("xdp")
int xdp_pass(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u16 dest_port = 0;
    __u16 src_port = 0;
    void *payload = NULL;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;
        dest_port = bpf_ntohs(tcp->dest);
        src_port = bpf_ntohs(tcp->source);
        payload = (void *)tcp + (tcp->doff * 4);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end) return XDP_PASS;
        dest_port = bpf_ntohs(udp->dest);
        src_port = bpf_ntohs(udp->source);
        payload = (void *)(udp + 1);
    } else {
        return XDP_PASS; // Pass non-TCP/UDP
    }

    // Filter OT traffic (Modbus 502 or DNP3 20000)
    if (dest_port == 502 || src_port == 502 || dest_port == 20000 || src_port == 20000) {
        
        // Allow Handshake/Control packets (zero payload)
        if (payload == data_end) {
            return XDP_PASS;
        }

        // --- L7 Shallow Parsing ---
        __u8 *bytes = payload;

        // DNP3 (Port 20000): Magic bytes 0x05 0x64
        if (dest_port == 20000 || src_port == 20000) {
            if (payload + 2 > data_end) return XDP_DROP;
            if (bytes[0] == 0x05 && bytes[1] == 0x64) {
                goto submit_event; // Valid DNP3
            }
            return XDP_DROP; // Noise on DNP3 port
        }

        // Modbus TCP (Port 502): Protocol ID is 0x00 0x00 (bytes 2 and 3)
        if (dest_port == 502 || src_port == 502) {
            if (payload + 4 > data_end) return XDP_DROP;
            if (bytes[2] == 0x00 && bytes[3] == 0x00) {
                goto submit_event; // Valid Modbus
            }
            return XDP_DROP; // Noise on Modbus port
        }

submit_event:
        {
            struct event *e;
            e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
            if (e) {
                e->src_ip = ip->saddr;
                e->dst_ip = ip->daddr;
                e->dst_port = dest_port;
                e->packet_len = data_end - data;
                bpf_ringbuf_submit(e, 0);
            }
        }
        return XDP_PASS;
    }

    // Drop other noise (simulating XDP_DROP's power)
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
