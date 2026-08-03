#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct tx_event {
    __u32 pid;
    __u32 uid;
    char comm[16];
    __u32 src_ip;
    __u32 dst_ip;
    __u16 dst_port;
    __u64 t_tx;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, struct sock *sk)
{
    struct tx_event *e;
    __u16 dport = 0;
    __u32 daddr = 0;
    __u32 saddr = 0;
    __u64 ts = bpf_ktime_get_ns();

    // Extract destination port using CO-RE
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
    
    // Filter by DNP3 Port 20000 (Network byte order: 0x204e)
    if (__builtin_bswap16(dport) != 20000) {
        return 0;
    }

    // Extract IPs
    BPF_CORE_READ_INTO(&daddr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&saddr, sk, __sk_common.skc_rcv_saddr);

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->src_ip = saddr;
    e->dst_ip = daddr;
    e->dst_port = __builtin_bswap16(dport);
    e->t_tx = ts;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
