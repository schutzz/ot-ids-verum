#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "xdp_prog.skel.h"

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

struct event {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 dst_port;
    __u32 packet_len;
    __u8  function_code;
};

static int handle_event(void *ctx, void *data, size_t data_sz) {
    struct event *e = data;
    printf("[eBPF Vanguard] OT Packet (Port %d, Len %d) FC=%u authenticated and passed to Zeek!\n", 
           e->dst_port, e->packet_len, e->function_code);
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv) {
    struct xdp_prog_bpf *skel;
    int err;
    int ifindex;
    
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ifname>\n", argv[0]);
        return 1;
    }

    ifindex = if_nametoindex(argv[1]);
    if (!ifindex) {
        fprintf(stderr, "Invalid interface name %s\n", argv[1]);
        return 1;
    }

    libbpf_set_print(libbpf_print_fn);

    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK\n");
    }

    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, open_opts);
    char *custom_btf = getenv("CUSTOM_BTF_PATH");
    if (custom_btf && access(custom_btf, R_OK) == 0) {
        open_opts.btf_custom_path = custom_btf;
        printf("[eBPF Vanguard] Using custom BTF file: %s\n", custom_btf);
    } else {
        printf("[eBPF Vanguard] Using system default BTF from /sys/kernel/btf/vmlinux\n");
    }

    skel = xdp_prog_bpf__open_opts(&open_opts);
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = xdp_prog_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        return 1;
    }

    /* Check if an active BPF link is already pinned and detach it via bpf_link_detach */
    int pinned_link_fd = bpf_obj_get("/sys/fs/bpf/xdp_pass");
    if (pinned_link_fd >= 0) {
        printf("[eBPF Vanguard] Found existing pinned XDP link at /sys/fs/bpf/xdp_pass. Detaching...\n");
        bpf_link_detach(pinned_link_fd);
        close(pinned_link_fd);
    }

    /* Unlink old pinned paths from bpffs */
    unlink("/sys/fs/bpf/xdp_pass");
    unlink("/sys/fs/bpf/xdp_counter_map");

    /* Force detach old XDP programs across potential modes using libbpf bpf_xdp_detach */
    bpf_xdp_detach(ifindex, 0, NULL);
    bpf_xdp_detach(ifindex, 1 << 1, NULL); // XDP_FLAGS_SKB_MODE

    skel->links.xdp_pass = bpf_program__attach_xdp(skel->progs.xdp_pass, ifindex);
    if (!skel->links.xdp_pass) {
        err = -errno;
        fprintf(stderr, "Failed to attach BPF program to ifindex %d (err=%d)\n", ifindex, err);
        goto cleanup;
    }


    printf("Successfully attached XDP program to %s (ifindex %d)\n", argv[1], ifindex);

    err = bpf_link__pin(skel->links.xdp_pass, "/sys/fs/bpf/xdp_pass");
    if (err) {
        fprintf(stderr, "Failed to pin XDP link to /sys/fs/bpf/xdp_pass (err=%d). Check if bpffs is mounted.\n", err);
    } else {
        printf("XDP program successfully pinned to /sys/fs/bpf/xdp_pass. It will survive container exit!\n");
    }



    /* Pin xdp_counter_map so ebpf_tx_agent can read DROP/PASS stats
     * without needing curl or network capabilities in this container.
     * Security: ebpf_agent stays read_only; ebpf_tx_agent (privileged) polls via bpf_obj_get().
     */
    err = bpf_map__pin(skel->maps.xdp_counter_map, "/sys/fs/bpf/xdp_counter_map");
    if (err) {
        fprintf(stderr, "Warning: Failed to pin xdp_counter_map (err=%d). Counter export disabled.\n", err);
    } else {
        printf("xdp_counter_map pinned to /sys/fs/bpf/xdp_counter_map. ebpf_tx_agent can now read DROP/PASS stats.\n");
    }



    struct ring_buffer *rb = NULL;
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = -1;
        goto cleanup;
    }

    while (1) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    xdp_prog_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
