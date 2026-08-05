#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/resource.h>
#include <pthread.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <curl/curl.h>
#include <openssl/sha.h>
#include "tx_prog.skel.h"

/* ------------------------------------------------------------------ *
 * XDP counter polling: reads xdp_counter_map pinned by ebpf_agent and
 * reports DROP/PASS totals to Webdis every COUNTER_POLL_SEC seconds.
 * This keeps ebpf_agent read_only (no curl/network capability needed).
 * ------------------------------------------------------------------ */
#define COUNTER_POLL_SEC 5
#define COUNTER_PIN_PATH "/sys/fs/bpf/xdp_counter_map"
#define MAX_CPUS 256

typedef struct {
    const char *webdis_base;
} counter_args_t;

static void *counter_poll_thread(void *arg) {
    counter_args_t *a = (counter_args_t *)arg;
    const char *webdis_base = a->webdis_base;

    while (1) {
        sleep(COUNTER_POLL_SEC);

        int map_fd = bpf_obj_get(COUNTER_PIN_PATH);
        if (map_fd < 0) {
            /* ebpf_agent not running or map not pinned yet - silently retry */
            continue;
        }

        __u64 drop_cpu[MAX_CPUS] = {0};
        __u64 pass_cpu[MAX_CPUS] = {0};
        __u32 key_drop = 0, key_pass = 1;
        bpf_map_lookup_elem(map_fd, &key_drop, drop_cpu);
        bpf_map_lookup_elem(map_fd, &key_pass, pass_cpu);
        close(map_fd);

        /* Aggregate per-CPU values */
        __u64 total_drop = 0, total_pass = 0;
        for (int i = 0; i < MAX_CPUS; i++) {
            total_drop += drop_cpu[i];
            total_pass += pass_cpu[i];
        }

        /* Report to Webdis (TTL 60s - longer than poll interval) */
        CURL *curl = curl_easy_init();
        if (curl) {
            char url[512];
            /* drop counter */
            snprintf(url, sizeof(url), "%s/SET/xdp_drop_total/%llu/EX/60",
                     webdis_base, (unsigned long long)total_drop);
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L);
            curl_easy_perform(curl);

            /* pass counter */
            snprintf(url, sizeof(url), "%s/SET/xdp_pass_total/%llu/EX/60",
                     webdis_base, (unsigned long long)total_pass);
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_perform(curl);
            curl_easy_cleanup(curl);

            printf("[XDP-Counter] DROP=%llu PASS=%llu -> Webdis OK\n",
                   (unsigned long long)total_drop, (unsigned long long)total_pass);
            fflush(stdout);
        }
    }
    return NULL;
}


struct tx_event {
    __u32 pid;
    __u32 uid;
    char comm[16];
    __u32 src_ip;
    __u16 src_port;
    __u32 dst_ip;
    __u16 dst_port;
    __u64 t_tx;
};

void generate_trace_id(char *out) {
    FILE *f = fopen("/dev/urandom", "r");
    unsigned char buf[16];
    fread(buf, 1, 16, f);
    fclose(f);
    for (int i = 0; i < 16; i++) {
        sprintf(out + (i * 2), "%02x", buf[i]);
    }
    out[32] = '\0';
}

void generate_parent_id(char *out) {
    FILE *f = fopen("/dev/urandom", "r");
    unsigned char buf[8];
    fread(buf, 1, 8, f);
    fclose(f);
    for (int i = 0; i < 8; i++) {
        sprintf(out + (i * 2), "%02x", buf[i]);
    }
    out[16] = '\0';
}

// Note: Removed SHA256 keying to align with attack and Vector raw_key format

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct tx_event *e = data;
    
    // Calculate clock offset
    struct timespec ts_real, ts_mono;
    clock_gettime(CLOCK_REALTIME, &ts_real);
    clock_gettime(CLOCK_MONOTONIC, &ts_mono);
    long long t_real_ns = (long long)ts_real.tv_sec * 1000000000LL + ts_real.tv_nsec;
    long long t_mono_ns = (long long)ts_mono.tv_sec * 1000000000LL + ts_mono.tv_nsec;
    long long offset = t_real_ns - t_mono_ns;
    long long t_tx_epoch = e->t_tx + offset;

    struct in_addr src, dst;
    src.s_addr = e->src_ip;
    dst.s_addr = e->dst_ip;
    
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src, src_ip_str, sizeof(src_ip_str));
    inet_ntop(AF_INET, &dst, dst_ip_str, sizeof(dst_ip_str));

    char trace_id[33];
    char parent_id[17];
    generate_trace_id(trace_id);
    generate_parent_id(parent_id);

    // Build raw_key to use source IP and ephemeral port as specified in Phase4-4-2 plan
    char raw_key[128];
    snprintf(raw_key, sizeof(raw_key), "%s:%u", src_ip_str, e->src_port);

    char payload[256];
    snprintf(payload, sizeof(payload), "{\"trace_id\":\"%s\",\"parent_span_id\":\"%s\"}", trace_id, parent_id);

    const char *webdis_url_env = getenv("WEBDIS_URL");
    const char *webdis_base = webdis_url_env != NULL ? webdis_url_env : "http://127.0.0.1:7379";

    // URL encode payload (but keep raw_key un-hashed/un-encoded to match Vector GET)
    CURL *curl = curl_easy_init();
    if(curl) {
        char *encoded_payload = curl_easy_escape(curl, payload, strlen(payload));
        char url[512];
        snprintf(url, sizeof(url), "%s/SET/%s/%s/EX/30", webdis_base, raw_key, encoded_payload);
        
        curl_easy_setopt(curl, CURLOPT_URL, url);
        CURLcode res = curl_easy_perform(curl);
        
        // Capture T_reg immediately after HTTP request completes
        struct timespec ts_reg;
        clock_gettime(CLOCK_REALTIME, &ts_reg);
        long long t_reg_ns = (long long)ts_reg.tv_sec * 1000000000LL + ts_reg.tv_nsec;

        if(res != CURLE_OK) {
            fprintf(stderr, "    [-] Webdis request failed: %s\n", curl_easy_strerror(res));
        } else {
            // Output structured JSON for Race Condition Analysis
            printf("{\"trace_id\":\"%s\",\"t_tx_epoch\":%lld,\"t_reg\":%lld,\"status\":\"hit\"}\n", trace_id, t_tx_epoch, t_reg_ns);
        }
        curl_free(encoded_payload);
        curl_easy_cleanup(curl);
    }
    
    return 0;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *enable_oob = getenv("ENABLE_OOB");
    if (enable_oob == NULL || strcmp(enable_oob, "1") != 0) {
        printf("[TX-Vanguard] ENABLE_OOB!=1. Sleeping forever to simulate inactive quadrant.\n");
        while(1) { sleep(60); }
        return 0;
    }

    printf("[TX-Vanguard] Starting eBPF TX Enforcer...\n");

    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    setrlimit(RLIMIT_MEMLOCK, &rlim);

    printf("[TX-Vanguard] Opening BPF skeleton...\n");
    struct tx_prog_bpf *skel = tx_prog_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    printf("[TX-Vanguard] Loading BPF skeleton...\n");
    int err = tx_prog_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        tx_prog_bpf__destroy(skel);
        return 1;
    }

    printf("[TX-Vanguard] Attaching BPF skeleton...\n");
    err = tx_prog_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        tx_prog_bpf__destroy(skel);
        return 1;
    }

    printf("[TX-Vanguard] Creating ring buffer...\n");
    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        tx_prog_bpf__destroy(skel);
        return 1;
    }

    printf("[TX-Vanguard] Attached kprobe to tcp_sendmsg successfully.\n");

    /* Start counter polling thread (reads xdp_counter_map pinned by ebpf_agent) */
    const char *webdis_url_env_main = getenv("WEBDIS_URL");
    const char *webdis_base = (webdis_url_env_main != NULL) ? webdis_url_env_main : "http://127.0.0.1:7379";
    pthread_t counter_tid;
    counter_args_t cargs = { .webdis_base = webdis_base };
    if (pthread_create(&counter_tid, NULL, counter_poll_thread, &cargs) != 0) {
        fprintf(stderr, "[TX-Vanguard] Warning: failed to start counter poll thread\n");
    } else {
        pthread_detach(counter_tid);
        printf("[TX-Vanguard] XDP counter poll thread started (interval=%ds)\n", COUNTER_POLL_SEC);
    }


    while (1) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err == -EINTR)
            break;
        if (err < 0) {
            printf("Error polling ring buffer: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    tx_prog_bpf__destroy(skel);
    return 0;
}
