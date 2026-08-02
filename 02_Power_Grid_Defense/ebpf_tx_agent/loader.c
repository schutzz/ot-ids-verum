#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <curl/curl.h>
#include <openssl/sha.h>
#include "tx_prog.skel.h"

struct tx_event {
    __u32 pid;
    __u32 uid;
    char comm[16];
    __u32 src_ip;
    __u32 dst_ip;
    __u16 dst_port;
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

void compute_sha256(const char *input, char *output) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input, strlen(input));
    SHA256_Final(hash, &sha256);
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[64] = '\0';
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct tx_event *e = data;
    struct in_addr src, dst;
    src.s_addr = e->src_ip;
    dst.s_addr = e->dst_ip;
    
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src, src_ip_str, sizeof(src_ip_str));
    inet_ntop(AF_INET, &dst, dst_ip_str, sizeof(dst_ip_str));

    printf("[TX-Vanguard] Detected DNP3 Packet Send!\n");
    printf("    -> PID: %u, UID: %u, COMM: %s\n", e->pid, e->uid, e->comm);
    printf("    -> Src: %s, Dst: %s:%d\n", src_ip_str, dst_ip_str, e->dst_port);

    char trace_id[33];
    char parent_id[17];
    generate_trace_id(trace_id);
    generate_parent_id(parent_id);

    // Hardcode function code 5 for DNP3 Direct Operate hook
    char raw_key[128];
    snprintf(raw_key, sizeof(raw_key), "%s:%s:%d:5", src_ip_str, dst_ip_str, e->dst_port);
    
    char hash_key[65];
    compute_sha256(raw_key, hash_key);

    char payload[256];
    snprintf(payload, sizeof(payload), "{\"trace_id\":\"%s\",\"parent_span_id\":\"%s\"}", trace_id, parent_id);
    
    // URL encode payload
    CURL *curl = curl_easy_init();
    if(curl) {
        char *encoded_payload = curl_easy_escape(curl, payload, strlen(payload));
        char url[512];
        snprintf(url, sizeof(url), "http://127.0.0.1:7379/SET/%s/%s/EX/5", hash_key, encoded_payload);
        
        curl_easy_setopt(curl, CURLOPT_URL, url);
        CURLcode res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            fprintf(stderr, "    [-] Webdis request failed: %s\n", curl_easy_strerror(res));
        } else {
            printf("    -> [TX-Vanguard] FORCED OOB Registration Success! TraceID=%s\n", trace_id);
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
