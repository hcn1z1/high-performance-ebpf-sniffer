#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define EVENT_TYPE_CAPTURE 0
#define EVENT_TYPE_ALERT   1

struct packet_metadata {
    __u32 len;
    __u32 capture_len;
    __u32 event_type;
    __u32 src_ip;
};

struct rate_limit_entry {
    __u64 last_reset;
    __u32 count;
};

struct flow_metrics_t {
    __u64 first_seen;
    __u64 last_seen;
    __u64 sum_iat_us;
    __u64 sum_iat_sq_us;
    __u64 min_iat_us;
    __u64 max_iat_us;
    __u64 pkt_count;
    __u64 total_bytes;
    __u64 sum_pkt_len;
    __u64 sum_pkt_len_sq;
    __u64 max_pkt_len;
    __u64 cnt_syn;
    __u64 cnt_ack;
    __u64 cnt_rst;
    __u64 cnt_fin;
    __u64 sum_win_size;
    __u64 sum_ttl;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 10000);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct flow_metrics_t));
} flow_metrics_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct rate_limit_entry));
} rate_limit_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
} block_list_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} config_map SEC(".maps");

SEC("xdp")
int packet_monitor(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u64 now = bpf_ktime_get_ns();

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

    __u32 src_ip = ip->saddr;

    // Check Block List
    __u64 *expiry = bpf_map_lookup_elem(&block_list_map, &src_ip);
    if (expiry) {
        if (now < *expiry) {
            return XDP_DROP;
        } else {
            bpf_map_delete_elem(&block_list_map, &src_ip);
        }
    }

    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;

    // DDoS Detection (SYN Flood)
    if (tcp->syn && !tcp->ack) {
        __u32 key_idx = 0;
        __u32 *threshold_ptr = bpf_map_lookup_elem(&config_map, &key_idx);
        __u32 threshold = threshold_ptr ? *threshold_ptr : 100;

        struct rate_limit_entry *entry = bpf_map_lookup_elem(&rate_limit_map, &src_ip);
        if (!entry) {
            struct rate_limit_entry new_entry = { .last_reset = now, .count = 1 };
            bpf_map_update_elem(&rate_limit_map, &src_ip, &new_entry, BPF_ANY);
        } else {
            if (now - entry->last_reset > 1000000000) {
                entry->last_reset = now;
                entry->count = 1;
            } else {
                __sync_fetch_and_add(&entry->count, 1);
                if (entry->count > threshold) {
                    __u64 block_expiry = now + 120000000000ULL;
                    bpf_map_update_elem(&block_list_map, &src_ip, &block_expiry, BPF_ANY);

                    struct packet_metadata meta = {0};
                    meta.event_type = EVENT_TYPE_ALERT;
                    meta.src_ip = src_ip;
                    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &meta, sizeof(meta));

                    return XDP_DROP;
                }
            }
        }
    }

    // Packet Capture & Flow Metrics
    __u16 port443 = bpf_htons(443);
    if (tcp->source == port443 || tcp->dest == port443) {
        // Collect Ingress Flow Metrics (Client -> Server)
        if (tcp->dest == port443) {
            struct flow_metrics_t *metrics = bpf_map_lookup_elem(&flow_metrics_map, &src_ip);
            __u32 pkt_len = (__u32)(data_end - data);

            if (!metrics) {
                struct flow_metrics_t new_metrics = {0};
                new_metrics.first_seen = now;
                new_metrics.last_seen = now;
                new_metrics.pkt_count = 1;
                new_metrics.total_bytes = pkt_len;
                new_metrics.sum_pkt_len = pkt_len;
                new_metrics.sum_pkt_len_sq = (__u64)pkt_len * pkt_len;
                new_metrics.max_pkt_len = pkt_len;
                new_metrics.min_iat_us = 0xFFFFFFFFFFFFFFFFULL;
                new_metrics.max_iat_us = 0;

                if (tcp->syn) new_metrics.cnt_syn = 1;
                if (tcp->ack) new_metrics.cnt_ack = 1;
                if (tcp->rst) new_metrics.cnt_rst = 1;
                if (tcp->fin) new_metrics.cnt_fin = 1;

                new_metrics.sum_win_size = bpf_ntohs(tcp->window);
                new_metrics.sum_ttl = ip->ttl;

                bpf_map_update_elem(&flow_metrics_map, &src_ip, &new_metrics, BPF_ANY);
            } else {
                // Timing
                __u64 delta_us = (now - metrics->last_seen) / 1000;
                metrics->sum_iat_us += delta_us;
                metrics->sum_iat_sq_us += (delta_us * delta_us);
                if (delta_us < metrics->min_iat_us) metrics->min_iat_us = delta_us;
                if (delta_us > metrics->max_iat_us) metrics->max_iat_us = delta_us;
                metrics->last_seen = now;

                // Volume
                metrics->pkt_count++;
                metrics->total_bytes += pkt_len;
                metrics->sum_pkt_len += pkt_len;
                metrics->sum_pkt_len_sq += (__u64)pkt_len * pkt_len;
                if (pkt_len > metrics->max_pkt_len) metrics->max_pkt_len = pkt_len;

                // Flags
                if (tcp->syn) metrics->cnt_syn++;
                if (tcp->ack) metrics->cnt_ack++;
                if (tcp->rst) metrics->cnt_rst++;
                if (tcp->fin) metrics->cnt_fin++;

                metrics->sum_win_size += bpf_ntohs(tcp->window);
                metrics->sum_ttl += ip->ttl;
            }
        }

        __u32 tcp_header_len = tcp->doff * 4;
        void *payload = (void *)tcp + tcp_header_len;

        if (payload < data_end) {
             __u32 capture_len = (__u32)(data_end - data);
             if (capture_len > 1514) capture_len = 1514;

             struct packet_metadata meta = {0};
             meta.len = (__u32)(data_end - data);
             meta.capture_len = capture_len;
             meta.event_type = EVENT_TYPE_CAPTURE;

             __u64 flags = BPF_F_CURRENT_CPU;
             flags |= (__u64)capture_len << 32;

             bpf_perf_event_output(ctx, &events, flags, &meta, sizeof(meta));
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
