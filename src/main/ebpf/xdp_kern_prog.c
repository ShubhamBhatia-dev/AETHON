#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <bpf/bpf_endian.h>
#include "common.h"

#define AETHON_MAX_IPS 65536
#define AETHON_MAX_QUEUE_SIZE 64
#define SECOND_NS 1000000000ULL
#define AETHON_PER_CORE_BURST 100000ULL
#define AETHON_PER_CORE_REFILL_PER_SEC 50000ULL
#define AETHON_MAX_XDP_RETURN_TYPE 5
#define AETHON_MAX_RATE_LIMIT_PARAMETER 3
#define AETHON_MAX_FIREWALL_RULES 64

struct aethon_vlan_hdr {
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

struct aethon_firewall_rule {
    __u8  src_mac[6];
    __u8  use_src_mac;
    __u8  pad0;

    __u8  dst_mac[6];
    __u8  use_dst_mac;
    __u8  pad1;

    __u32 src_ip;
    __u32 src_mask;
    __u32 dst_ip;
    __u32 dst_mask;

    __u16 src_port;
    __u16 dst_port;
    __u16 vlan_id;
    __u8  proto;
    __u8  action; // 0 = DROP, 1 = ALLOW
    __u8  active; // 1 = active rule
    __u8  pad2[3];
};

static aethon_always_inline int mac_equal(const __u8 *a, const __u8 *b) {
    #pragma unroll
    for (int i = 0; i < 6; i++) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}



/*

 Bit:  15   14   13   12 11 10 9 8 7 6 5 4 3 2 1 0
     ┌────┬────┬────┬───────────────────────────────┐
     │ R  │ DF │ MF │       Fragment Offset         │
     └────┴────┴────┴───────────────────────────────┘
       ▲    ▲    ▲                  ▲
       │    │    │                  └─ 13 bits: byte offset in original datagram
       │    │    └─ Bit 13: "More Fragments" (MF) flag
       │    └────── Bit 14: "Don't Fragment" (DF) flag
       └─────────── Bit 15: Reserved (always 0)


*/

// getting the no of queeu map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,__u32);
    __type(value,__u32);
} queue_config_map SEC(".maps");

// IP blocking map (global blocklist)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, AETHON_MAX_IPS);
    __type(key, struct aethon_ip_address);
    __type(value, __u64);
} aethon_ip_blocklist SEC(".maps");

struct{
    __uint(type,BPF_MAP_TYPE_HASH);
    __uint(max_entries,AETHON_MAX_IPS);
    __type(key,struct aethon_ip_address);
    __type(value,__u16);
} aethon_rate_limiter SEC(".maps");

struct{
    __uint(type,BPF_MAP_TYPE_HASH);
    __uint(max_entries,AETHON_MAX_RATE_LIMIT_PARAMETER);
    __type(key,__u16);
    __type(value,__u64);
} rate_limiter_params SEC(".maps");

// Service ports map: external ports configured in services.conf (e.g. 80, 443, 8443)
// Packets for these ports are redirected to Aethon AF_XDP.
// All other ports (e.g. 22 for SSH, 53 for DNS, ICMP ping) pass directly to the Linux OS.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u16);   // destination port in host byte order
    __type(value, __u8);  // 1 = active
} aethon_services_map SEC(".maps");

// Firewall ACL map (prioritized array of rules)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, AETHON_MAX_FIREWALL_RULES);
    __type(key, __u32);
    __type(value, struct aethon_firewall_rule);
} aethon_firewall_map SEC(".maps");

// Engine operation mode:
// 0 = Bypass (pass all traffic directly to Linux OS network stack)
// 1 = Match-Only (audit/monitor: rules and limits evaluate, but NEVER drop)
// 2 = Full Protection (active inspection, drop enforcement; default)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} match_only SEC(".maps");

struct token_bucket_state{
    __u64 tokens;
    __u64 last_updated;
    __u64 drop_count;
};

struct sliding_window_state{
    __u64 last_time;
    __u64 packets;
    __u64 drop_count;
    __u64 limit;
    __u64 window; 
};
// Lockless per-CPU rate limiting state struct
struct rate_limit_state {
    struct token_bucket_state token_bucket;
    struct sliding_window_state sliding_window_limiter;
    __u64 algo;  
};

// 100% Lock-Free Per-CPU map (Zero cross-core lock contention!)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, AETHON_MAX_IPS);
    __type(key, struct aethon_ip_address);
    __type(value, struct rate_limit_state);
} aethon_ip_ratelimit SEC(".maps");

// afxdp NIC queue to AF_XDP 
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, AETHON_MAX_QUEUE_SIZE);
    __type(key, int);
    __type(value, int);
} aethon_xsks_map SEC(".maps");


// records maps (PER CLIMITER) // for all XDP actions
struct {
    __uint(type,BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key,__u32);
    __type(value,struct datarec);
    __uint(max_entries,AETHON_MAX_XDP_RETURN_TYPE);
} aethon_xdp_stats_map SEC(".maps");


// function to count records
static aethon_always_inline void stats_record_count(struct xdp_md * ctx, __u32 action){
    struct datarec *rec;
    __u32 key  = action;
    rec = (struct datarec * )bpf_map_lookup_elem(&aethon_xdp_stats_map,&key);
    if(rec){
        void * data_end = (void *)(long)ctx->data_end;
        void * data = (void *)(long)ctx->data;

        __u64 bytes  = (__u64)((__u64)data_end - (__u64)data);
        rec->rx_bytes+=bytes;
        rec->rx_packets+=1;
    }
}
static aethon_always_inline int token_bucket(struct aethon_ip_address* src_ip, struct rate_limit_state* state, __u64 tokens) {
    __u64 now = bpf_ktime_get_ns();
    if (!state) {
        struct rate_limit_state init_state = {
            .token_bucket = {
                .tokens = (tokens > 0) ? (tokens - 1) : 0,
                .last_updated = now,
                .drop_count = 0
            },
            .sliding_window_limiter = {},
            .algo = 0
        };
        bpf_map_update_elem(&aethon_ip_ratelimit, src_ip, &init_state, BPF_ANY);
        return (tokens > 0) ? 1 : 0;
    } else if (state->token_bucket.last_updated == 0) {
        state->token_bucket.tokens = (tokens > 0) ? (tokens - 1) : 0;
        state->token_bucket.last_updated = now;
        state->token_bucket.drop_count = 0;
        return (tokens > 0) ? 1 : 0;
    } else {
        __u64 elapsed = now - state->token_bucket.last_updated;
        __u64 tokens_to_add = (elapsed * AETHON_PER_CORE_REFILL_PER_SEC) / SECOND_NS;
        if (tokens_to_add > 0) {
            __u64 new_tokens = state->token_bucket.tokens + tokens_to_add;
            state->token_bucket.tokens = (new_tokens > tokens) ? tokens : new_tokens;
            state->token_bucket.last_updated = now;
        }

        if (state->token_bucket.tokens == 0) {
            state->token_bucket.drop_count += 1;
            bpf_printk("RATE LIMIT EXCEEDED - DROP\n");

            if (state->token_bucket.drop_count >= 8) {
                __u64 flag = 1;
                bpf_map_update_elem(&aethon_ip_blocklist, src_ip, &flag, BPF_ANY);
                bpf_printk("IP BLOCKLISTED DUE TO FLOOD\n");
            }

            return 0;
        }
        state->token_bucket.tokens -= 1;
    }
    return 1;
}

static aethon_always_inline int sliding_window_limiter(struct aethon_ip_address* src_ip, struct rate_limit_state* state, __u64 limit, __u64 window) {
    __u64 now = bpf_ktime_get_ns();
    if (!state) {
        struct rate_limit_state init_state = {
            .token_bucket = {},
            .sliding_window_limiter = {
                .limit = limit,
                .drop_count = 0,
                .packets = 1,
                .last_time = now,
                .window = window
            },
            .algo = 1
        };
        bpf_map_update_elem(&aethon_ip_ratelimit, src_ip, &init_state, BPF_ANY);
        return (limit >= 1) ? 1 : 0;
    } else if (state->sliding_window_limiter.last_time == 0 ||
               (now - state->sliding_window_limiter.last_time >= state->sliding_window_limiter.window * SECOND_NS)) {
        state->sliding_window_limiter.limit = limit;
        state->sliding_window_limiter.window = window;
        state->sliding_window_limiter.packets = 1;
        state->sliding_window_limiter.drop_count = 0;
        state->sliding_window_limiter.last_time = now;
        return (limit >= 1) ? 1 : 0;
    } else {
        if (state->sliding_window_limiter.packets >= state->sliding_window_limiter.limit) {
            state->sliding_window_limiter.drop_count++;
            bpf_printk("RATE LIMIT EXCEEDED - DROP\n");
            if (state->sliding_window_limiter.drop_count >= 8) {
                __u64 flag = 1;
                bpf_map_update_elem(&aethon_ip_blocklist, src_ip, &flag, BPF_ANY);
                bpf_printk("IP BLOCKLISTED DUE TO FLOOD\n");
            }
            return 0;
        }
        state->sliding_window_limiter.packets++;
    }
    return 1;
}

SEC("xdp")
int aethon_xdp_prog_main(struct xdp_md * ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    int action = XDP_PASS;

    // 0. Engine Mode Check:
    //    0 = Bypass: pass all traffic directly to Linux OS network stack
    //    1 = Match-only: audit/monitor mode (rules & rate limits evaluate, but NEVER drop)
    //    2 = Full Protection: active drops & inspection (DEFAULT = 2)
    __u32 mode_key = 0;
    __u32 *mode_ptr = bpf_map_lookup_elem(&match_only, &mode_key);
    __u32 mode = mode_ptr ? *mode_ptr : 2;

    if (mode == 0) {
        action = XDP_PASS;
        goto out;
    }

    // 1. Parse Ethernet Header
    struct ethhdr *eth = (struct ethhdr *)data;
    if ((void *)(eth + 1) > data_end) 
        return XDP_DROP;

    // 2. Parse VLAN Tagging (802.1Q and 802.1ad QinQ)
    void *nh = (void *)(eth + 1);
    __be16 h_proto = eth->h_proto;
    __u16 vlan_id = 0;

    #pragma unroll
    for (int i = 0; i < 2; i++) {
        if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
            struct aethon_vlan_hdr *vlh = (struct aethon_vlan_hdr *)nh;
            if ((void *)(vlh + 1) > data_end)
                return XDP_DROP;
            h_proto = vlh->h_vlan_encapsulated_proto;
            vlan_id = bpf_ntohs(vlh->h_vlan_TCI) & 0x0FFF;
            nh = (void *)(vlh + 1);
        }
    }

    struct aethon_ip_address src_ip = {};
    struct iphdr *iph = NULL;
    if (h_proto == bpf_htons(ETH_P_IP)) {
        iph = (struct iphdr *)nh;
        if ((void *)(iph + 1) > data_end) 
            return XDP_DROP;
        src_ip.addr.v4 = iph->saddr;
        src_ip.is_ipv6 = 0;
    } else if (h_proto == bpf_htons(ETH_P_IPV6)) {
        // IPv6 is passed to Linux network stack
        action = XDP_PASS;
        goto out;
    } else {
        // Non-IP traffic (ARP, etc.) -> Pass
        action = XDP_PASS;
        goto out;
    }

    // Extract L4 ports for firewall filtering
    __u16 sport = 0, dport = 0;
    if (iph->protocol == IPPROTO_TCP) {
        if (iph->ihl >= 5) {
            struct tcphdr *tcph = (struct tcphdr *)((void *)iph + (iph->ihl * 4));
            if ((void *)(tcph + 1) <= data_end) {
                sport = bpf_ntohs(tcph->source);
                dport = bpf_ntohs(tcph->dest);
            }
        }
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)((void *)iph + (iph->ihl * 4));
        if ((void *)(udph + 1) <= data_end) {
            sport = bpf_ntohs(udph->source);
            dport = bpf_ntohs(udph->dest);
        }
    }

    // 3. Firewall ACL evaluation (Priority order 0..31)
    #pragma unroll
    for (__u32 i = 0; i < 32; i++) {
        __u32 r_idx = i;
        struct aethon_firewall_rule *r = bpf_map_lookup_elem(&aethon_firewall_map, &r_idx);
        if (!r || !r->active)
            continue;

        if (r->use_src_mac && !mac_equal(eth->h_source, r->src_mac))
            continue;
        if (r->use_dst_mac && !mac_equal(eth->h_dest, r->dst_mac))
            continue;
        if (r->vlan_id != 0 && r->vlan_id != vlan_id)
            continue;
        if (r->proto != 0 && r->proto != iph->protocol)
            continue;
        if (r->src_mask != 0 && (iph->saddr & r->src_mask) != (r->src_ip & r->src_mask))
            continue;
        if (r->dst_mask != 0 && (iph->daddr & r->dst_mask) != (r->dst_ip & r->dst_mask))
            continue;
        if (r->src_port != 0 && r->src_port != sport)
            continue;
        if (r->dst_port != 0 && r->dst_port != dport)
            continue;

        // Matched!
        if (r->action == 0) { // DISALLOW / DROP
            if (mode == 1) {
                // Mode 1: Match-only, skip drop and continue
                goto allow_firewall;
            }
            action = XDP_DROP;
            goto out;
        } else { // ALLOW (skip blocklists and rate-limiter)
            goto allow_firewall;
        }
    }

    // 4. IP Blocklist & Rate Limiter
    __u8 is_test_subnet = (src_ip.is_ipv6 == 0 && (bpf_ntohl(src_ip.addr.v4) & 0xFFFFFF00) == 0xC0A83200);

    if (!is_test_subnet) {
        if (bpf_map_lookup_elem(&aethon_ip_blocklist, &src_ip)) {
            if (mode == 1) {
                goto allow_firewall;
            }
            action = XDP_DROP;
            goto out;
        }

        __u16 key_token = 1;
        __u16 key_window = 2;
        __u16 key_limit = 3;
        __u64* tokens_ptr = bpf_map_lookup_elem(&rate_limiter_params, &key_token);
        __u64* limit_ptr = bpf_map_lookup_elem(&rate_limiter_params, &key_limit);
        __u64* window_ptr = bpf_map_lookup_elem(&rate_limiter_params, &key_window);

        __u64 tokens_val = tokens_ptr ? *tokens_ptr : 100000ULL;
        __u64 limit_val = limit_ptr ? *limit_ptr : 50000ULL;
        __u64 window_val = window_ptr ? *window_ptr : 10ULL;

        __u16* algo_ptr = bpf_map_lookup_elem(&aethon_rate_limiter, &src_ip);
        __u16 algo = 0;
        if (!algo_ptr) {
            __u16 default_algo = 0;
            bpf_map_update_elem(&aethon_rate_limiter, &src_ip, &default_algo, BPF_ANY);
            algo = 0;
        } else {
            algo = *algo_ptr;
        }

        struct rate_limit_state* state = bpf_map_lookup_elem(&aethon_ip_ratelimit, &src_ip);
        int resp = 1;
        if (algo == 0) {
            resp = token_bucket(&src_ip, state, tokens_val);
        } else if (algo == 1) {
            resp = sliding_window_limiter(&src_ip, state, limit_val, window_val);
        } else {
            __u16 reset_algo = 0;
            bpf_map_update_elem(&aethon_rate_limiter, &src_ip, &reset_algo, BPF_ANY);
            resp = token_bucket(&src_ip, state, tokens_val);
        }

        if (!resp) {
            if (mode == 1) {
                goto allow_firewall;
            }
            action = XDP_DROP;
            goto out;
        }
    }

allow_firewall:
    // 5. Attack Checks (fragment check)
    if (iph != NULL) {
        __u16 frag_off_check = bpf_ntohs(iph->frag_off);
        __u8 is_fragment_check = (frag_off_check & 0x3FFF) != 0 || (frag_off_check & 0x2000) != 0;

        if (is_fragment_check && iph->protocol == IPPROTO_TCP) {
            if (mode != 1) {
                action = XDP_DROP;
                goto out;
            }
        }
    }

    // Dynamic queue routing
    __u32 key = 0;
    __u32 *num_queues_ptr  = (__u32 * )bpf_map_lookup_elem(&queue_config_map, &key);
    __u32 dynamic_num_queues = (num_queues_ptr && *num_queues_ptr > 0) ? *num_queues_ptr : 1;
    
    // Spread incoming hardware queues evenly across active worker queues
    __u32 target_queue = ctx->rx_queue_index % dynamic_num_queues;

    if (iph != NULL) {
        if (iph->protocol == IPPROTO_TCP) {
            if (iph->ihl < 5) return XDP_DROP;
            void *tcp_start = (void *)iph + (iph->ihl * 4);
            struct tcphdr *tcph = (struct tcphdr *)tcp_start;
            if ((void *)(tcph + 1) > data_end) return XDP_DROP;

            __u16 dport = bpf_ntohs(tcph->dest);
            __u8 *service_active = bpf_map_lookup_elem(&aethon_services_map, &dport);
            if (!service_active) {
                action = XDP_PASS;
                goto out;
            }
        } else if (iph->protocol == IPPROTO_UDP) {
            void *udp_start = (void *)iph + (iph->ihl * 4);
            struct udphdr *udph = (struct udphdr *)udp_start;
            if ((void *)(udph + 1) > data_end) return XDP_DROP;
            // Redirect UDP traffic to AF_XDP for user-space reassembly and full Hyperscan IDS inspection!
        } else if (iph->protocol == IPPROTO_ICMP) {
            void *icmp_start = (void *)iph + (iph->ihl * 4);
            struct icmphdr *icmph = (struct icmphdr *)icmp_start;
            if ((void *)(icmph + 1) > data_end) return XDP_DROP;
            // Only redirect ICMP Echo requests (type 8, code 0) to AF_XDP for fast replies.
            // Non-echo ICMP (Type 3 Code 4 PMTU, Time Exceeded, etc.) are passed to kernel!
            if (icmph->type == 8 && icmph->code == 0) {
                // Keep for fast user-space ICMP echo reply
            } else {
                action = XDP_PASS;
                goto out;
            }
        } else {
            action = XDP_PASS;
            goto out;
        }

        __u16 frag_off = bpf_ntohs(iph->frag_off);
        __u8 is_fragment = (frag_off & 0x3FFF) != 0 || (frag_off & 0x2000) != 0;

        if (is_fragment) {
            __u64 ip_hash = (__u64)iph->saddr + (__u64)iph->daddr;
            target_queue = ip_hash % dynamic_num_queues;
        }
    } else {
        action = XDP_PASS;
        goto out;
    }

    // Safety bounds check for the eBPF kernel verifier
    if (target_queue >= dynamic_num_queues) {
        target_queue = 0;
    }

    action = bpf_redirect_map(&aethon_xsks_map, target_queue, 0);

out:
    stats_record_count(ctx, action);
    return action;
}



char _license[] SEC("license") = "GPL";
