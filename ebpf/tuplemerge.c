/**
 * Copyright 2023 Leon Hwang.
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "bpf_all.h"

#ifdef __USE_HASH_KERN
extern __u32 jhash(const void *key, __u32 length, __u32 initval) __ksym;
#else
#include "jhash.h"
#endif

#define RULE_BUCKETS_NUM 0x8000

struct acl_rule_table {
    __u32 id;
    __be32 smask;
    __be32 dmask;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 0x80);
    __type(key, __u32);
    __type(value, struct acl_rule_table);
} acl_tables SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, RULE_BUCKETS_NUM);
    __type(key, __u32);
    __type(value, __u32);
} acl_rule_buckets SEC(".maps");

struct acl_rule {
    __u32 table_id;
    __u32 hash;
    __u8 protocol;
    __be32 saddr;
    __be32 smask;
    __be32 daddr;
    __be32 dmask;
    __be16 sport_start;
    __be16 sport_end;
    __be16 dport_start;
    __be16 dport_end;
    __u8 action;
    __u16 _pad;
} __attribute__((packed));

#define __sizeof_acl_rule (sizeof(struct acl_rule))

struct acl_rule_hash_key {
    __be32 saddr;
    __be32 daddr;
    __u8 protocol;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __uint(map_flags, BPF_F_INNER_MAP);
    __type(key, __u32);
    __type(value, struct acl_rule);
} acl_rules SEC(".maps");

struct packet {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
    __u8 protocol;
};

struct rule_matching {
    struct packet pkt;
    __u32 table_id;
    __u32 hash;

    __u8 matched;
    __u8 action;

    __u8 pad;
} __attribute__((aligned(4)));

static __always_inline bool __match_rule(
    struct acl_rule *rule, struct packet *pkt)
{
    return ((rule->protocol == pkt->protocol) &&
        (rule->saddr == (pkt->saddr & rule->smask)) &&
        (rule->daddr == (pkt->daddr & rule->dmask)) &&
        (pkt->protocol == IPPROTO_ICMP || // tcp/udp
            (((rule->sport_start <= pkt->sport) &&
                 (pkt->sport <= rule->sport_end)) &&
                ((rule->dport_start <= pkt->dport) &&
                    (pkt->dport <= rule->dport_end)))));
}

static int __iterate_rules(struct bpf_map *map, const __u32 *key,
    struct acl_rule *value, struct rule_matching *match)
{

    if (match->table_id != value->table_id)
        return 0;
    if (match->hash != value->hash)
        return 0;

    if (__match_rule(value, &match->pkt)) {
        match->matched = 1;
        match->action = value->action;
        return 1;
    }

    return 0;
}

static int __iterate_tables(struct bpf_map *map, const __u32 *key,
    struct acl_rule_table *value, struct rule_matching *match)
{
    struct acl_rule_hash_key hash_key = {
        .saddr = match->pkt.saddr & value->smask,
        .daddr = match->pkt.daddr & value->dmask,
        .protocol = match->pkt.protocol,
    };

    match->table_id = value->id;
    match->hash = jhash(&hash_key, 9, value->id);

    __u32 index = match->hash & (RULE_BUCKETS_NUM - 1);
    void *inner_map = bpf_map_lookup_elem(&acl_rule_buckets, &index);
    if (!inner_map)
        return 0;

    bpf_for_each_map_elem(inner_map, __iterate_rules, match, 0);

    return match->matched ? 1 : 0;
}

static __always_inline int match_acl_rules(struct xdp_md *ctx)
{
    struct rule_matching match = { 0 };

    struct ethhdr *eth = (struct ethhdr *)ctx_ptr(ctx, data);
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    struct udphdr *udph = (struct udphdr *)(iph + 1);
    VALIDATE_HEADER(udph, ctx);

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    bool is_tcp_udp =
        (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP);
    bool is_icmp = (iph->protocol == IPPROTO_ICMP);

    if (is_tcp_udp) {
        match.pkt.sport = udph->source;
        match.pkt.dport = udph->dest;
    } else if (is_icmp) {
        // do nothing
    } else {
        return XDP_PASS;
    }

    match.pkt.saddr = iph->saddr;
    match.pkt.daddr = iph->daddr;
    match.pkt.protocol = iph->protocol;

    bpf_for_each_map_elem(&acl_tables, __iterate_tables, &match, 0);

    return match.matched ? match.action : XDP_PASS;
}

SEC("xdp")
int xdp_acl(struct xdp_md *ctx) { return match_acl_rules(ctx); }