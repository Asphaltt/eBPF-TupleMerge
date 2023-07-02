<!--
 Copyright 2023 Leon Hwang.
 SPDX-License-Identifier: Apache-2.0
-->

# eBPF TupleMerge

This is a pure-bpf demo to implement TupleMerge online-classification algorithm.

It's not a generic implementation. It only works with IPv4 five-tuple.

## TupleMerge

TupleMerge is not a simple online-classification algorithm. It's expected to
perform lower operations (*lookup*, *add*, *delete*) cost than other algorithms.

- [TupleMerge: Fast Software Packet Processing for Online Packet Classification](https://nonsns.github.io/paper/rossi19ton.pdf)

Hence, it's really hard to implement it fully with pure-bpf. And, Anton
Protopopov from Isovalent commited a patch to implement a simplified version of
TupleMerge in kernel bpf.

- [[RFC PATCH] bpf: introduce new bpf map type BPF_MAP_TYPE_WILDCARD](https://lore.kernel.org/bpf/20220907080140.290413-1-aspsk@isovalent.com/)

Someone says, why not implement it with pure-bpf?

> As for eBPF, today is different from yesterday, and tomorrow is different from today.
>
> 与时俱进的 eBPF 早已今非昔比。 -- Leon Hwang

With Go+bpf, it's possible to implement a simplest version of TupleMerge.

> Required 5.15+ kernel.

### Go+bpf TupleMerge

Unlike the **BPF_MAP_TYPE_WILDCARD** patch, this implementation is not a generic
one. It only works with IPv4 five-tuple, whose rule description is fixed.

The rule description is:

```JSON
{
    "saddr": "10.11.12.0/24",
    "daddr": "192.168.1.0/24",
    "proto": "tcp",
    "dport": "22",
    "sport": "1024-65535",
    "action": "allow",
    "priority": 2
}
```

In XDP, it'll be:

```C
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
```

Then, in XDP, the matching process is:

1. Iterate ACL rule tables.
2. Hash it and get the bucket index in ACL rule buckets.
3. Get the inner bpf map from ACL rule buckets with the index.
4. Iterate the inner bpf map.
5. Match packet with `table_id`, `hash` and ACL rule.

- Check the source code: [tuplemerge.c](./ebpf/tuplemerge.c).

![TupleMerge](./tuplemerge%20layout.png)

And, it requires Go to prepare the ACL rule tables and ACL rule buckets.

### Go+bpf TupleMerge improvements

Currently, this demo does not support to add/delete ACL rules dynamically.

However, it's not hard to implement them.

And amazingly, it can replace a whole bpf map to reduce the operations impact to
XDP data plane. In other word, adding/deleting an ACL rule is costless for XDP.

#### Add ACL rule

1. Find a compatible ACL rule table.
2. Update the ACL rule table bpf map if requiring a new one.
3. Find a ACL rule bucket in the ACL rule buckets bpf map.
4. Add the ACL rule to the ACL rule bucket.
5. Update the ACL rule bucket to the ACL rule buckets bpf map.

#### Delete ACL rule

1. Find a compatible ACL rule table.
2. Delete the ACL rule table from the ACL rule tables bpf map if no ACL rule
   compatible with it.
3. Find a ACL rule bucket in the ACL rule buckets bpf map.
4. Delete the ACL rule from the ACL rule bucket.
5. Delete the ACL rule bucket from the ACL rule buckets bpf map if no ACL rule
   in it.
6. Or, update the ACL rule bucket to the ACL rule buckets bpf map.

### Go+bpf TupleMerge better performance

The performance of Go+bpf TupleMerge can be improved by less ACL rule tables and
smaller number of max ACL rules in a ACL rule bucket.

It can achieve the better performance this way to specific cases.

### Go+bpf TupleMerge scalability

Because of eBPF extensibility, it can run with a small capacity of ACL rule
buckets. Then, with more and more ACL rules, the ACL rule buckets can be scaled
with larger capacity with rebuilding the ACL rule tables bpf map.

It's a helpful feature to reduce the memory usage of ACL rule buckets when the
ACl rule number is small.

## Other XDP ACL implementations

Before TupleMerge, I've tried other XDP ACL implementations.

- Bitmap based: [XDP ACL](https://github.com/Asphaltt/xdp_acl)
- Iterating based: [iptables like XDP ACL](https://github.com/Asphaltt/iptables-in-bpf)

Bitmap based XDP ACL is learned from

1. [eBPF / XDP based firewall and packet filtering](http://vger.kernel.org/lpc_net2018_talks/ebpf-firewall-paper-LPC.pdf)
2. [Securing Linux with a Faster and Scalable Iptables](https://mbertrone.github.io/documents/21-Securing_Linux_with_a_Faster_and_Scalable_Iptables.pdf)

`iptables` like XDP ACL is iterating all rules one by one. It's not a good idea.

Comparing with them, TupleMerge is a better choice.
