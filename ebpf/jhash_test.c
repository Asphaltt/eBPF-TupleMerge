/**
 * Copyright 2023 Leon Hwang.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>

typedef signed char __s8;

typedef unsigned char __u8;

typedef short int __s16;

typedef short unsigned int __u16;

typedef int __s32;

typedef unsigned int __u32;

typedef long long int __s64;

typedef long long unsigned int __u64;

typedef __s8 s8;

typedef __u8 u8;

typedef __s16 s16;

typedef __u16 u16;

typedef __s32 s32;

typedef __u32 u32;

typedef __s64 s64;

typedef __u64 u64;

typedef __u16 __be16;

typedef __u32 __be32;

#define __jhash_test

#include "jhash.h"

struct acl_rule_hash_key {
    __be32 saddr;
    __be32 daddr;
    __u8 protocol;
} __attribute__((packed));

int main()
{
    struct acl_rule_hash_key key;
    key.saddr = 0x0001A8C0;
    key.daddr = 0x0001A8C0;
    key.protocol = 0x01;

    u32 hash = jhash(&key, 9, 1);
    printf("hash1 (icmp): %x\n", hash);

    key.protocol = 6;
    hash = jhash(&key, 9, 1);
    printf("hash1 (tcp): %x\n", hash);

    key.protocol = 17;
    hash = jhash(&key, 9, 1);
    printf("hash1 (udp): %x\n", hash);

    key.saddr = 0xC0A80100;
    key.daddr = 0xC0A80100;
    key.protocol = 0x01;

    hash = jhash(&key, sizeof(key), 1);
    printf("hash2: %x\n", hash);

    return 0;
}