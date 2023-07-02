// Copyright 2023 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

#ifndef __JHASH_H_
#define __JHASH_H_

#ifndef  __jhash_test
#include "vmlinux.h"
#endif

// Taken from linux kernel

/**
 * rol32 - rotate a 32-bit value left
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline __u32 rol32(__u32 word, unsigned int shift)
{
    return (word << (shift & 31)) | (word >> ((-shift) & 31));
}

/* __jhash_final - final mixing of 3 32-bit values (a,b,c) into c */
#define __jhash_final(a, b, c)                                                 \
    {                                                                          \
        c ^= b;                                                                \
        c -= rol32(b, 14);                                                     \
        a ^= c;                                                                \
        a -= rol32(c, 11);                                                     \
        b ^= a;                                                                \
        b -= rol32(a, 25);                                                     \
        c ^= b;                                                                \
        c -= rol32(b, 16);                                                     \
        a ^= c;                                                                \
        a -= rol32(c, 4);                                                      \
        b ^= a;                                                                \
        b -= rol32(a, 14);                                                     \
        c ^= b;                                                                \
        c -= rol32(b, 24);                                                     \
    }

/* An arbitrary initial parameter */
#define JHASH_INITVAL 0xdeadbeef

/* Programmatically mark implicit fallthroughs for GCC and Clang. */
#ifndef __has_attribute
#define __has_attribute(x) 0
#endif
#if __has_attribute(__fallthrough__)
#define JHASH_FALLTHROUGH __attribute__((__fallthrough__))
#else
#define JHASH_FALLTHROUGH                                                      \
    do {                                                                       \
    } while (0)
#endif

/* jhash - hash an arbitrary key
 * @k: sequence of bytes as key
 * @length: the length of the key
 * @initval: the previous hash, or an arbitray value
 *
 * The generic version, hashes an arbitrary sequence of bytes.
 * No alignment or length assumptions are made about the input key.
 *
 * Returns the hash value of the key. The result depends on endianness.
 */
static inline u32 jhash(const void *key, u32 length, u32 initval)
{
    u32 a, b, c;
    const u8 *k = key;

    /* Set up the internal state */
    a = b = c = JHASH_INITVAL + length + initval;

    /* All but the last block: affect some 32 bits of (a,b,c) */
    if (length > 12) // ignore this case
        return c;

    /* Last block: affect all 32 bits of (c) */
    switch (length) {
    case 12:
        c += (u32)k[11] << 24;
        JHASH_FALLTHROUGH;
    case 11:
        c += (u32)k[10] << 16;
        JHASH_FALLTHROUGH;
    case 10:
        c += (u32)k[9] << 8;
        JHASH_FALLTHROUGH;
    case 9:
        c += k[8];
        JHASH_FALLTHROUGH;
    case 8:
        b += (u32)k[7] << 24;
        JHASH_FALLTHROUGH;
    case 7:
        b += (u32)k[6] << 16;
        JHASH_FALLTHROUGH;
    case 6:
        b += (u32)k[5] << 8;
        JHASH_FALLTHROUGH;
    case 5:
        b += k[4];
        JHASH_FALLTHROUGH;
    case 4:
        a += (u32)k[3] << 24;
        JHASH_FALLTHROUGH;
    case 3:
        a += (u32)k[2] << 16;
        JHASH_FALLTHROUGH;
    case 2:
        a += (u32)k[1] << 8;
        JHASH_FALLTHROUGH;
    case 1:
        a += k[0];
        __jhash_final(a, b, c);
        break;
    case 0: /* Nothing left to add */
        break;
    }

    return c;
}

#endif // __JHASH_H_