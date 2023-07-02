// Copyright 2023 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

// Note: This is a port of the jhash function from the Linux kernel.
// ${KERNEL}/include/linux/jhash.h

func rol32(word uint32, shift uint) uint32 {
	return (word << (shift & 31)) | (word >> ((-shift) & 31))
}

func __jhash_final(a, b, c uint32) uint32 {
	c ^= b
	c -= rol32(b, 14)
	a ^= c
	a -= rol32(c, 11)
	b ^= a
	b -= rol32(a, 25)
	c ^= b
	c -= rol32(b, 16)
	a ^= c
	a -= rol32(c, 4)
	b ^= a
	b -= rol32(a, 14)
	c ^= b
	c -= rol32(b, 24)
	return c
}

/* An arbitrary initial parameter */
const JHASH_INITVAL = 0xdeadbeef

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
func jhash(k []byte, initval uint32) uint32 {
	var a, b, c uint32

	length := uint32(len(k))

	/* Set up the internal state */
	c = JHASH_INITVAL + length + initval
	a = c
	b = c

	/* All but the last block: affect some 32 bits of (a,b,c) */
	if length > 12 {
		panic("length > 12")
	}

	/* Last block: affect all 32 bits of (c) */
	switch length {
	case 12:
		c += ((uint32)(k[11])) << 24
		fallthrough
	case 11:
		c += (uint32)(k[10]) << 16
		fallthrough
	case 10:
		c += (uint32)(k[9]) << 8
		fallthrough
	case 9:
		c += (uint32)(k[8])
		fallthrough
	case 8:
		b += (uint32)(k[7]) << 24
		fallthrough
	case 7:
		b += (uint32)(k[6]) << 16
		fallthrough
	case 6:
		b += (uint32)(k[5]) << 8
		fallthrough
	case 5:
		b += (uint32)(k[4])
		fallthrough
	case 4:
		a += (uint32)(k[3]) << 24
		fallthrough
	case 3:
		a += (uint32)(k[2]) << 16
		fallthrough
	case 2:
		a += (uint32)(k[1]) << 8
		fallthrough
	case 1:
		a += (uint32)(k[0])
		c = __jhash_final(a, b, c)
	case 0: /* Nothing left to add */
		break
	}

	return c
}
