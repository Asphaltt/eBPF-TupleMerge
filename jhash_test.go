// Copyright 2023 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"
	"unsafe"
)

func TestJhash(t *testing.T) {
	var hashKey struct {
		saddr    [4]byte
		daddr    [4]byte
		protocol uint8
	}
	hashKey.saddr = [4]byte{192, 168, 1, 0}
	hashKey.daddr = [4]byte{192, 168, 1, 0}
	hashKey.protocol = 1

	b := (*[9]byte)(unsafe.Pointer(&hashKey))[:]

	hash := jhash(b, 1)

	if hash != 0xb2dea0d4 {
		t.Logf("hash: %x, expect: %x", hash, 0xb2dea0d4)
		t.Fail()
	}

	hashKey.saddr = [4]byte{0, 1, 168, 192}
	hashKey.daddr = [4]byte{0, 1, 168, 192}

	b = (*[9]byte)(unsafe.Pointer(&hashKey))[:]
	hash2 := jhash(b, 1)

	if hash2 != 0x95e3afc7 {
		t.Logf("hash: %x, expect: %x", hash2, 0x95e3afc7)
		t.Fail()
	}
}
