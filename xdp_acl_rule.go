// Copyright 2023 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"reflect"
	"sort"
	"unsafe"
)

type rule struct {
	tableID    uint32
	hash       uint32
	protocol   uint8
	saddr      [4]byte
	smask      [4]byte
	daddr      [4]byte
	dmask      [4]byte
	_pad0      uint8 // Note: it's weird to pad here
	sportStart uint16
	sportEnd   uint16
	dportStart uint16
	dportEnd   uint16
	action     uint8
	_pad1      uint8
	priority   uint64
}

func sortRules(rules []*rule) []*rule {
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].priority > rules[j].priority
	})
	return rules
}

func (r *rule) setTableID(id uint32) {
	r.tableID = id
}

func (r *rule) doHash() {
	var hashKey struct {
		saddr    [4]byte
		daddr    [4]byte
		protocol uint8
	}
	hashKey.saddr = r.saddr
	hashKey.daddr = r.daddr
	hashKey.protocol = r.protocol

	b := (*[9]byte)(unsafe.Pointer(&hashKey))[:]
	r.hash = jhash(b, r.tableID)
}

func (r *rule) toBinary() []byte {
	const siz = 36 // sizeof(struct acl_rule)

	var b []byte
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	sh.Data = uintptr(unsafe.Pointer(r))
	sh.Len = siz
	sh.Cap = siz

	return b
}
