// Copyright 2023 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"net"
	"reflect"
	"sort"
	"unsafe"
)

type aclTable struct {
	ID        uint32
	smaskBits int
	dmaskBits int
}

func (t *aclTable) toBinary() []byte {
	var tbl struct {
		ID    uint32
		smask [4]byte
		dmask [4]byte
	}

	tbl.ID = t.ID
	tbl.smask = ([4]byte)(net.CIDRMask(t.smaskBits, 32))
	tbl.dmask = ([4]byte)(net.CIDRMask(t.dmaskBits, 32))

	siz := int(unsafe.Sizeof(tbl))

	var b []byte
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	sh.Data = uintptr(unsafe.Pointer(&tbl))
	sh.Len = siz
	sh.Cap = siz

	return b
}

func randID() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return *(*uint32)(unsafe.Pointer(&b))
}

type aclTables []*aclTable

func (t *aclTables) isTableIDUsed(id uint32) bool {
	for _, table := range *t {
		if table.ID == id {
			return true
		}
	}

	return false
}

func (t *aclTables) findCompatibleTable(smaskBits, dmaskBits int) *aclTable {
	for _, table := range *t {
		// xbits <= ybits means ybits is a subset of xbits
		if table.smaskBits <= smaskBits && table.dmaskBits <= dmaskBits {
			return table
		}
	}

	tblID := randID()
	for t.isTableIDUsed(tblID) {
		tblID = randID()
	}

	tbl := &aclTable{
		ID:        tblID,
		smaskBits: smaskBits,
		dmaskBits: dmaskBits,
	}

	*t = append(*t, tbl)

	return tbl
}

func (t *aclTables) sort() {
	sort.Slice(*t, func(i, j int) bool {
		return (*t)[i].smaskBits < (*t)[j].smaskBits ||
			(*t)[i].dmaskBits < (*t)[j].dmaskBits
	})
}
