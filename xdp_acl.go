// Copyright 2023 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
)

type xdpAcl struct {
	rules  []*rule
	tables aclTables
}

func maskOnes(mask [4]byte) int {
	ones, _ := net.IPMask(mask[:]).Size()
	return ones
}

func newXdpAcl(rules []*RuleDesc) (*xdpAcl, error) {
	var a xdpAcl
	a.rules = make([]*rule, 0, len(rules))

	for _, r := range rules {
		rule, err := r.toRule()
		if err != nil {
			return nil, fmt.Errorf("failed to parse rules: %w", err)
		}

		smaskBits := maskOnes(rule.smask)
		dmaskBits := maskOnes(rule.dmask)
		tbl := a.tables.findCompatibleTable(smaskBits, dmaskBits)
		rule.setTableID(tbl.ID)
		rule.doHash()

		a.rules = append(a.rules, rule)
	}

	a.tables.sort()

	return &a, nil
}

func isPowOf2(n uint32) bool {
	return (n & (n - 1)) == 0
}

func (a *xdpAcl) saveRulesToMap(m *ebpf.Map, save func([]*rule) (*ebpf.Map, error)) error {
	maxEntries := m.MaxEntries()
	if !isPowOf2(maxEntries) {
		return fmt.Errorf("map max entries must be power of 2")
	}

	var index []uint32

	arr := make([][]*rule, maxEntries)
	for _, r := range a.rules {
		idx := r.hash & (maxEntries - 1)
		arr[idx] = append(arr[idx], r)
		index = append(index, idx)
	}

	for _, idx := range index {
		innerMap, err := save(arr[idx])
		if err != nil {
			return fmt.Errorf("failed to save rules: %w", err)
		}
		defer innerMap.Close()

		if err := m.Update(idx, innerMap, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("failed to update acl buckets map: %w", err)
		}
	}

	return nil
}

func (a *xdpAcl) saveTablesToMap(m *ebpf.Map) error {
	for i, tbl := range a.tables {
		b := tbl.toBinary()
		if err := m.Put(uint32(i), b); err != nil {
			return fmt.Errorf("failed to update acl tables map: %w", err)
		}
	}

	return nil
}
