// Copyright 2023 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate bpf2go -cc=clang xdpacl ./ebpf/tuplemerge.c -- -D__TARGET_ARCH_x86 -I./ebpf/headers -Wall -Wimplicit-fallthrough
//go:generate bpf2go -cc=clang xdpaclkern ./ebpf/tuplemerge.c -- -D__TARGET_ARCH_x86 -D__USE_HASH_KERN -I./ebpf/headers -Wall -Wimplicit-fallthrough

type xdp struct {
	acl *xdpAcl

	bpfSpec     *ebpf.CollectionSpec
	ruleMapSpec *ebpf.MapSpec
}

func newXdp(rules []*RuleDesc, useKernelHash bool) (*xdp, error) {
	var (
		spec *ebpf.CollectionSpec
		err  error
	)
	if useKernelHash {
		spec, err = loadXdpaclkern()
	} else {
		spec, err = loadXdpacl()
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load bpf spec: %w", err)
	}

	ruleSpec := spec.Maps["acl_rules"]
	if ruleSpec == nil {
		return nil, fmt.Errorf("acl_rules map spec not found")
	}

	acl, err := newXdpAcl(rules)
	if err != nil {
		return nil, fmt.Errorf("failed to create xdp acl: %w", err)
	}

	return &xdp{acl: acl, bpfSpec: spec, ruleMapSpec: ruleSpec}, nil
}

func (x *xdp) saveRules(rules []*rule) (*ebpf.Map, error) {
	mapSpec := x.ruleMapSpec.Copy()
	mapSpec.MaxEntries = uint32(len(rules))
	m, err := ebpf.NewMap(mapSpec)
	if err != nil {
		return nil, fmt.Errorf("failed to create acl_rules map: %w", err)
	}

	rules = sortRules(rules)

	for i, rule := range rules {
		b := rule.toBinary()
		if err := m.Put(uint32(i), b); err != nil {
			return nil, fmt.Errorf("failed to put rule to map: %w", err)
		}
	}

	return m, nil
}

func (x *xdp) run(ifindex int, ifname string) (link.Link, error) {
	mapSpec := x.bpfSpec.Maps["acl_rule_buckets"]
	if mapSpec == nil {
		return nil, fmt.Errorf("acl_rule_buckets map spec not found")
	}
	mapSpec.InnerMap = x.ruleMapSpec

	var obj xdpaclObjects
	if err := x.bpfSpec.LoadAndAssign(&obj, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, fmt.Errorf("verifier error: %w\n%+v", err, ve)
		}
		return nil, fmt.Errorf("loading objects: %w", err)
	}
	defer obj.Close()

	if err := x.acl.saveTablesToMap(obj.AclTables); err != nil {
		return nil, fmt.Errorf("failed to save acl tables to map: %w", err)
	}

	if err := x.acl.saveRulesToMap(obj.AclRuleBuckets, x.saveRules); err != nil {
		return nil, fmt.Errorf("failed to save acl rules to map: %w", err)
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Interface: ifindex,
		Program:   obj.XdpAcl,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to attach xdp program to %s: %w", ifname, err)
	}

	return link, nil
}
