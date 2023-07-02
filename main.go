// Copyright 2023 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"

	flag "github.com/spf13/pflag"
	"github.com/vishvananda/netlink"
)

func main() {
	var device string
	var ruleFile string
	var useKernelHash bool
	flag.StringVarP(&device, "device", "d", "", "device to run XDP ACL")
	flag.StringVarP(&ruleFile, "rule-file", "r", "", "file containing rules to load")
	flag.BoolVarP(&useKernelHash, "use-kernel-hash", "k", false, "use kernel hash function [DEPRECATED] (not support kfunc jhash)")
	flag.Parse()

	ifi, err := netlink.LinkByName(device)
	if err != nil {
		log.Fatalf("failed to find device %s: %v", device, err)
	}

	rules, err := loadRules(ruleFile)
	if err != nil {
		log.Fatalf("failed to load rules: %v", err)
	}

	xdp, err := newXdp(rules, useKernelHash)
	if err != nil {
		log.Fatalf("failed to create xdp: %v", err)
	}

	ifindex, ifname := ifi.Attrs().Index, ifi.Attrs().Name
	link, err := xdp.run(ifindex, ifname)
	if err != nil {
		log.Printf("failed to run xdp: %v", err)
		return
	}
	defer link.Close()

	log.Printf("XDP ACL is running on %s (ifindex:%d)", ifname, ifindex)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	<-ctx.Done()
}

func loadRules(ruleFile string) ([]*RuleDesc, error) {
	fd, err := os.Open(ruleFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load rules file: %w", err)
	}
	defer fd.Close()

	var rules struct {
		Rules []*RuleDesc `json:"rules"`
	}
	if err := json.NewDecoder(fd).Decode(&rules); err != nil {
		return nil, fmt.Errorf("failed to decode rules file: %w", err)
	}

	return rules.Rules, nil
}
