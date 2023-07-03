// Copyright 2023 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"math"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// RuleDesc is a rule description with 5-tuple, action and priority.
type RuleDesc struct {
	// Source CIDR like "192.168.0.0/24".
	Saddr string `json:"saddr"`

	// Destination CIDR like "192.168.0.0/24".
	Daddr string `json:"daddr"`

	// Source port like "80" or "80-90", or "*"/"all" for all ports. But it can
	// be empty if protocol is not TCP or UDP.
	Sport string `json:"sport"`

	// Destination port like "80" or "80-90", or "*"/"all" for all ports. But it
	// can be empty if protocol is not TCP or UDP.
	Dport string `json:"dport"`

	// Protocol like "tcp", "udp" or "icmp", case insensitive.
	Proto string `json:"proto"`

	// Action like "allow" or "deny", case insensitive.
	Action string `json:"action"`

	// Priority is a rule priority. The higher the value, the higher priority.
	Priority uint `json:"priority"`
}

func parseAddr(s string) ([4]byte, [4]byte, error) {
	var addr, mask [4]byte

	pref, err := netip.ParsePrefix(s)
	if err != nil {
		return addr, mask, fmt.Errorf("invalid cidr: %w", err)
	}

	pref = pref.Masked()
	addr = pref.Addr().As4()
	mask = ([4]byte)(net.CIDRMask(pref.Bits(), 32))

	return addr, mask, nil
}

func parsePort(s string) (start, end uint16, errr error) {
	sport := strings.ToLower(s)
	switch sport {
	case "*", "all":
		return 0, math.MaxUint16, nil

	default:
	}

	a, b, ok := strings.Cut(sport, "-")
	if !ok {
		n, err := strconv.Atoi(sport)
		if err != nil {
			errr = fmt.Errorf("invalid port: %w", err)
			return
		}

		start = uint16(n)
		end = uint16(n)
		return
	}

	x, err := strconv.Atoi(a)
	if err != nil {
		errr = fmt.Errorf("invalid port: %w", err)
		return
	}

	y, err := strconv.Atoi(b)
	if err != nil {
		errr = fmt.Errorf("invalid port: %w", err)
		return
	}

	start = uint16(x)
	end = uint16(y)
	return
}

func parseProtocol(s string) (uint8, error) {
	switch strings.ToLower(s) {
	case "tcp":
		return 6, nil
	case "udp":
		return 17, nil
	case "icmp":
		return 1, nil
	default:
		return 0, fmt.Errorf("invalid protocol: %s", s)
	}
}

func parseAction(s string) (uint8, error) {
	switch strings.ToLower(s) {
	case "allow": // XDP_PASS
		return 2, nil
	case "deny": // XDP_DROP
		return 1, nil
	default:
		return 0, fmt.Errorf("invalid action: %s", s)
	}
}

func (d *RuleDesc) toRule() (*rule, error) {
	var r rule

	var err error
	r.saddr, r.smask, err = parseAddr(d.Saddr)
	if err != nil {
		return nil, fmt.Errorf("invalid saddr: %w", err)
	}

	r.daddr, r.dmask, err = parseAddr(d.Daddr)
	if err != nil {
		return nil, fmt.Errorf("invalid daddr: %w", err)
	}

	r.protocol, err = parseProtocol(d.Proto)
	if err != nil {
		return nil, fmt.Errorf("invalid proto: %w", err)
	}

	if r.protocol != 1 { // not icmp => tcp/udp
		r.sportStart, r.sportEnd, err = parsePort(d.Sport)
		if err != nil {
			return nil, fmt.Errorf("invalid sport: %w", err)
		}

		r.dportStart, r.dportEnd, err = parsePort(d.Dport)
		if err != nil {
			return nil, fmt.Errorf("invalid dport: %w", err)
		}
	}

	r.action, err = parseAction(d.Action)
	if err != nil {
		return nil, fmt.Errorf("invalid action: %w", err)
	}

	r.priority = uint64(d.Priority)

	return &r, nil
}
