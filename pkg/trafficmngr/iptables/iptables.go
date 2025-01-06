// Copyright 2015 flannel authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// ...

//go:build !windows
// +build !windows

package iptables

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/flannel-io/flannel/pkg/ip"
	"github.com/flannel-io/flannel/pkg/lease"
	"github.com/flannel-io/flannel/pkg/trafficmngr"
	log "k8s.io/klog/v2"
)

type IPTables interface {
	AppendUnique(table string, chain string, rulespec ...string) error
	ChainExists(table, chain string) (bool, error)
	ClearChain(table, chain string) error
	Delete(table string, chain string, rulespec ...string) error
	Exists(table string, chain string, rulespec ...string) (bool, error)
}

type IPTablesError interface {
	IsNotExist() bool
	Error() string
}

type IPTablesManager struct {
	ipv4Rules []trafficmngr.IPTablesRule
	ipv6Rules []trafficmngr.IPTablesRule

	// CHANGED: track if we've already done the "first run" insertion
	firstIPv4SetupDone bool
	firstIPv6SetupDone bool
}

func (iptm *IPTablesManager) Init(ctx context.Context, wg *sync.WaitGroup) error {
	log.Info("Starting flannel in iptables mode...")

	iptm.ipv4Rules = make([]trafficmngr.IPTablesRule, 0, 10)
	iptm.ipv6Rules = make([]trafficmngr.IPTablesRule, 0, 10)

	// CHANGED: Initialize the flags that let us know if we've done the first-run insertion
	iptm.firstIPv4SetupDone = false
	iptm.firstIPv6SetupDone = false

	wg.Add(1)
	go func() {
		<-ctx.Done()
		time.Sleep(time.Second)
		err := iptm.cleanUp()
		if err != nil {
			log.Errorf("iptables: error while cleaning-up: %v", err)
		}
		wg.Done()
	}()

	return nil
}

func (iptm *IPTablesManager) cleanUp() error {
	if len(iptm.ipv4Rules) > 0 {
		ipt, err := iptables.New()
		if err != nil {
			// if we can't find iptables, give up and return
			return fmt.Errorf("failed to setup IPTables. iptables binary was not found: %v", err)
		}
		iptRestore, err := NewIPTablesRestoreWithProtocol(iptables.ProtocolIPv4)
		if err != nil {
			return fmt.Errorf("failed to setup IPTables. iptables-restore binary was not found: %v", err)
		}
		log.Info("iptables (ipv4): cleaning-up before exiting flannel...")
		err = teardownIPTables(ipt, iptRestore, iptm.ipv4Rules)
		if err != nil {
			log.Errorf("Failed to tear down IPTables: %v", err)
		}
	}
	if len(iptm.ipv6Rules) > 0 {
		ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
		if err != nil {
			return fmt.Errorf("failed to setup IPTables. iptables binary was not found: %v", err)
		}
		iptRestore, err := NewIPTablesRestoreWithProtocol(iptables.ProtocolIPv6)
		if err != nil {
			return fmt.Errorf("failed to setup IPTables. iptables-restore binary was not found: %v", err)
		}
		log.Info("iptables (ipv6): cleaning-up before exiting flannel...")
		err = teardownIPTables(ipt, iptRestore, iptm.ipv6Rules)
		if err != nil {
			log.Errorf("Failed to tear down IPTables: %v", err)
		}
	}
	return nil
}

func (iptm *IPTablesManager) SetupAndEnsureMasqRules(ctx context.Context, flannelIPv4Net, prevSubnet, prevNetwork ip.IP4Net,
	flannelIPv6Net, prevIPv6Subnet, prevIPv6Network ip.IP6Net,
	currentlease *lease.Lease,
	resyncPeriod int) error {

	if !flannelIPv4Net.Empty() {
		// recycle iptables rules only when network configured or subnet leased is not equal to current one.
		if !(flannelIPv4Net.Equal(prevNetwork) && prevSubnet.Equal(currentlease.Subnet)) {
			log.Infof("Current network or subnet (%v, %v) is not equal to previous one (%v, %v), trying to recycle old iptables rules",
				flannelIPv4Net, currentlease.Subnet, prevNetwork, prevSubnet)
			newLease := &lease.Lease{
				Subnet: prevSubnet,
			}
			if err := iptm.deleteIP4Tables(iptm.masqRules(prevNetwork, newLease)); err != nil {
				return err
			}
		}

		log.Infof("Setting up masking rules")
		iptm.CreateIP4Chain("nat", "FLANNEL-POSTRTG")
		go iptm.setupAndEnsureIP4Tables(ctx, iptm.masqRules(flannelIPv4Net, currentlease), resyncPeriod)
	}
	if !flannelIPv6Net.Empty() {
		if !(flannelIPv6Net.Equal(prevIPv6Network) && prevIPv6Subnet.Equal(currentlease.IPv6Subnet)) {
			log.Infof("Current network or subnet (%v, %v) is not equal to previous one (%v, %v), trying to recycle old iptables rules",
				flannelIPv6Net, currentlease.IPv6Subnet, prevIPv6Network, prevIPv6Subnet)
			newLease := &lease.Lease{
				IPv6Subnet: prevIPv6Subnet,
			}
			if err := iptm.deleteIP6Tables(iptm.masqIP6Rules(prevIPv6Network, newLease)); err != nil {
				return err
			}
		}

		log.Infof("Setting up masking rules for IPv6")
		iptm.CreateIP6Chain("nat", "FLANNEL-POSTRTG")
		go iptm.setupAndEnsureIP6Tables(ctx, iptm.masqIP6Rules(flannelIPv6Net, currentlease), resyncPeriod)
	}
	return nil
}

func (iptm *IPTablesManager) masqRules(ccidr ip.IP4Net, lease *lease.Lease) []trafficmngr.IPTablesRule {
	cluster_cidr := ccidr.String()
	pod_cidr := lease.Subnet.String()

	ipt, err := iptables.New()
	supports_random_fully := false
	if err == nil {
		supports_random_fully = ipt.HasRandomFully()
	}
	rules := make([]trafficmngr.IPTablesRule, 2)
	// This rule ensures that the flannel iptables rules are executed (normally near the top).
	rules[0] = trafficmngr.IPTablesRule{Table: "nat", Action: "-A", Chain: "POSTROUTING", Rulespec: []string{
		"-m", "comment", "--comment", "flanneld masq", "-j", "FLANNEL-POSTRTG",
	}}
	rules[1] = trafficmngr.IPTablesRule{Table: "nat", Action: "-A", Chain: "FLANNEL-POSTRTG", Rulespec: []string{
		"-m", "mark", "--mark", trafficmngr.KubeProxyMark,
		"-m", "comment", "--comment", "flanneld masq",
		"-j", "RETURN",
	}}
	// ...
	rules = append(rules,
		trafficmngr.IPTablesRule{Table: "nat", Action: "-A", Chain: "FLANNEL-POSTRTG", Rulespec: []string{
			"-s", pod_cidr, "-d", cluster_cidr, "-m", "comment", "--comment", "flanneld masq", "-j", "RETURN",
		}},
		trafficmngr.IPTablesRule{Table: "nat", Action: "-A", Chain: "FLANNEL-POSTRTG", Rulespec: []string{
			"-s", cluster_cidr, "-d", pod_cidr, "-m", "comment", "--comment", "flanneld masq", "-j", "RETURN",
		}},
	)
	rules = append(rules, trafficmngr.IPTablesRule{Table: "nat", Action: "-A", Chain: "FLANNEL-POSTRTG", Rulespec: []string{
		"!", "-s", cluster_cidr, "-d", pod_cidr, "-m", "comment", "--comment", "flanneld masq", "-j", "RETURN",
	}})

	if supports_random_fully {
		rules = append(rules,
			trafficmngr.IPTablesRule{
				Table:  "nat",
				Action: "-A",
				Chain:  "FLANNEL-POSTRTG",
				Rulespec: []string{
					"-s", cluster_cidr, "!", "-d", "224.0.0.0/4",
					"-m", "comment", "--comment", "flanneld masq",
					"-j", "MASQUERADE", "--random-fully",
				},
			},
		)
	} else {
		rules = append(rules,
			trafficmngr.IPTablesRule{
				Table:  "nat",
				Action: "-A",
				Chain:  "FLANNEL-POSTRTG",
				Rulespec: []string{
					"-s", cluster_cidr, "!", "-d", "224.0.0.0/4",
					"-m", "comment", "--comment", "flanneld masq",
					"-j", "MASQUERADE",
				},
			},
		)
	}

	if supports_random_fully {
		rules = append(rules,
			trafficmngr.IPTablesRule{
				Table:  "nat",
				Action: "-A",
				Chain:  "FLANNEL-POSTRTG",
				Rulespec: []string{
					"!", "-s", cluster_cidr, "-d", cluster_cidr,
					"-m", "comment", "--comment", "flanneld masq",
					"-j", "MASQUERADE", "--random-fully",
				},
			},
		)
	} else {
		rules = append(rules,
			trafficmngr.IPTablesRule{
				Table:  "nat",
				Action: "-A",
				Chain:  "FLANNEL-POSTRTG",
				Rulespec: []string{
					"!", "-s", cluster_cidr, "-d", cluster_cidr,
					"-m", "comment", "--comment", "flanneld masq",
					"-j", "MASQUERADE",
				},
			},
		)
	}

	return rules
}

func (iptm *IPTablesManager) masqIP6Rules(ccidr ip.IP6Net, lease *lease.Lease) []trafficmngr.IPTablesRule {
	cluster_cidr := ccidr.String()
	pod_cidr := lease.IPv6Subnet.String()
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	supports_random_fully := false
	if err == nil {
		supports_random_fully = ipt.HasRandomFully()
	}
	rules := make([]trafficmngr.IPTablesRule, 2)

	rules[0] = trafficmngr.IPTablesRule{Table: "nat", Action: "-A", Chain: "POSTROUTING", Rulespec: []string{
		"-m", "comment", "--comment", "flanneld masq", "-j", "FLANNEL-POSTRTG",
	}}
	rules[1] = trafficmngr.IPTablesRule{Table: "nat", Action: "-A", Chain: "FLANNEL-POSTRTG", Rulespec: []string{
		"-m", "mark", "--mark", trafficmngr.KubeProxyMark,
		"-m", "comment", "--comment", "flanneld masq",
		"-j", "RETURN",
	}}

	rules = append(rules,
		trafficmngr.IPTablesRule{Table: "nat", Action: "-A", Chain: "FLANNEL-POSTRTG", Rulespec: []string{
			"-s", pod_cidr, "-d", cluster_cidr, "-m", "comment", "--comment", "flanneld masq", "-j", "RETURN",
		}},
		trafficmngr.IPTablesRule{Table: "nat", Action: "-A", Chain: "FLANNEL-POSTRTG", Rulespec: []string{
			"-s", cluster_cidr, "-d", pod_cidr, "-m", "comment", "--comment", "flanneld masq", "-j", "RETURN",
		}},
	)
	rules = append(rules, trafficmngr.IPTablesRule{Table: "nat", Action: "-A", Chain: "FLANNEL-POSTRTG", Rulespec: []string{
		"!", "-s", cluster_cidr, "-d", pod_cidr, "-m", "comment", "--comment", "flanneld masq", "-j", "RETURN",
	}})

	if supports_random_fully {
		rules = append(rules,
			trafficmngr.IPTablesRule{
				Table:  "nat",
				Action: "-A",
				Chain:  "FLANNEL-POSTRTG",
				Rulespec: []string{
					"-s", cluster_cidr, "!", "-d", "ff00::/8",
					"-m", "comment", "--comment", "flanneld masq",
					"-j", "MASQUERADE", "--random-fully",
				},
			},
		)
	} else {
		rules = append(rules,
			trafficmngr.IPTablesRule{
				Table:  "nat",
				Action: "-A",
				Chain:  "FLANNEL-POSTRTG",
				Rulespec: []string{
					"-s", cluster_cidr, "!", "-d", "ff00::/8",
					"-m", "comment", "--comment", "flanneld masq",
					"-j", "MASQUERADE",
				},
			},
		)
	}

	if supports_random_fully {
		rules = append(rules,
			trafficmngr.IPTablesRule{
				Table:  "nat",
				Action: "-A",
				Chain:  "FLANNEL-POSTRTG",
				Rulespec: []string{
					"!", "-s", cluster_cidr, "-d", cluster_cidr,
					"-m", "comment", "--comment", "flanneld masq",
					"-j", "MASQUERADE", "--random-fully",
				},
			},
		)
	} else {
		rules = append(rules,
			trafficmngr.IPTablesRule{
				Table:  "nat",
				Action: "-A",
				Chain:  "FLANNEL-POSTRTG",
				Rulespec: []string{
					"!", "-s", cluster_cidr, "-d", cluster_cidr,
					"-m", "comment", "--comment", "flanneld masq",
					"-j", "MASQUERADE",
				},
			},
		)
	}

	return rules
}

func (iptm *IPTablesManager) SetupAndEnsureForwardRules(ctx context.Context, flannelIPv4Network ip.IP4Net, flannelIPv6Network ip.IP6Net, resyncPeriod int) {
	if !flannelIPv4Network.Empty() {
		log.Infof("Changing default FORWARD chain policy to ACCEPT")
		iptm.CreateIP4Chain("filter", "FLANNEL-FWD")
		go iptm.setupAndEnsureIP4Tables(ctx, iptm.forwardRules(flannelIPv4Network.String()), resyncPeriod)
	}
	if !flannelIPv6Network.Empty() {
		log.Infof("IPv6: Changing default FORWARD chain policy to ACCEPT")
		iptm.CreateIP6Chain("filter", "FLANNEL-FWD")
		go iptm.setupAndEnsureIP6Tables(ctx, iptm.forwardRules(flannelIPv6Network.String()), resyncPeriod)
	}
}

func (iptm *IPTablesManager) forwardRules(flannelNetwork string) []trafficmngr.IPTablesRule {
	return []trafficmngr.IPTablesRule{
		{Table: "filter", Action: "-A", Chain: "FORWARD", Rulespec: []string{
			"-m", "comment", "--comment", "flanneld forward", "-j", "FLANNEL-FWD",
		}},
		{Table: "filter", Action: "-A", Chain: "FLANNEL-FWD", Rulespec: []string{
			"-s", flannelNetwork,
			"-m", "comment", "--comment", "flanneld forward",
			"-j", "ACCEPT",
		}},
		{Table: "filter", Action: "-A", Chain: "FLANNEL-FWD", Rulespec: []string{
			"-d", flannelNetwork,
			"-m", "comment", "--comment", "flanneld forward",
			"-j", "ACCEPT",
		}},
	}
}

func (iptm *IPTablesManager) CreateIP4Chain(table, chain string) {
	ipt, err := iptables.New()
	if err != nil {
		log.Errorf("Failed to setup IPTables. iptables binary was not found: %v", err)
		return
	}
	err = ipt.ClearChain(table, chain)
	if err != nil {
		log.Errorf("Failed to setup IPTables. Error on creating the chain: %v", err)
		return
	}
}

func (iptm *IPTablesManager) CreateIP6Chain(table, chain string) {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		log.Errorf("Failed to setup IP6Tables. iptables binary was not found: %v", err)
		return
	}
	err = ipt.ClearChain(table, chain)
	if err != nil {
		log.Errorf("Failed to setup IP6Tables. Error on creating the chain: %v", err)
		return
	}
}

// ------------------------------------------------------------------------
// CHANGED: We remove the deletion logic from ipTablesCleanAndBuild so it
// won’t reorder. We'll only *append or insert* if rules are missing.
// ------------------------------------------------------------------------
func ipTablesCleanAndBuild(ipt IPTables, rules []trafficmngr.IPTablesRule, firstSetup bool) (IPTablesRestoreRules, error) {
	tablesRules := IPTablesRestoreRules{}

	for _, rule := range rules {
		// Ensure chain exists
		if rule.Chain == "FLANNEL-FWD" || rule.Rulespec[len(rule.Rulespec)-1] == "FLANNEL-FWD" {
			chainExist, err := ipt.ChainExists(rule.Table, "FLANNEL-FWD")
			if err != nil {
				return nil, fmt.Errorf("failed to check rule existence: %v", err)
			}
			if !chainExist {
				err = ipt.ClearChain(rule.Table, "FLANNEL-FWD")
				if err != nil {
					return nil, fmt.Errorf("failed to create chain FLANNEL-FWD: %v", err)
				}
			}
		} else if rule.Chain == "FLANNEL-POSTRTG" || rule.Rulespec[len(rule.Rulespec)-1] == "FLANNEL-POSTRTG" {
			chainExist, err := ipt.ChainExists(rule.Table, "FLANNEL-POSTRTG")
			if err != nil {
				return nil, fmt.Errorf("failed to check rule existence: %v", err)
			}
			if !chainExist {
				err = ipt.ClearChain(rule.Table, "FLANNEL-POSTRTG")
				if err != nil {
					return nil, fmt.Errorf("failed to create chain FLANNEL-POSTRTG: %v", err)
				}
			}
		}

		exists, err := ipt.Exists(rule.Table, rule.Chain, rule.Rulespec...)
		if err != nil {
			return nil, fmt.Errorf("failed to check rule existence: %v", err)
		}

		// If the rule is missing, we add it. If it's the "first run," we insert at the top (-I 1).
		// Otherwise, we just do a normal append.
		if !exists {
			if _, ok := tablesRules[rule.Table]; !ok {
				tablesRules[rule.Table] = []IPTablesRestoreRuleSpec{}
			}

			if firstSetup {
				// Insert at position 1
				tablesRules[rule.Table] = append(
					tablesRules[rule.Table],
					append(IPTablesRestoreRuleSpec{"-I", rule.Chain, "1"}, rule.Rulespec...),
				)
			} else {
				// Normal append
				tablesRules[rule.Table] = append(
					tablesRules[rule.Table],
					append(IPTablesRestoreRuleSpec{rule.Action, rule.Chain}, rule.Rulespec...),
				)
			}
		}
	}

	return tablesRules, nil
}

// ------------------------------------------------------------------------
// CHANGED: ipTablesBootstrap now calls ipTablesCleanAndBuild with a
// “firstSetup” boolean. If it’s truly the “first run,” we do top insertion.
// Otherwise, we do a normal append if rules are missing.
// ------------------------------------------------------------------------
func ipTablesBootstrap(ipt IPTables, iptRestore IPTablesRestore, rules []trafficmngr.IPTablesRule, firstSetup bool) error {
	tablesRules, err := ipTablesCleanAndBuild(ipt, rules, firstSetup)
	if err != nil {
		return fmt.Errorf("failed to setup iptables-restore payload: %v", err)
	}
	if len(tablesRules) == 0 {
		// Means everything already exists, so no changes needed
		log.V(6).Infof("All iptables rules already exist - skipping restore")
		return nil
	}

	log.V(6).Infof("trying to run iptables-restore with changes: %+v", tablesRules)
	err = iptRestore.ApplyWithoutFlush(tablesRules)
	if err != nil {
		return fmt.Errorf("failed to apply partial iptables-restore: %v", err)
	}

	log.Infof("iptables bootstrap done (firstSetup=%v)", firstSetup)
	return nil
}

func ensureIPTables(ipt IPTables, iptRestore IPTablesRestore, rules []trafficmngr.IPTablesRule) error {
	// Instead of tearing down and re-adding everything, we only add missing rules.
	tablesRules, err := ipTablesCleanAndBuild(ipt, rules, false /* firstSetup */)
	if err != nil {
		return fmt.Errorf("error checking rule existence: %v", err)
	}

	// If tablesRules is empty, nothing is missing
	if len(tablesRules) == 0 {
		return nil
	}

	log.Info("Some iptables rules are missing; adding them without reordering existing rules")
	err = iptRestore.ApplyWithoutFlush(tablesRules)
	if err != nil {
		return fmt.Errorf("error adding missing rules: %v", err)
	}
	return nil
}

func (iptm *IPTablesManager) setupAndEnsureIP4Tables(ctx context.Context, rules []trafficmngr.IPTablesRule, resyncPeriod int) {
	ipt, err := iptables.New()
	if err != nil {
		log.Errorf("Failed to setup IPTables. iptables binary was not found: %v", err)
		return
	}
	iptRestore, err := NewIPTablesRestoreWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		log.Errorf("Failed to setup IPTables. iptables-restore binary was not found: %v", err)
		return
	}

	// CHANGED: If we have not done the first IPv4 setup, do it now
	err = ipTablesBootstrap(ipt, iptRestore, rules, !iptm.firstIPv4SetupDone)
	if err != nil {
		log.Errorf("Failed to bootstrap IPTables: %v", err)
	}
	iptm.firstIPv4SetupDone = true

	iptm.ipv4Rules = append(iptm.ipv4Rules, rules...)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(resyncPeriod) * time.Second):
			// CHANGED: Only ensure missing rules are appended. We do NOT delete or re-insert existing ones.
			if err := ensureIPTables(ipt, iptRestore, rules); err != nil {
				log.Errorf("Failed to ensure iptables rules: %v", err)
			}
		}
	}
}

func (iptm *IPTablesManager) setupAndEnsureIP6Tables(ctx context.Context, rules []trafficmngr.IPTablesRule, resyncPeriod int) {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		log.Errorf("Failed to setup IP6Tables. iptables binary was not found: %v", err)
		return
	}
	iptRestore, err := NewIPTablesRestoreWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		log.Errorf("Failed to setup iptables-restore: %v", err)
		return
	}

	// CHANGED: If we have not done the first IPv6 setup, do it now
	err = ipTablesBootstrap(ipt, iptRestore, rules, !iptm.firstIPv6SetupDone)
	if err != nil {
		log.Errorf("Failed to bootstrap IPTables: %v", err)
	}
	iptm.firstIPv6SetupDone = true

	iptm.ipv6Rules = append(iptm.ipv6Rules, rules...)

	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(resyncPeriod) * time.Second):
			// Only append missing rules
			if err := ensureIPTables(ipt, iptRestore, rules); err != nil {
				log.Errorf("Failed to ensure iptables rules: %v", err)
			}
		}
	}
}

func (iptm *IPTablesManager) deleteIP4Tables(rules []trafficmngr.IPTablesRule) error {
	ipt, err := iptables.New()
	if err != nil {
		log.Errorf("Failed to setup IPTables. iptables binary was not found: %v", err)
		return err
	}
	iptRestore, err := NewIPTablesRestoreWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		log.Errorf("Failed to setup iptables-restore: %v", err)
		return err
	}
	err = teardownIPTables(ipt, iptRestore, rules)
	if err != nil {
		log.Errorf("Failed to teardown iptables: %v", err)
		return err
	}
	return nil
}

func (iptm *IPTablesManager) deleteIP6Tables(rules []trafficmngr.IPTablesRule) error {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		log.Errorf("Failed to setup IP6Tables. iptables binary was not found: %v", err)
		return err
	}

	iptRestore, err := NewIPTablesRestoreWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		log.Errorf("Failed to setup iptables-restore: %v", err)
		return err
	}
	err = teardownIPTables(ipt, iptRestore, rules)
	if err != nil {
		log.Errorf("Failed to teardown iptables: %v", err)
		return err
	}
	return nil
}

func teardownIPTables(ipt IPTables, iptr IPTablesRestore, rules []trafficmngr.IPTablesRule) error {
	tablesRules := IPTablesRestoreRules{}

	for _, rule := range rules {
		if rule.Chain == "FLANNEL-FWD" || rule.Rulespec[len(rule.Rulespec)-1] == "FLANNEL-FWD" {
			chainExists, err := ipt.ChainExists(rule.Table, "FLANNEL-FWD")
			if err != nil {
				return fmt.Errorf("failed to check rule existence: %v", err)
			}
			if !chainExists {
				continue
			}
		} else if rule.Chain == "FLANNEL-POSTRTG" || rule.Rulespec[len(rule.Rulespec)-1] == "FLANNEL-POSTRTG" {
			chainExists, err := ipt.ChainExists(rule.Table, "FLANNEL-POSTRTG")
			if err != nil {
				return fmt.Errorf("failed to check rule existence: %v", err)
			}
			if !chainExists {
				continue
			}
		}
		exists, err := ipt.Exists(rule.Table, rule.Chain, rule.Rulespec...)
		if err != nil {
			return fmt.Errorf("failed to check rule existence: %v", err)
		}

		if exists {
			if _, ok := tablesRules[rule.Table]; !ok {
				tablesRules[rule.Table] = []IPTablesRestoreRuleSpec{}
			}
			tablesRules[rule.Table] = append(
				tablesRules[rule.Table],
				append(IPTablesRestoreRuleSpec{"-D", rule.Chain}, rule.Rulespec...),
			)
		}
	}

	err := iptr.ApplyWithoutFlush(tablesRules)
	if err != nil {
		return fmt.Errorf("unable to teardown iptables: %v", err)
	}

	return nil
}

