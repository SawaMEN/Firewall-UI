package service

import (
	"context"
	"errors"
	"os/exec"
	"strings"

	"github.com/SawaMEN/Firewall-UI/internal/hostexec"
)

const managedIPTablesRuleComment = "Firewall-UI-managed"

func managedIPTablesPortRuleArgs(rule FirewallRule) ([]string, bool) {
	spec := firewallRuleSpec(rule)
	if spec == "" {
		return nil, false
	}
	parts := strings.SplitN(spec, "/", 2)
	if len(parts) != 2 {
		return nil, false
	}
	return []string{
		"-A", managedIPTablesChain,
		"-p", parts[1],
		"--dport", iptablesPortExpression(rule),
		"-m", "comment", "--comment", managedIPTablesRuleComment,
		"-j", "ACCEPT",
	}, true
}

func managedIPTablesBaseRuleArgs(icmpProto string) [][]string {
	return [][]string{
		{"-A", managedIPTablesChain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-m", "comment", "--comment", managedIPTablesRuleComment, "-j", "ACCEPT"},
		{"-A", managedIPTablesChain, "-i", "lo", "-m", "comment", "--comment", managedIPTablesRuleComment, "-j", "ACCEPT"},
		{"-A", managedIPTablesChain, "-p", icmpProto, "-m", "comment", "--comment", managedIPTablesRuleComment, "-j", "ACCEPT"},
	}
}

func ensureManagedIPTablesChain(ctx context.Context, binary string) error {
	if _, err := runFirewallCommand(ctx, binary, "-N", managedIPTablesChain); err != nil {
		if _, checkErr := runFirewallCommand(ctx, binary, "-S", managedIPTablesChain); checkErr != nil {
			return err
		}
	}
	_, err := runFirewallCommand(ctx, binary, "-F", managedIPTablesChain)
	return err
}

func managedIPTablesJumpExists(ctx context.Context, binary string) (bool, error) {
	cmd := firewallCommand(ctx, binary, "-C", "INPUT", "-j", managedIPTablesChain)
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func resetManagedIPTablesJump(ctx context.Context, binary string) error {
	for {
		exists, err := managedIPTablesJumpExists(ctx, binary)
		if err != nil {
			return err
		}
		if !exists {
			break
		}
		if _, err := runFirewallCommand(ctx, binary, "-D", "INPUT", "-j", managedIPTablesChain); err != nil {
			return err
		}
	}
	_, err := runFirewallCommand(ctx, binary, "-A", "INPUT", "-j", managedIPTablesChain)
	return err
}

func applyManagedIPTablesSafe(ctx context.Context, binary string, rules []FirewallRule) error {
	if err := applyManagedIPTablesBinarySafe(ctx, binary, "icmp", rules); err != nil {
		return err
	}
	if ip6, err := hostexec.LookPath("ip6tables"); err == nil {
		if err := applyManagedIPTablesBinarySafe(ctx, ip6, "ipv6-icmp", rules); err != nil {
			return err
		}
	}
	return nil
}

func applyManagedIPTablesBinarySafe(ctx context.Context, binary, icmpProto string, rules []FirewallRule) error {
	if err := ensureManagedIPTablesChain(ctx, binary); err != nil {
		return err
	}
	for _, args := range managedIPTablesBaseRuleArgs(icmpProto) {
		if _, err := runFirewallCommand(ctx, binary, args...); err != nil {
			return err
		}
	}
	appendPortRule := func(rule FirewallRule) error {
		args, ok := managedIPTablesPortRuleArgs(rule)
		if !ok {
			return nil
		}
		_, err := runFirewallCommand(ctx, binary, args...)
		return err
	}
	for _, rule := range rules {
		if isFirewallSafetyRule(rule) {
			if err := appendPortRule(rule); err != nil {
				return err
			}
		}
	}
	advanced, err := loadAdvancedFirewallRules()
	if err != nil {
		return err
	}
	ipv6 := icmpProto == "ipv6-icmp"
	for _, rule := range advanced {
		args, ok := advancedIPTablesArgs(rule, ipv6)
		if !ok {
			continue
		}
		if _, err := runFirewallCommand(ctx, binary, args...); err != nil {
			return err
		}
	}
	for _, rule := range rules {
		if !isFirewallSafetyRule(rule) {
			if err := appendPortRule(rule); err != nil {
				return err
			}
		}
	}
	if _, err := runFirewallCommand(ctx, binary,
		"-A", managedIPTablesChain,
		"-m", "comment", "--comment", managedIPTablesRuleComment,
		"-j", "DROP"); err != nil {
		return err
	}
	return resetManagedIPTablesJump(ctx, binary)
}
