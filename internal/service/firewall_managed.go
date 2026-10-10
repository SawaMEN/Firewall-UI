package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/SawaMEN/Firewall-UI/internal/hostexec"
)

const (
	firewallManualLabelsKey = "firewallManualRuleLabels"
	managedNftTable         = "firewall_ui"
	managedNftChain         = "input"
	managedIPTablesChain    = "FIREWALL-UI"
)

type FirewallManualRuleView struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Label    string `json:"label,omitempty"`
}

type FirewallManagedStatus struct {
	Supported   bool                     `json:"supported"`
	Backend     string                   `json:"backend"`
	Enabled     bool                     `json:"enabled"`
	AutoSync    bool                     `json:"autoSync"`
	Rules       []FirewallRule           `json:"rules"`
	ManualRules []FirewallManualRuleView `json:"manualRules"`
	Message     string                   `json:"message,omitempty"`
}

func loadFirewallManualLabels() (map[string]string, error) {
	labels := map[string]string{}
	raw, err := firewallSetting(firewallManualLabelsKey, "{}")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(raw) == "" {
		return labels, nil
	}
	if err := json.Unmarshal([]byte(raw), &labels); err != nil {
		return nil, err
	}
	if labels == nil {
		labels = map[string]string{}
	}
	return labels, nil
}

func saveFirewallManualLabels(labels map[string]string) error {
	return saveFirewallJSON(firewallManualLabelsKey, labels)
}

func manualRuleViews(rules []FirewallManualRule, labels map[string]string) []FirewallManualRuleView {
	out := make([]FirewallManualRuleView, 0, len(rules))
	for _, rule := range rules {
		out = append(out, FirewallManualRuleView{
			Port:     rule.Port,
			Protocol: rule.Protocol,
			Label:    labels[firewallRuleKey(rule.Port, rule.Protocol)],
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Port < out[j].Port || (out[i].Port == out[j].Port && out[i].Protocol < out[j].Protocol)
	})
	return out
}

func (s *FirewallService) managedDesiredRules(auto bool, safetyPort int) ([]FirewallRule, error) {
	rules, err := s.desiredRules(auto, safetyPort)
	if err != nil {
		return nil, err
	}
	byKey := make(map[string]FirewallRule, len(rules)+8)
	for _, rule := range rules {
		if key := firewallRuleSpec(rule); key != "" {
			byKey[key] = rule
		}
	}

	labels, err := loadFirewallManualLabels()
	if err != nil {
		return nil, err
	}
	for key, rule := range byKey {
		if rule.Source == "manual" {
			if label := normalizeFirewallLabelUnicode(labels[key]); label != "" {
				rule.Label = label
				byKey[key] = rule
			}
		}
	}

	out := make([]FirewallRule, 0, len(byKey))
	for _, rule := range byKey {
		out = append(out, rule)
	}
	sortFirewallRules(out)
	return out, nil
}

func nativeFirewallBackend(name, binary string, enabled func(context.Context) (bool, error)) firewallBackend {
	return firewallBackend{name: name, binary: binary, enabled: enabled}
}

func detectOwnedNativeFirewallBackend(ctx context.Context) (firewallBackend, bool) {
	if path, err := hostexec.LookPath("nft"); err == nil {
		b := nativeFirewallBackend("nftables", path, func(ctx context.Context) (bool, error) {
			_, err := runFirewallCommand(ctx, path, "list", "table", "inet", managedNftTable)
			if err != nil {
				return false, nil
			}
			return true, nil
		})
		if on, _ := b.enabled(ctx); on {
			return b, true
		}
	}
	if path, err := hostexec.LookPath("iptables"); err == nil {
		b := nativeFirewallBackend("iptables", path, func(ctx context.Context) (bool, error) {
			cmd := firewallCommand(ctx, path, "-C", "INPUT", "-j", managedIPTablesChain)
			if err := cmd.Run(); err != nil {
				var exitErr *exec.ExitError
				if errors.As(err, &exitErr) {
					return false, nil
				}
				return false, err
			}
			return true, nil
		})
		if on, _ := b.enabled(ctx); on {
			return b, true
		}
	}
	return firewallBackend{}, false
}

func detectManagedFirewallBackend(ctx context.Context) (firewallBackend, error) {
	system, systemErr := detectFirewallBackend(ctx)
	if systemErr == nil {
		if on, _ := system.enabled(ctx); on {
			return system, nil
		}
	}
	if native, ok := detectOwnedNativeFirewallBackend(ctx); ok {
		return native, nil
	}
	if systemErr == nil {
		return system, nil
	}

	if path, err := hostexec.LookPath("nft"); err == nil {
		safe, err := nftablesSafeForManagedFirewall(ctx, path)
		if err != nil {
			return firewallBackend{}, err
		}
		if safe {
			return nativeFirewallBackend("nftables", path, func(ctx context.Context) (bool, error) {
				_, err := runFirewallCommand(ctx, path, "list", "table", "inet", managedNftTable)
				return err == nil, nil
			}), nil
		}
		return firewallBackend{}, errors.New("existing nftables input hooks detected; install/use UFW or firewalld, or remove the conflicting native input hook before enabling Firewall-UI firewall")
	}
	if path, err := hostexec.LookPath("iptables"); err == nil {
		return nativeFirewallBackend("iptables", path, func(ctx context.Context) (bool, error) {
			cmd := firewallCommand(ctx, path, "-C", "INPUT", "-j", managedIPTablesChain)
			err := cmd.Run()
			if err == nil {
				return true, nil
			}
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				return false, nil
			}
			return false, err
		}), nil
	}
	return firewallBackend{}, errors.New("no supported firewall found (install ufw, firewalld, nftables, or iptables)")
}

func nftablesSafeForManagedFirewall(ctx context.Context, binary string) (bool, error) {
	out, err := runFirewallCommand(ctx, binary, "-j", "list", "ruleset")
	if err != nil {
		return false, fmt.Errorf("inspect nftables ruleset: %w", err)
	}
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return false, fmt.Errorf("decode nftables ruleset: %w", err)
	}
	for _, item := range doc.Nftables {
		raw, ok := item["chain"]
		if !ok {
			continue
		}
		var chain struct {
			Family string `json:"family"`
			Table  string `json:"table"`
			Name   string `json:"name"`
			Hook   string `json:"hook"`
		}
		if json.Unmarshal(raw, &chain) != nil || chain.Hook != "input" {
			continue
		}
		if chain.Family == "inet" && chain.Table == managedNftTable && chain.Name == managedNftChain {
			continue
		}
		return false, nil
	}
	return true, nil
}

func (s *FirewallService) managedStatusLocked(ctx context.Context, safetyPort int) (FirewallManagedStatus, error) {
	auto, err := firewallAutoSync()
	if err != nil {
		return FirewallManagedStatus{}, err
	}
	manual, err := loadManualFirewallRules()
	if err != nil {
		return FirewallManagedStatus{}, err
	}
	labels, err := loadFirewallManualLabels()
	if err != nil {
		return FirewallManagedStatus{}, err
	}
	status := FirewallManagedStatus{AutoSync: auto, ManualRules: manualRuleViews(manual, labels)}
	backend, err := detectManagedFirewallBackend(ctx)
	if err != nil {
		status.Message = err.Error()
		return status, nil
	}
	status.Supported = true
	status.Backend = backend.name
	status.Enabled, _ = backend.enabled(ctx)
	desired, err := s.managedDesiredRules(auto, safetyPort)
	if err != nil {
		return FirewallManagedStatus{}, err
	}
	managed, err := loadManagedFirewallRules()
	if err != nil {
		return FirewallManagedStatus{}, err
	}
	owned := map[string]bool{}
	for _, rule := range managed {
		if key := firewallRuleSpec(rule); key != "" {
			owned[key] = rule.Owned
		}
	}

	if backend.name == "nftables" || backend.name == "iptables" {
		for i := range desired {
			key := firewallRuleSpec(desired[i])
			desired[i].Owned = owned[key] || status.Enabled
			desired[i].Exists = status.Enabled
		}
		status.Rules = desired
		return status, nil
	}

	existing, err := listFirewallRules(ctx, backend)
	if err != nil {
		return FirewallManagedStatus{}, err
	}
	seen := make(map[string]bool, len(desired))
	for i := range desired {
		key := firewallRuleSpec(desired[i])
		seen[key] = true
		desired[i].Exists = existing[key]
		desired[i].Owned = owned[key]
	}
	if !auto {
		for _, rule := range managed {
			key := firewallRuleSpec(rule)
			if key == "" || rule.Source != "service" || seen[key] {
				continue
			}
			rule.Exists = existing[key]
			desired = append(desired, rule)
			seen[key] = true
		}
		sortFirewallRules(desired)
	}
	status.Rules = desired
	return status, nil
}

func (s *FirewallService) syncManagedLocked(ctx context.Context, backend firewallBackend, safetyPort int) error {
	auto, err := firewallAutoSync()
	if err != nil {
		return err
	}
	desired, err := s.managedDesiredRules(auto, safetyPort)
	if err != nil {
		return err
	}
	if backend.name == "nftables" {
		if err := applyManagedNftables(ctx, backend.binary, desired); err != nil {
			return err
		}
		return saveManagedOwnedRules(desired)
	}
	if backend.name == "iptables" {
		if err := applyManagedIPTables(ctx, backend.binary, desired); err != nil {
			return err
		}
		return saveManagedOwnedRules(desired)
	}

	existing, err := listFirewallRules(ctx, backend)
	if err != nil {
		return err
	}
	managed, err := loadManagedFirewallRules()
	if err != nil {
		return err
	}
	old := map[string]FirewallRule{}
	for _, rule := range managed {
		if key := firewallRuleSpec(rule); key != "" {
			old[key] = rule
		}
	}
	want := map[string]bool{}
	next := make([]FirewallRule, 0, len(desired)+len(managed))
	for _, rule := range desired {
		key := firewallRuleSpec(rule)
		if key == "" {
			continue
		}
		want[key] = true
		rule.Owned = old[key].Owned
		if !existing[key] {
			if err := addFirewallRule(ctx, backend, rule); err != nil {
				return err
			}
			rule.Owned = true
			existing[key] = true
		}
		rule.Exists = true
		next = append(next, rule)
	}
	for _, rule := range managed {
		key := firewallRuleSpec(rule)
		if key == "" || want[key] {
			continue
		}
		if !auto && rule.Source == "service" {
			rule.Exists = false
			next = append(next, rule)
			continue
		}
		if !rule.Owned || !existing[key] {
			continue
		}
		if err := deleteFirewallRule(ctx, backend, rule); err != nil {
			return err
		}
	}
	for i := range next {
		next[i].Exists = false
	}
	return saveFirewallJSON(firewallManagedRulesKey, next)
}

func saveManagedOwnedRules(rules []FirewallRule) error {
	out := make([]FirewallRule, 0, len(rules))
	for _, rule := range rules {
		rule.Owned = true
		rule.Exists = false
		out = append(out, rule)
	}
	return saveFirewallJSON(firewallManagedRulesKey, out)
}

func disableManagedBackend(ctx context.Context, backend firewallBackend) error {
	switch backend.name {
	case "nftables":
		_, _ = runFirewallCommand(ctx, backend.binary, "delete", "table", "inet", managedNftTable)
		return nil
	case "iptables":
		return removeManagedIPTables(ctx, backend.binary)
	default:
		return setFirewallBackendEnabled(ctx, backend, false)
	}
}

func nftPortExpression(rule FirewallRule) string {
	if rule.PortRange != "" {
		spec := strings.SplitN(firewallRuleSpec(rule), "/", 2)
		if len(spec) == 2 {
			return spec[0]
		}
	}
	return strconv.Itoa(rule.Port)
}

func applyManagedNftables(ctx context.Context, binary string, rules []FirewallRule) error {
	safe, err := nftablesSafeForManagedFirewall(ctx, binary)
	if err != nil {
		return err
	}
	if !safe {
		_, _ = runFirewallCommand(ctx, binary, "delete", "table", "inet", managedNftTable)
		return errors.New("another nftables input hook appeared; Firewall-UI removed its managed table to avoid overriding administrator firewall policy")
	}
	_, _ = runFirewallCommand(ctx, binary, "delete", "table", "inet", managedNftTable)
	var script strings.Builder
	script.WriteString("table inet " + managedNftTable + " {\n")
	script.WriteString(" chain " + managedNftChain + " {\n")
	script.WriteString("  type filter hook input priority 100; policy drop;\n")
	script.WriteString("  ct state established,related accept\n")
	script.WriteString("  iifname \"lo\" accept\n")
	script.WriteString("  ip protocol icmp accept\n")
	script.WriteString("  ip6 nexthdr ipv6-icmp accept\n")
	writePortRule := func(rule FirewallRule) {
		spec := firewallRuleSpec(rule)
		if spec == "" {
			return
		}
		parts := strings.SplitN(spec, "/", 2)
		script.WriteString("  " + parts[1] + " dport " + nftPortExpression(rule) + " accept\n")
	}
	for _, rule := range rules {
		if isFirewallSafetyRule(rule) {
			writePortRule(rule)
		}
	}
	advanced, err := loadAdvancedFirewallRules()
	if err != nil {
		return err
	}
	for _, rule := range advanced {
		expression := strings.TrimSpace(advancedNFTExpression(rule))
		if expression != "" {
			script.WriteString("  " + expression + "\n")
		}
	}
	for _, rule := range rules {
		if !isFirewallSafetyRule(rule) {
			writePortRule(rule)
		}
	}
	script.WriteString(" }\n}\n")
	cmd := firewallCommand(ctx, binary, "-f", "-")
	cmd.Stdin = strings.NewReader(script.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("apply nftables firewall: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func iptablesPortExpression(rule FirewallRule) string {
	if rule.PortRange != "" {
		spec := strings.SplitN(firewallRuleSpec(rule), "/", 2)
		if len(spec) == 2 {
			return strings.ReplaceAll(spec[0], "-", ":")
		}
	}
	return strconv.Itoa(rule.Port)
}

func applyManagedIPTables(ctx context.Context, binary string, rules []FirewallRule) error {
	if err := applyManagedIPTablesBinary(ctx, binary, "icmp", rules); err != nil {
		return err
	}
	if ip6, err := hostexec.LookPath("ip6tables"); err == nil {
		if err := applyManagedIPTablesBinary(ctx, ip6, "ipv6-icmp", rules); err != nil {
			return err
		}
	}
	return nil
}

func applyManagedIPTablesBinary(ctx context.Context, binary, icmpProto string, rules []FirewallRule) error {
	_, _ = runFirewallCommand(ctx, binary, "-N", managedIPTablesChain)
	if _, err := runFirewallCommand(ctx, binary, "-F", managedIPTablesChain); err != nil {
		return err
	}
	base := [][]string{
		{"-A", managedIPTablesChain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		{"-A", managedIPTablesChain, "-i", "lo", "-j", "ACCEPT"},
		{"-A", managedIPTablesChain, "-p", icmpProto, "-j", "ACCEPT"},
	}
	for _, args := range base {
		if _, err := runFirewallCommand(ctx, binary, args...); err != nil {
			return err
		}
	}
	for _, rule := range rules {
		spec := firewallRuleSpec(rule)
		if spec == "" {
			continue
		}
		parts := strings.SplitN(spec, "/", 2)
		args := []string{"-A", managedIPTablesChain, "-p", parts[1], "--dport", iptablesPortExpression(rule), "-j", "ACCEPT"}
		if _, err := runFirewallCommand(ctx, binary, args...); err != nil {
			return err
		}
	}
	if _, err := runFirewallCommand(ctx, binary, "-A", managedIPTablesChain, "-j", "DROP"); err != nil {
		return err
	}
	for {
		cmd := firewallCommand(ctx, binary, "-C", "INPUT", "-j", managedIPTablesChain)
		if cmd.Run() != nil {
			break
		}
		_, _ = runFirewallCommand(ctx, binary, "-D", "INPUT", "-j", managedIPTablesChain)
	}
	_, err := runFirewallCommand(ctx, binary, "-A", "INPUT", "-j", managedIPTablesChain)
	return err
}

func removeManagedIPTables(ctx context.Context, binary string) error {
	for _, candidate := range []string{binary, "ip6tables"} {
		path, err := hostexec.LookPath(candidate)
		if err != nil {
			continue
		}
		for {
			cmd := firewallCommand(ctx, path, "-C", "INPUT", "-j", managedIPTablesChain)
			if cmd.Run() != nil {
				break
			}
			_, _ = runFirewallCommand(ctx, path, "-D", "INPUT", "-j", managedIPTablesChain)
		}
		_, _ = runFirewallCommand(ctx, path, "-F", managedIPTablesChain)
		_, _ = runFirewallCommand(ctx, path, "-X", managedIPTablesChain)
	}
	return nil
}
