package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const firewallAdvancedRulesKey = "firewallAdvancedRules"

var interfacePattern = regexp.MustCompile(`^[A-Za-z0-9_.:@-]{1,32}$`)

type FirewallAdvancedRule struct {
	ID         string `json:"id"`
	Action     string `json:"action"`
	Protocol   string `json:"protocol"`
	PortStart  int    `json:"portStart,omitempty"`
	PortEnd    int    `json:"portEnd,omitempty"`
	SourceCIDR string `json:"sourceCidr,omitempty"`
	Interface  string `json:"interface,omitempty"`
	IPVersion  string `json:"ipVersion,omitempty"`
	Label      string `json:"label,omitempty"`
	Priority   int    `json:"priority"`
}

func (s *FirewallService) AdvancedRules() ([]FirewallAdvancedRule, error) {
	firewallMu.Lock()
	defer firewallMu.Unlock()
	return loadAdvancedFirewallRules()
}

func (s *FirewallService) AddAdvancedRuleSafe(ctx context.Context, rule FirewallAdvancedRule, safetyPort int) ([]FirewallAdvancedRule, error) {
	if strings.HasPrefix(rule.ID, "close-port-") {
		return nil, errors.New("use the port access action for reserved close rules")
	}
	firewallMu.Lock()
	defer firewallMu.Unlock()
	if err := validateAdvancedRule(&rule); err != nil {
		return nil, err
	}
	if rule.ID == "" {
		rule.ID = newFirewallRuleID()
	}
	rules, err := loadAdvancedFirewallRules()
	if err != nil {
		return nil, err
	}
	rules = append(rules, rule)
	sortAdvancedRules(rules)
	if err := saveFirewallJSON(firewallAdvancedRulesKey, rules); err != nil {
		return nil, err
	}
	if err := s.applyAdvancedChangeLocked(ctx, rule, true, safetyPort); err != nil {
		rules = removeAdvancedByID(rules, rule.ID)
		_ = saveFirewallJSON(firewallAdvancedRulesKey, rules)
		return nil, err
	}
	return rules, nil
}

func (s *FirewallService) DeleteAdvancedRuleSafe(ctx context.Context, id string, safetyPort int) ([]FirewallAdvancedRule, error) {
	firewallMu.Lock()
	defer firewallMu.Unlock()
	rules, err := loadAdvancedFirewallRules()
	if err != nil {
		return nil, err
	}
	var target *FirewallAdvancedRule
	for i := range rules {
		if rules[i].ID == id {
			copy := rules[i]
			target = &copy
			break
		}
	}
	if target == nil {
		return nil, errors.New("advanced rule not found")
	}
	next := removeAdvancedByID(rules, id)
	if err := saveFirewallJSON(firewallAdvancedRulesKey, next); err != nil {
		return nil, err
	}
	if err := s.applyAdvancedChangeLocked(ctx, *target, false, safetyPort); err != nil {
		_ = saveFirewallJSON(firewallAdvancedRulesKey, rules)
		return nil, err
	}
	return next, nil
}

func (s *FirewallService) ReplaceAdvancedRulesSafe(ctx context.Context, rules []FirewallAdvancedRule, safetyPort int) error {
	firewallMu.Lock()
	defer firewallMu.Unlock()
	previous, err := loadAdvancedFirewallRules()
	if err != nil {
		return err
	}
	for i := range rules {
		if rules[i].ID == "" {
			rules[i].ID = newFirewallRuleID()
		}
		if err := validateAdvancedRule(&rules[i]); err != nil {
			return err
		}
	}
	sortAdvancedRules(rules)
	if err := saveFirewallJSON(firewallAdvancedRulesKey, rules); err != nil {
		return err
	}
	backend, err := detectManagedFirewallBackend(ctx)
	if err != nil {
		return err
	}
	on, err := backend.enabled(ctx)
	if err != nil || !on {
		return err
	}
	if backend.name == "nftables" || backend.name == "iptables" {
		return s.syncManagedSafeLocked(ctx, backend, safetyPort)
	}
	return reconcileLegacyAdvancedRules(ctx, backend, previous, rules)
}

func loadAdvancedFirewallRules() ([]FirewallAdvancedRule, error) {
	var rules []FirewallAdvancedRule
	raw, err := firewallSetting(firewallAdvancedRulesKey, "[]")
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(raw), &rules); err != nil {
		return nil, err
	}
	for i := range rules {
		if err := validateAdvancedRule(&rules[i]); err != nil {
			return nil, fmt.Errorf("stored advanced rule %q: %w", rules[i].ID, err)
		}
	}
	sortAdvancedRules(rules)
	return rules, nil
}

func validateAdvancedRule(rule *FirewallAdvancedRule) error {
	rule.Action = strings.ToLower(strings.TrimSpace(rule.Action))
	rule.Protocol = strings.ToLower(strings.TrimSpace(rule.Protocol))
	rule.SourceCIDR = strings.TrimSpace(rule.SourceCIDR)
	rule.Interface = strings.TrimSpace(rule.Interface)
	rule.IPVersion = strings.ToLower(strings.TrimSpace(rule.IPVersion))
	rule.Label = normalizeFirewallLabelUnicode(rule.Label)
	if rule.Action != "allow" && rule.Action != "deny" {
		return errors.New("action must be allow or deny")
	}
	if rule.Protocol == "" {
		rule.Protocol = "any"
	}
	if rule.Protocol != "tcp" && rule.Protocol != "udp" && rule.Protocol != "any" {
		return errors.New("protocol must be tcp, udp, or any")
	}
	if rule.PortStart < 0 || rule.PortStart > 65535 || rule.PortEnd < 0 || rule.PortEnd > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	if rule.PortStart == 0 && rule.PortEnd != 0 {
		return errors.New("portStart is required when portEnd is set")
	}
	if rule.PortStart > 0 && rule.PortEnd == 0 {
		rule.PortEnd = rule.PortStart
	}
	if rule.PortEnd > 0 && rule.PortEnd < rule.PortStart {
		return errors.New("portEnd must be greater than or equal to portStart")
	}
	if rule.Protocol == "any" && rule.PortStart > 0 {
		return errors.New("a port requires tcp or udp protocol")
	}
	if rule.SourceCIDR != "" {
		ip := net.ParseIP(rule.SourceCIDR)
		if ip == nil {
			var network *net.IPNet
			var err error
			_, network, err = net.ParseCIDR(rule.SourceCIDR)
			if err != nil {
				return errors.New("invalid source CIDR")
			}
			rule.SourceCIDR = network.String()
			ip = network.IP
		} else {
			rule.SourceCIDR = ip.String()
		}
		family := "ipv6"
		if ip.To4() != nil {
			family = "ipv4"
		}
		if rule.IPVersion != "" && rule.IPVersion != "any" && rule.IPVersion != family {
			return errors.New("IP version does not match source CIDR")
		}
		rule.IPVersion = family
	}
	if rule.IPVersion == "" {
		rule.IPVersion = "any"
	}
	if rule.IPVersion != "any" && rule.IPVersion != "ipv4" && rule.IPVersion != "ipv6" {
		return errors.New("ipVersion must be any, ipv4, or ipv6")
	}
	if rule.Interface != "" && !interfacePattern.MatchString(rule.Interface) {
		return errors.New("invalid interface name")
	}
	if rule.Priority < -1000 || rule.Priority > 1000 {
		return errors.New("priority must be between -1000 and 1000")
	}
	return nil
}

func sortAdvancedRules(rules []FirewallAdvancedRule) {
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Priority != rules[j].Priority {
			return rules[i].Priority < rules[j].Priority
		}
		if rules[i].Action != rules[j].Action {
			return rules[i].Action == "deny"
		}
		return rules[i].ID < rules[j].ID
	})
}

func removeAdvancedByID(rules []FirewallAdvancedRule, id string) []FirewallAdvancedRule {
	out := make([]FirewallAdvancedRule, 0, len(rules))
	for _, rule := range rules {
		if rule.ID != id {
			out = append(out, rule)
		}
	}
	return out
}

func newFirewallRuleID() string {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return strconv.FormatInt(int64(len(raw)), 10)
	}
	return hex.EncodeToString(raw)
}

func (s *FirewallService) applyAdvancedChangeLocked(ctx context.Context, rule FirewallAdvancedRule, add bool, safetyPort int) error {
	backend, err := detectManagedFirewallBackend(ctx)
	if err != nil {
		return err
	}
	on, err := backend.enabled(ctx)
	if err != nil || !on {
		return err
	}
	if backend.name == "nftables" || backend.name == "iptables" {
		return s.syncManagedSafeLocked(ctx, backend, safetyPort)
	}
	return applyLegacyAdvancedRule(ctx, backend, rule, add)
}

func isFirewallSafetyRule(rule FirewallRule) bool {
	switch rule.Source {
	case "panel", "session", "ssh":
		return true
	default:
		return false
	}
}

func advancedPortExpression(rule FirewallAdvancedRule, separator string) string {
	if rule.PortStart == 0 {
		return ""
	}
	if rule.PortEnd == 0 || rule.PortEnd == rule.PortStart {
		return strconv.Itoa(rule.PortStart)
	}
	return strconv.Itoa(rule.PortStart) + separator + strconv.Itoa(rule.PortEnd)
}

func advancedNFTExpression(rule FirewallAdvancedRule) string {
	parts := []string{}
	if rule.IPVersion == "ipv4" && rule.SourceCIDR == "" {
		parts = append(parts, "meta nfproto ipv4")
	} else if rule.IPVersion == "ipv6" && rule.SourceCIDR == "" {
		parts = append(parts, "meta nfproto ipv6")
	}
	if rule.Interface != "" {
		parts = append(parts, `iifname "`+rule.Interface+`"`)
	}
	if rule.SourceCIDR != "" {
		family := "ip"
		if rule.IPVersion == "ipv6" {
			family = "ip6"
		}
		parts = append(parts, family+" saddr "+rule.SourceCIDR)
	}
	if rule.Protocol == "tcp" || rule.Protocol == "udp" {
		parts = append(parts, rule.Protocol)
		if rule.PortStart > 0 {
			ports := advancedPortExpression(rule, "-")
			if rule.PortEnd > rule.PortStart {
				ports = rule.Protocol + " dport " + strconv.Itoa(rule.PortStart) + "-" + strconv.Itoa(rule.PortEnd)
				parts = append(parts, strings.TrimPrefix(ports, rule.Protocol+" "))
			} else {
				parts = append(parts, "dport "+ports)
			}
		}
	}
	verdict := "accept"
	if rule.Action == "deny" {
		verdict = "drop"
	}
	return strings.Join(parts, " ") + " " + verdict
}

func advancedIPTablesArgs(rule FirewallAdvancedRule, ipv6 bool) ([]string, bool) {
	if rule.IPVersion == "ipv4" && ipv6 || rule.IPVersion == "ipv6" && !ipv6 {
		return nil, false
	}
	args := []string{"-A", managedIPTablesChain}
	if rule.Interface != "" {
		args = append(args, "-i", rule.Interface)
	}
	if rule.SourceCIDR != "" {
		args = append(args, "-s", rule.SourceCIDR)
	}
	if rule.Protocol != "any" {
		args = append(args, "-p", rule.Protocol)
		if rule.PortStart > 0 {
			args = append(args, "--dport", advancedPortExpression(rule, ":"))
		}
	}
	args = append(args, "-m", "comment", "--comment", managedIPTablesRuleComment)
	if rule.Action == "deny" {
		args = append(args, "-j", "DROP")
	} else {
		args = append(args, "-j", "ACCEPT")
	}
	return args, true
}

func applyLegacyAdvancedRule(ctx context.Context, backend firewallBackend, rule FirewallAdvancedRule, add bool) error {
	if add && isClosePortRule(rule) {
		desired, err := (&FirewallService{}).managedDesiredRules(false, rememberedFirewallSafetyPort())
		if err != nil {
			return err
		}
		for _, safety := range desired {
			if isFirewallSafetyRule(safety) && safety.Port == rule.PortStart && safety.Protocol == rule.Protocol {
				return errors.New("a protected panel or SSH port cannot be closed")
			}
		}
	}
	if backend.name == "ufw" {
		if rule.IPVersion != "any" && rule.SourceCIDR == "" {
			return errors.New("UFW requires a source CIDR/IP for an IPv4-only or IPv6-only advanced rule")
		}
		if !add {
			return deleteUFWManagedRules(ctx, backend.binary, "Firewall-UI advanced "+rule.ID, "")
		}
		args := []string{rule.Action}
		if isClosePortRule(rule) {
			args = []string{"insert", "1", rule.Action}
		}
		if rule.Interface != "" {
			args = append(args, "in", "on", rule.Interface)
		}
		if rule.SourceCIDR != "" {
			args = append(args, "from", rule.SourceCIDR)
		}
		args = append(args, "to", "any")
		if rule.PortStart > 0 {
			args = append(args, "port", advancedPortExpression(rule, ":"))
		}
		if rule.Protocol != "any" {
			args = append(args, "proto", rule.Protocol)
		}
		if add {
			args = append(args, "comment", "Firewall-UI advanced "+rule.ID)
		}
		_, err := runFirewallCommand(ctx, backend.binary, args...)
		return err
	}
	if backend.name != "firewalld" {
		return errors.New("advanced rules are not supported by this firewall backend")
	}
	if rule.Interface != "" {
		return errors.New("firewalld advanced rules with an interface are not supported; assign the interface to a zone or use nftables/iptables/UFW")
	}
	rich := firewalldRichRule(rule)
	if !add {
		return removeFirewalldRichRule(ctx, backend, rich)
	}
	flag := "--add-rich-rule=" + rich
	if !add {
		flag = "--remove-rich-rule=" + rich
	}
	on, _ := backend.enabled(ctx)
	if on {
		if _, err := runFirewallCommand(ctx, backend.binary, "--permanent", "--zone="+backend.zone, flag); err != nil {
			return err
		}
		_, err := runFirewallCommand(ctx, backend.binary, "--zone="+backend.zone, flag)
		return err
	}
	if backend.offline == "" {
		return errors.New("firewalld is stopped and firewall-offline-cmd is unavailable")
	}
	_, err := runFirewallCommand(ctx, backend.offline, "--zone="+backend.zone, flag)
	return err
}

func firewalldRichRule(rule FirewallAdvancedRule) string {
	parts := []string{"rule"}
	if isClosePortRule(rule) {
		parts = append(parts, `priority="-1000"`)
	}
	if rule.IPVersion == "ipv4" {
		parts = append(parts, `family="ipv4"`)
	} else if rule.IPVersion == "ipv6" {
		parts = append(parts, `family="ipv6"`)
	}
	if rule.SourceCIDR != "" {
		parts = append(parts, `source address="`+rule.SourceCIDR+`"`)
	}
	if rule.Protocol != "any" && rule.PortStart > 0 {
		parts = append(parts, `port port="`+advancedPortExpression(rule, "-")+`" protocol="`+rule.Protocol+`"`)
	} else if rule.Protocol != "any" {
		parts = append(parts, `protocol value="`+rule.Protocol+`"`)
	}
	if rule.Action == "deny" {
		parts = append(parts, "drop")
	} else {
		parts = append(parts, "accept")
	}
	return strings.Join(parts, " ")
}

func reconcileLegacyAdvancedRules(ctx context.Context, backend firewallBackend, previous, rules []FirewallAdvancedRule) error {
	// Existing advanced rules are tagged in UFW and represented as exact rich rules
	// in firewalld. Restore is implemented as delete-known + add desired; unknown
	// administrator rules remain untouched.
	for _, rule := range previous {
		_ = applyLegacyAdvancedRule(ctx, backend, rule, false)
	}
	for _, rule := range rules {
		if err := applyLegacyAdvancedRule(ctx, backend, rule, true); err != nil {
			return err
		}
	}
	return nil
}
