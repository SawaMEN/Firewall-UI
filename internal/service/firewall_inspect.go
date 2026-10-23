package service

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
)

type RuleConflict struct {
	First    string `json:"first"`
	Second   string `json:"second"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}
type FirewallRuleAnalysis struct {
	Backend   string         `json:"backend"`
	Conflicts []RuleConflict `json:"conflicts"`
	Notes     []string       `json:"notes"`
}
type AccessProbe struct {
	SourceIP  string `json:"sourceIp"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	Interface string `json:"interface"`
}
type AccessDiagnosis struct {
	Verdict    string          `json:"verdict"`
	Rule       string          `json:"rule,omitempty"`
	Reason     string          `json:"reason"`
	Backend    string          `json:"backend"`
	Listener   bool            `json:"listener"`
	Processes  []Process       `json:"processes"`
	Containers []ContainerPort `json:"containers"`
	Notes      []string        `json:"notes"`
}

// advancedFamilyMask combines the IP version and the source CIDR family.
func advancedFamilyMask(r FirewallAdvancedRule) int {
	mask := 3 // IPv4 (1) and IPv6 (2).
	switch r.IPVersion {
	case "ipv4":
		mask = 1
	case "ipv6":
		mask = 2
	}
	if r.SourceCIDR == "" {
		return mask
	}
	var ip net.IP
	if strings.Contains(r.SourceCIDR, "/") {
		parsed, _, err := net.ParseCIDR(r.SourceCIDR)
		if err != nil {
			return mask // Validation handles malformed source ranges.
		}
		ip = parsed
	} else {
		ip = net.ParseIP(r.SourceCIDR)
	}
	if ip == nil {
		return mask
	}
	if ip.To4() != nil {
		return mask & 1
	}
	return mask & 2
}

func advancedOverlap(a, b FirewallAdvancedRule) bool {
	if a.Protocol != "any" && b.Protocol != "any" && a.Protocol != b.Protocol {
		return false
	}
	if advancedFamilyMask(a)&advancedFamilyMask(b) == 0 {
		return false
	}
	if a.Interface != "" && b.Interface != "" && a.Interface != b.Interface {
		return false
	}
	loA, hiA, loB, hiB := a.PortStart, a.PortEnd, b.PortStart, b.PortEnd
	if loA == 0 {
		loA, hiA = 1, 65535
	}
	if loB == 0 {
		loB, hiB = 1, 65535
	}
	if hiA == 0 {
		hiA = loA
	}
	if hiB == 0 {
		hiB = loB
	}
	if hiA < loB || hiB < loA {
		return false
	}
	return cidrIntersects(a.SourceCIDR, b.SourceCIDR)
}

func cidrIntersects(a, b string) bool {
	if a == "" || b == "" {
		return true
	}
	address := func(raw string) (net.IP, *net.IPNet) {
		if !strings.Contains(raw, "/") {
			ip := net.ParseIP(raw)
			if ip == nil {
				return nil, nil
			}
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			return ip, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
		}
		_, cidr, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, nil
		}
		return cidr.IP, cidr
	}
	ipA, netA := address(a)
	ipB, netB := address(b)
	return netA != nil && netB != nil && (netA.Contains(ipB) || netB.Contains(ipA))
}

func AnalyzeFirewallRules(backend string, basic []FirewallRule, advanced []FirewallAdvancedRule) FirewallRuleAnalysis {
	out := FirewallRuleAnalysis{Backend: backend, Conflicts: []RuleConflict{}, Notes: []string{}}
	if backend == "ufw" {
		out.Notes = append(out.Notes, "UFW insertion order, not the displayed numeric priority, determines effective precedence.")
	}
	if backend == "firewalld" {
		out.Notes = append(out.Notes, "Effective results depend on active zone bindings and existing administrator rules.")
	}
	for i := 0; i < len(advanced); i++ {
		for j := i + 1; j < len(advanced); j++ {
			a, b := advanced[i], advanced[j]
			if !advancedOverlap(a, b) {
				continue
			}
			severity := "warning"
			message := "Overlapping advanced rules; verify effective order"
			if a.Action != b.Action {
				severity = "danger"
				message = "Overlapping allow/deny rules may produce unexpected access"
			}
			out.Conflicts = append(out.Conflicts, RuleConflict{a.ID, b.ID, severity, message})
		}
	}
	for _, a := range advanced {
		if a.Action != "deny" {
			continue
		}
		for _, b := range basic {
			if !b.Exists {
				continue
			}
			basicRule := FirewallAdvancedRule{Action: "allow", Protocol: b.Protocol, PortStart: b.Port, PortEnd: b.Port, IPVersion: "any"}
			if b.PortRange != "" {
				basicRule.PortStart = firewallRuleStart(b)
				basicRule.PortEnd = firewallRuleEnd(b)
			}
			if advancedOverlap(a, basicRule) {
				out.Conflicts = append(out.Conflicts, RuleConflict{a.ID, firewallRuleSpec(b), "warning", "Deny rule overlaps an active allow rule"})
			}
		}
	}
	sort.Slice(out.Conflicts, func(i, j int) bool {
		if out.Conflicts[i].First != out.Conflicts[j].First {
			return out.Conflicts[i].First < out.Conflicts[j].First
		}
		return out.Conflicts[i].Second < out.Conflicts[j].Second
	})
	return out
}

func firewallRuleEnd(r FirewallRule) int {
	if r.PortRange == "" {
		return r.Port
	}
	var a, b int
	if _, err := fmt.Sscanf(strings.ReplaceAll(r.PortRange, ":", "-"), "%d-%d", &a, &b); err == nil {
		return b
	}
	return firewallRuleStart(r)
}

func matchAdvancedProbe(rule FirewallAdvancedRule, p AccessProbe, ip net.IP) bool {
	if rule.Protocol != "any" && rule.Protocol != p.Protocol {
		return false
	}
	if rule.PortStart > 0 && (p.Port < rule.PortStart || p.Port > max(rule.PortEnd, rule.PortStart)) {
		return false
	}
	if rule.Interface != "" && rule.Interface != p.Interface {
		return false
	}
	if rule.IPVersion == "ipv4" && ip.To4() == nil {
		return false
	}
	if rule.IPVersion == "ipv6" && ip.To4() != nil {
		return false
	}
	if rule.SourceCIDR != "" {
		if strings.Contains(rule.SourceCIDR, "/") {
			_, cidr, err := net.ParseCIDR(rule.SourceCIDR)
			if err != nil || !cidr.Contains(ip) {
				return false
			}
		} else if !net.ParseIP(rule.SourceCIDR).Equal(ip) {
			return false
		}
	}
	return true
}

func (s *FirewallService) InspectRules(ctx context.Context, safetyPort int) (FirewallRuleAnalysis, error) {
	firewallMu.Lock()
	defer firewallMu.Unlock()
	status, err := s.managedStatusSafeLocked(ctx, safetyPort)
	if err != nil {
		return FirewallRuleAnalysis{}, err
	}
	advanced, err := loadAdvancedFirewallRules()
	if err != nil {
		return FirewallRuleAnalysis{}, err
	}
	return AnalyzeFirewallRules(status.Backend, status.Rules, advanced), nil
}

// InspectAccess is a local policy simulation, not an external connectivity
// probe. In particular, upstream cloud firewalls and third-party rules may
// override the result. Expose those limits in the response.
func (s *FirewallService) InspectAccess(ctx context.Context, safetyPort int, probe AccessProbe) (AccessDiagnosis, error) {
	ip := net.ParseIP(strings.TrimSpace(probe.SourceIP))
	if ip == nil || ip.IsUnspecified() || probe.Port < 1 || probe.Port > 65535 ||
		(probe.Protocol != "tcp" && probe.Protocol != "udp") {
		return AccessDiagnosis{}, fmt.Errorf("%w: valid source IP, port and tcp/udp are required", ErrInvalidFirewallChange)
	}
	firewallMu.Lock()
	defer firewallMu.Unlock()
	status, err := s.managedStatusSafeLocked(ctx, safetyPort)
	if err != nil {
		return AccessDiagnosis{}, err
	}
	out := AccessDiagnosis{Verdict: "unknown", Backend: status.Backend, Processes: []Process{}, Containers: []ContainerPort{}, Notes: []string{"Local rule prediction only; external security groups, routing, other nftables/iptables rules and service-level access controls are not verified."}}
	var snap PortSnapshot
	if s.PortMonitor != nil {
		snap = s.PortMonitor.Snapshot()
	} else {
		snap.Ports, _ = ReadPorts("/proc")
		snap.Containers = ReadContainerPorts(ctx)
	}
	for _, sock := range snap.Ports {
		if sock.Port == probe.Port && sock.Protocol == probe.Protocol && sock.Listening && !sock.Loopback {
			out.Listener = true
			out.Processes = append(out.Processes, sock.Processes...)
		}
	}
	for _, port := range snap.Containers {
		if port.HostPort == probe.Port && port.Protocol == probe.Protocol && port.Public {
			out.Containers = append(out.Containers, port)
		}
	}
	advanced, err := loadAdvancedFirewallRules()
	if err != nil {
		return out, err
	}
	for _, rule := range advanced {
		if !isClosePortRule(rule) || rule.PortStart != probe.Port || rule.Protocol != probe.Protocol {
			continue
		}
		out.Rule = rule.ID
		if err := verifyNFTPortClose(ctx, rule); err != nil {
			out.Reason = "Saved close has no verified live kernel enforcement"
			out.Notes = append(out.Notes, err.Error())
		} else {
			out.Verdict = "predicted-deny"
			out.Reason = "Verified explicit INPUT and DNAT/FORWARD port close"
		}
		return out, nil
	}
	if len(out.Containers) > 0 {
		protected, _ := containerProtectionEnabled()
		if protected {
			out.Notes = append(out.Notes, "Container traffic is forwarded after DNAT; the dedicated FORWARD policy must be considered.")
		} else {
			out.Notes = append(out.Notes, "Container FORWARD protection is disabled; INPUT allows/denies do not reliably protect published ports.")
			out.Reason = "Container published port; inspect FORWARD/DOCKER-USER rules"
			return out, nil
		}
	}
	if !status.Enabled {
		out.Reason = "Firewall-UI management is disabled"
		return out, nil
	}
	sortAdvancedRules(advanced)
	if len(out.Containers) == 0 && (status.Backend == "nftables" || status.Backend == "iptables") {
		// Native backends evaluate protected panel/SSH access before advanced rules.
		for _, rule := range status.Rules {
			if rule.Exists && isFirewallSafetyRule(rule) && rule.Protocol == probe.Protocol &&
				probe.Port >= firewallRuleStart(rule) && probe.Port <= firewallRuleEnd(rule) {
				out.Rule = firewallRuleSpec(rule)
				out.Verdict = "predicted-allow"
				out.Reason = "Protected panel or SSH rule precedes advanced rules"
				return out, nil
			}
		}
	}
	for _, rule := range advanced {
		if !matchAdvancedProbe(rule, probe, ip) {
			continue
		}
		out.Rule = rule.ID
		out.Reason = "Matches managed advanced " + rule.Action + " rule"
		if rule.Action == "deny" {
			out.Verdict = "predicted-deny"
		} else {
			out.Verdict = "predicted-allow"
		}
		if !out.Listener && len(out.Containers) == 0 {
			out.Notes = append(out.Notes, "No matching listening service or published container was detected")
		}
		return out, nil
	}
	if len(out.Containers) > 0 {
		// Docker's published-port policy deliberately does NOT use automatic
		// service rules as exceptions. Only explicit manual/advanced allow rules.
		for _, manual := range status.ManualRules {
			if manual.Port == probe.Port && manual.Protocol == probe.Protocol {
				out.Rule = firewallRuleKey(manual.Port, manual.Protocol)
				out.Verdict = "predicted-allow"
				out.Reason = "Explicit container FORWARD exception"
				return out, nil
			}
		}
		out.Verdict = "predicted-deny"
		out.Reason = "Container FORWARD default-deny rule matches this published port"
		return out, nil
	}
	for _, rule := range status.Rules {
		if !rule.Exists || rule.Protocol != probe.Protocol {
			continue
		}
		if probe.Port < firewallRuleStart(rule) || probe.Port > firewallRuleEnd(rule) {
			continue
		}
		out.Rule = firewallRuleSpec(rule)
		out.Verdict = "predicted-allow"
		out.Reason = "Matches a managed port allow rule"
		if len(out.Containers) > 0 {
			out.Notes = append(out.Notes, "A container's allow exception must be present in the FORWARD policy as well")
		}
		return out, nil
	}
	out.Reason = "No matching managed allow rule; other backend rules may still affect access"
	if status.Backend == "nftables" || status.Backend == "iptables" {
		out.Verdict = "predicted-deny"
	}
	return out, nil
}
