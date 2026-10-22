package service

import (
	"context"
	"strconv"
	"strings"
)

// Unknown firewall rules are shown without pretending to understand their
// effective outcome. Raw commands are for display only, never executed.
type FirewallUnknownRule struct {
	Raw      string `json:"raw"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	CanClose bool   `json:"canClose"`
	CanDelete bool  `json:"canDelete"`
	Reason   string `json:"reason"`
}

func unknownUFWRule(line string) (FirewallUnknownRule, bool) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "ufw ") {
		return FirewallUnknownRule{}, false
	}
	// Firewall-UI-created advanced/close rules already have their own
	// dedicated UI rows. Do not incorrectly mark them as foreign/unknown.
	if strings.Contains(line, "Firewall-UI advanced ") {
		return FirewallUnknownRule{}, false
	}
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return FirewallUnknownRule{Raw: line, Reason: "unrecognized"}, true
	}
	if _, ok := parseUFWAllowSpec(line); ok {
		return FirewallUnknownRule{}, false // straightforward ALLOW in main table
	}
	result := FirewallUnknownRule{Raw: line, Reason: "unrecognized"}
	// Only ALLOW with exactly one concrete port and protocol can be blocked
	// via /api/firewall/port. This never deletes or edits the external rule.
	if fields[1] != "allow" {
		return result, true
	}
	port, proto := "", ""
	for i := 2; i < len(fields); i++ {
		if fields[i] == "comment" {
			break
		}
		if fields[i] == "port" && i+1 < len(fields) {
			port = fields[i+1]
		}
		if fields[i] == "proto" && i+1 < len(fields) {
			proto = fields[i+1]
		}
		if spec, ok := canonicalFirewallSpec(fields[i]); ok {
			if p, t, found := strings.Cut(spec, "/"); found {
				port, proto = p, t
			}
		}
	}
	if strings.ContainsAny(port, ":-") {
		return result, true
	}
	spec, valid := canonicalFirewallSpec(port + "/" + proto)
	if !valid || strings.Contains(spec, "-") {
		return result, true
	}
	number, err := strconv.Atoi(port)
	if err != nil {
		return result, true
	}
	result.Port, result.Protocol, result.CanClose = number, proto, true
	result.Reason = "nonstandard-allow"
	return result, true
}

func unknownFirewalldRule(line string) FirewallUnknownRule {
	return FirewallUnknownRule{Raw: strings.TrimSpace(line), Reason: "rich-rule"}
}

// Read ALLOW coverage and other rules from one UFW snapshot, so refreshing
// the overview does not run 'ufw show added' twice.
func observedHostRules(ctx context.Context, b firewallBackend) (map[string]bool, []FirewallUnknownRule, error) {
	if b.name != "ufw" {
		known, err := listFirewallRules(ctx, b)
		if err != nil {
			return nil, nil, err
		}
		if b.name != "firewalld" {
			return known, nil, nil
		}
		binary := b.binary
		on, err := b.enabled(ctx)
		if err != nil {
			return nil, nil, err
		}
		if !on {
			if b.offline == "" {
				return known, nil, nil
			}
			binary = b.offline
		}
		raw, err := runFirewallCommand(ctx, binary, "--zone="+b.zone, "--list-rich-rules")
		if err != nil {
			return known, nil, nil // not supported on all firewalld versions
		}
		advanced, err := loadAdvancedFirewallRules()
		if err != nil {
			return nil, nil, err
		}
		ours := make(map[string]bool, len(advanced))
		for _, rule := range advanced {
			ours[firewalldRichRule(rule)] = true
		}
		var unknown []FirewallUnknownRule
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !ours[line] {
				unknown = append(unknown, unknownFirewalldRule(line))
			}
		}
		return known, unknown, nil
	}
	raw, err := runFirewallCommand(ctx, b.binary, "show", "added")
	if err != nil {
		return nil, nil, err
	}
	known := make(map[string]bool)
	var unknown []FirewallUnknownRule
	for _, line := range strings.Split(raw, "\n") {
		if spec, ok := parseUFWAllowSpec(line); ok {
			known[spec] = true
		} else if item, ok := unknownUFWRule(line); ok {
			unknown = append(unknown, item)
		}
	}
	if len(unknown) > 500 {
		unknown = append(unknown[:500], FirewallUnknownRule{
			Raw:    "More than 500 unknown entries; inspect the host firewall for the complete list.",
			Reason: "truncated",
		})
	}
	return known, unknown, nil
}
