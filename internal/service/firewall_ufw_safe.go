package service

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// parseUFWIncomingPolicy reads the policy from "ufw status verbose" in
// LC_ALL=C. Other policies (outgoing/routed) must not be mistaken for incoming.
func parseUFWIncomingPolicy(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(strings.ToLower(line), "default:") {
			continue
		}
		policies := strings.TrimSpace(line[len("Default:"):])
		for _, field := range strings.Split(policies, ",") {
			field = strings.ToLower(strings.TrimSpace(field))
			if policy, hasIncoming := strings.CutSuffix(field, "(incoming)"); hasIncoming {
				switch policy = strings.TrimSpace(policy); policy {
				case "allow", "deny", "reject":
					return policy
				}
			}
		}
	}
	return ""
}

func findUFWManagedRuleNumber(status, comment, spec string) int {
	for _, raw := range strings.Split(status, "\n") {
		line := strings.TrimSpace(raw)
		before, foundComment, hasComment := strings.Cut(line, "#")
		if !strings.HasPrefix(line, "[") || !hasComment || strings.TrimSpace(foundComment) != comment {
			continue
		}
		line = strings.TrimSpace(before)
		closeBracket := strings.Index(line, "]")
		if closeBracket < 0 {
			continue
		}
		numberText := strings.TrimSpace(strings.TrimPrefix(line[:closeBracket], "["))
		number, err := strconv.Atoi(numberText)
		if err != nil || number < 1 {
			continue
		}
		if spec == "" {
			return number
		}
		fields := strings.Fields(strings.TrimSpace(line[closeBracket+1:]))
		if len(fields) > 0 && strings.EqualFold(fields[0], spec) {
			return number
		}
	}
	return 0
}

// A rule for a port range or for all ports can shadow an exact-port DENY.
// Do not infer a successful block merely from an exact-looking DENY farther
// down the UFW list.
func ufwTargetCoversPort(target, spec string) bool {
	if strings.EqualFold(target, "Anywhere") {
		return true
	}
	parts := strings.Split(spec, "/")
	if len(parts) != 2 {
		return false
	}
	if strings.EqualFold(target, spec) || target == parts[0] {
		return true
	}
	targetParts := strings.Split(target, "/")
	if len(targetParts) > 2 || len(targetParts) == 2 && !strings.EqualFold(targetParts[1], parts[1]) {
		return false
	}
	rangeText := targetParts[0]
	separator := ":"
	if strings.Contains(rangeText, "-") {
		separator = "-"
	}
	limits := strings.Split(rangeText, separator)
	if len(limits) != 2 {
		return false
	}
	start, err1 := strconv.Atoi(limits[0])
	end, err2 := strconv.Atoi(limits[1])
	port, err3 := strconv.Atoi(parts[0])
	return err1 == nil && err2 == nil && err3 == nil && start <= port && port <= end
}

// Numbered UFW positions are shared between IPv4 and IPv6, but rule
// precedence is independent per IP family. Verify each family separately.
func findUFWPortDecisionFamily(status, spec string, ipv6 bool) (int, string) {
	for _, raw := range strings.Split(status, "\n") {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, "[") {
			continue
		}
		end := strings.IndexByte(line, ']')
		if end < 0 {
			continue
		}
		number, err := strconv.Atoi(strings.TrimSpace(line[1:end]))
		if err != nil || number < 1 {
			continue
		}
		before, _, _ := strings.Cut(line[end+1:], "#")
		fields := strings.Fields(before)
		if len(fields) < 3 || !ufwTargetCoversPort(fields[0], spec) {
			continue
		}
		actionAt := 1
		isIPv6 := fields[actionAt] == "(v6)"
		if isIPv6 {
			actionAt++
		}
		if isIPv6 != ipv6 || len(fields) < actionAt+2 || fields[actionAt+1] != "IN" {
			continue
		}
		action := fields[actionAt]
		if action != "ALLOW" && action != "DENY" && action != "REJECT" {
			continue
		}
		// Any earlier ALLOW potentially exposes the port, even if restricted
		// to a source/interface; do not let a later broad DENY hide it.
		if action == "ALLOW" {
			return number, action
		}
		// A DENY/REJECT scoped to one source does not block every client.
		// Continue until a globally applicable port decision is found.
		sourceAt := actionAt + 2
		if len(fields) <= sourceAt || !strings.EqualFold(fields[sourceAt], "Anywhere") {
			continue
		}
		return number, action
	}
	return 0, ""
}

func findUFWPortDecision(status, spec string) (int, string) {
	if position, action := findUFWPortDecisionFamily(status, spec, false); position != 0 {
		return position, action
	}
	return findUFWPortDecisionFamily(status, spec, true)
}

// Check the persistent UFW command list as well as the active numbered
// rules. This identifies Firewall-UI-owned rules even when the numbered
// display omits the # comment.
func hasUFWAdvancedRule(added, comment string) bool {
	for _, line := range strings.Split(added, "\n") {
		args := ownedUFWDeleteArgs(line)
		if len(args) >= 5 && args[len(args)-1] == comment {
			return true
		}
	}
	return false
}

func verifyUFWClosedPort(ctx context.Context, binary string, rule FirewallAdvancedRule) (int, error) {
	status, err := runFirewallCommand(ctx, binary, "status", "numbered")
	if err != nil {
		return 0, err
	}
	spec := strconv.Itoa(rule.PortStart) + "/" + rule.Protocol
	position, action := findUFWPortDecisionFamily(status, spec, false)
	if action != "DENY" {
		return position, fmt.Errorf("UFW has no effective leading DENY for %d/%s (first matching rule: %s at position %d)", rule.PortStart, rule.Protocol, action, position)
	}
	// If the host has IPv6 UFW rules, a v4-only DENY does not close IPv6.
	if strings.Contains(status, "(v6)") {
		ipv6Position, ipv6Action := findUFWPortDecisionFamily(status, spec, true)
		if ipv6Action != "DENY" {
			return ipv6Position, fmt.Errorf("UFW has no effective IPv6 DENY for %d/%s (first IPv6 rule: %s at position %d)", rule.PortStart, rule.Protocol, ipv6Action, ipv6Position)
		}
	}
	comment := "Firewall-UI advanced " + rule.ID
	if findUFWManagedRuleNumber(status, comment, "") != 0 {
		return position, nil
	}
	added, err := runFirewallCommand(ctx, binary, "show", "added")
	if err != nil {
		return position, err
	}
	if !hasUFWAdvancedRule(added, comment) {
		return position, fmt.Errorf("UFW DENY for %d/%s exists but Firewall-UI-owned rule %q is missing from 'ufw show added'", rule.PortStart, rule.Protocol, comment)
	}
	return position, nil
}

// Sync saved advanced policy with UFW even after a restart or when the
// automatic listening-port switch is off. A rule must be present in UFW's
// persistent configuration; for closed ports it must also be the first
// applicable inbound action for that port.
func syncUFWAdvancedRulesLocked(ctx context.Context, backend firewallBackend) error {
	if backend.name != "ufw" {
		return nil
	}
	on, err := backend.enabled(ctx)
	if err != nil || !on {
		return err
	}
	rules, err := loadAdvancedFirewallRules()
	if err != nil || len(rules) == 0 {
		return err
	}
	added, err := runFirewallCommand(ctx, backend.binary, "show", "added")
	if err != nil {
		return err
	}
	for _, rule := range rules {
		comment := "Firewall-UI advanced " + rule.ID
		exists := hasUFWAdvancedRule(added, comment)
		if exists && isClosePortRule(rule) {
			if _, err := verifyUFWClosedPort(ctx, backend.binary, rule); err != nil {
				// Only remove and replace a rule identified by its ownership
				// marker; don't modify administrator-owned entries.
				if err := deleteUFWManagedRules(ctx, backend.binary, comment, ""); err != nil {
					return err
				}
				exists = false
			}
		}
		if !exists {
			if err := applySystemAdvancedRule(ctx, backend, rule, true); err != nil {
				return fmt.Errorf("synchronize advanced UFW rule %s: %w", rule.ID, err)
			}
			added, err = runFirewallCommand(ctx, backend.binary, "show", "added")
			if err != nil {
				return err
			}
			if !hasUFWAdvancedRule(added, comment) {
				return fmt.Errorf("advanced UFW rule %s did not persist", rule.ID)
			}
		}
	}
	return nil
}

func deleteUFWManagedRules(ctx context.Context, binary, comment, spec string) error {
	for attempts := 0; attempts < 128; attempts++ {
		status, err := runFirewallCommand(ctx, binary, "status", "numbered")
		if err != nil {
			return err
		}
		if strings.Contains(status, "Status: inactive") {
			added, err := runFirewallCommand(ctx, binary, "show", "added")
			if err != nil {
				return err
			}
			for _, line := range strings.Split(added, "\n") {
				args := ownedUFWDeleteArgs(line)
				if len(args) < 6 || args[len(args)-1] != comment {
					continue
				}
				if spec != "" && args[3] != spec {
					continue
				}
				if _, err := runFirewallCommand(ctx, binary, args...); err != nil {
					return err
				}
			}
			return nil
		}
		number := findUFWManagedRuleNumber(status, comment, spec)
		if number > 0 {
			if _, err := runFirewallCommand(ctx, binary, "--force", "delete", strconv.Itoa(number)); err != nil {
				return fmt.Errorf("delete UFW rule %d: %w", number, err)
			}
			continue
		}
		// Some UFW versions omit comments from "status numbered" entirely.
		// Find the *owned* rule in persistent configuration instead of
		// silently treating it as deleted and leaving the port blocked.
		added, err := runFirewallCommand(ctx, binary, "show", "added")
		if err != nil {
			return err
		}
		var args []string
		for _, line := range strings.Split(added, "\n") {
			candidate := ownedUFWDeleteArgs(line)
			if len(candidate) < 6 || candidate[len(candidate)-1] != comment {
				continue
			}
			if spec != "" && candidate[3] != spec {
				continue
			}
			args = candidate
			break
		}
		if len(args) == 0 {
			return nil
		}
		if _, err := runFirewallCommand(ctx, binary, args...); err != nil {
			return fmt.Errorf("delete UFW rule with missing numbered comment: %w", err)
		}
	}
	return fmt.Errorf("too many matching UFW rules for comment %q", comment)
}
