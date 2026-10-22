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

// ufw status numbered may omit comments and may list unrelated rules above a
// port. Return the *first matching inbound rule* for the target port; only
// that action determines whether the port is allowed or denied.
func findUFWPortDecision(status, spec string) (int, string) {
	ipv6Position, ipv6Action := 0, ""
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
		if len(fields) < 3 || !strings.EqualFold(fields[0], spec) {
			continue
		}
		actionAt := 1
		ipv6 := false
		if fields[actionAt] == "(v6)" {
			ipv6 = true
			actionAt++
		}
		if len(fields) < actionAt+2 || fields[actionAt+1] != "IN" {
			continue
		}
		action := fields[actionAt]
		if action != "ALLOW" && action != "DENY" && action != "REJECT" {
			continue
		}
		if !ipv6 {
			return number, action
		}
		if ipv6Position == 0 {
			ipv6Position, ipv6Action = number, action
		}
	}
	return ipv6Position, ipv6Action
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
	position, action := findUFWPortDecision(status, strconv.Itoa(rule.PortStart)+"/"+rule.Protocol)
	if action != "DENY" {
		return position, fmt.Errorf("UFW has no effective leading DENY for %d/%s (first matching rule: %s at position %d)", rule.PortStart, rule.Protocol, action, position)
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
		if number == 0 {
			return nil
		}
		if _, err := runFirewallCommand(ctx, binary, "--force", "delete", strconv.Itoa(number)); err != nil {
			return fmt.Errorf("delete UFW rule %d: %w", number, err)
		}
	}
	return fmt.Errorf("too many matching UFW rules for comment %q", comment)
}
