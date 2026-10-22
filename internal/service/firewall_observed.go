package service

import (
    "strconv"
    "strings"
)

// appendObservedFirewallAllows merges only unrestricted TCP/UDP ALLOW entries
// observed in the host firewall into the status view. It never persists or
// manages them; ownership belongs to the external administrator.
func appendObservedFirewallAllows(desired []FirewallRule, observed map[string]bool, active bool) []FirewallRule {
    result := append([]FirewallRule(nil), desired...)
    if !active {
        sortFirewallRules(result)
        return result
    }
    seen := make(map[string]bool, len(result))
    for _, rule := range result {
        if spec := firewallRuleSpec(rule); spec != "" {
            seen[spec] = true
        }
    }
    for raw, exists := range observed {
        if !exists || seen[raw] {
            continue
        }
        spec, valid := canonicalFirewallSpec(raw)
        if !valid || spec != raw || seen[spec] {
            continue
        }
        parts := strings.SplitN(spec, "/", 2)
        rule := FirewallRule{
            Protocol: parts[1],
            Source:   "external",
            Label:    "Host firewall",
            Owned:    false,
            Exists:   true,
        }
        if strings.Contains(parts[0], "-") {
            rule.PortRange = parts[0]
        } else {
            port, err := strconv.Atoi(parts[0])
            if err != nil {
                continue
            }
            rule.Port = port
        }
        result = append(result, rule)
        seen[spec] = true
    }
    sortFirewallRules(result)
    return result
}
