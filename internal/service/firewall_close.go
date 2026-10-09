package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

func closeRuleID(port int, protocol string) string {
	return fmt.Sprintf("close-port-%d-%s", port, protocol)
}
func isClosePortRule(rule FirewallAdvancedRule) bool {
	return rule.ID == closeRuleID(rule.PortStart, rule.Protocol) && rule.Action == "deny" && rule.PortStart > 0 && rule.PortEnd == rule.PortStart && rule.SourceCIDR == "" && rule.Interface == "" && rule.IPVersion == "any"
}

// SetPortClosedSafe installs an explicit denial that takes precedence over
// auto-open rules. It leaves the listening process running.
func (s *FirewallService) SetPortClosedSafe(ctx context.Context, port int, protocol string, closed bool, safetyPort int) ([]FirewallAdvancedRule, error) {
	firewallMu.Lock()
	defer firewallMu.Unlock()
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if port < 1 || port > 65535 || (protocol != "tcp" && protocol != "udp") {
		return nil, fmt.Errorf("invalid port or protocol")
	}
	backend, err := detectManagedFirewallBackend(ctx)
	if err != nil {
		return nil, err
	}
	enabled, err := backend.enabled(ctx)
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, fmt.Errorf("Включите файрволл перед изменением доступа к порту")
	}
	if desired, configured, err := firewallManagedEnabledPreference(); err != nil {
		return nil, err
	} else if configured && !desired {
		return nil, fmt.Errorf("Включите управление файрволлом в панели")
	}
	if closed {
		desired, err := s.managedDesiredRules(false, safetyPort)
		if err != nil {
			return nil, err
		}
		for _, rule := range desired {
			if isFirewallSafetyRule(rule) && rule.Port == port && rule.Protocol == protocol {
				return nil, fmt.Errorf("Порт панели, SSH или текущего соединения защищён от закрытия")
			}
		}
	}
	rules, err := loadAdvancedFirewallRules()
	if err != nil {
		return nil, err
	}
	id := closeRuleID(port, protocol)
	rule := FirewallAdvancedRule{ID: id, Action: "deny", Protocol: protocol, PortStart: port, PortEnd: port, IPVersion: "any", Priority: -1000, Label: "Закрыт вручную"}
	for _, r := range rules {
		if r.ID == id {
			if !isClosePortRule(r) {
				return nil, fmt.Errorf("reserved port rule ID is already used")
			}
			if closed {
				return rules, nil
			}
			rule = r
		}
	}
	next := removeAdvancedByID(rules, id)
	if closed {
		next = append(next, rule)
	}
	sortAdvancedRules(next)
	if err := saveFirewallJSON(firewallAdvancedRulesKey, next); err != nil {
		return nil, err
	}
	if err := s.applyAdvancedChangeLocked(ctx, rule, closed, safetyPort); err != nil {
		restoreErr := saveFirewallJSON(firewallAdvancedRulesKey, rules)
		if restoreErr == nil {
			restoreErr = s.applyAdvancedChangeLocked(ctx, rule, !closed, safetyPort)
		}
		return nil, errors.Join(err, restoreErr)
	}
	return next, nil
}
