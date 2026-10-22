package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

func closeRuleID(port int, protocol string) string {
	return fmt.Sprintf("close-port-%d-%s", port, protocol)
}
func isClosePortRule(rule FirewallAdvancedRule) bool {
	return rule.ID == closeRuleID(rule.PortStart, rule.Protocol) && rule.Action == "deny" && rule.PortStart > 0 && rule.PortEnd == rule.PortStart && rule.SourceCIDR == "" && rule.Interface == "" && rule.IPVersion == "any" && rule.Priority == -1000
}

// SetPortClosedSafe installs an explicit denial that takes precedence over
// auto-open rules. It leaves the listening process running.
func (s *FirewallService) SetPortClosedSafe(ctx context.Context, port int, protocol string, closed bool, safetyPort int) ([]FirewallAdvancedRule, error) {
	firewallMu.Lock()
	defer firewallMu.Unlock()
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if port < 1 || port > 65535 || (protocol != "tcp" && protocol != "udp") {
		return nil, fmt.Errorf("%w: invalid port or protocol", ErrInvalidFirewallChange)
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
		return nil, fmt.Errorf("%w: Включите файрволл перед изменением доступа к порту", ErrInvalidFirewallChange)
	}
	if isManagedNativeFirewall(backend.name) {
		if desired, configured, err := firewallManagedEnabledPreference(); err != nil {
			return nil, err
		} else if configured && !desired {
			return nil, fmt.Errorf("%w: Включите файрволл в панели", ErrInvalidFirewallChange)
		}
	}
	if closed {
		desired, err := s.managedDesiredRules(false, safetyPort)
		if err != nil {
			return nil, err
		}
		for _, rule := range desired {
			if isFirewallSafetyRule(rule) && rule.Port == port && rule.Protocol == protocol {
				return nil, fmt.Errorf("%w: Порт панели, SSH или текущего соединения защищён от закрытия", ErrInvalidFirewallChange)
			}
		}
	}
	rules, err := loadAdvancedFirewallRules()
	if err != nil {
		return nil, err
	}
	id := closeRuleID(port, protocol)
	rule := FirewallAdvancedRule{ID: id, Action: "deny", Protocol: protocol, PortStart: port, PortEnd: port, IPVersion: "any", Priority: -1000, Label: "Закрыт вручную"}
	found := false
	for _, r := range rules {
		if r.ID == id {
			found = true
			if !isClosePortRule(r) {
				return nil, fmt.Errorf("%w: reserved port rule ID is already used", ErrInvalidFirewallChange)
			}
			if closed {
				// A saved close is not proof that the live rule still exists.
				// Repeated close requests must repair a missing/stale UFW rule
				// and install the DNAT hook after an upgrade or restart.
				if backend.name == "ufw" {
					status, statusErr := runFirewallCommand(ctx, backend.binary, "status", "numbered")
					if statusErr != nil {
						return nil, statusErr
					}
					number := findUFWManagedRuleNumber(status, "Firewall-UI advanced "+id, "")
					if number != 1 {
						if number > 0 {
							if err := deleteUFWManagedRules(ctx, backend.binary, "Firewall-UI advanced "+id, ""); err != nil {
								return nil, err
							}
						}
						if err := applySystemAdvancedRule(ctx, backend, rule, true); err != nil {
							return nil, err
						}
					}
				}
				if err := s.syncContainerProtectionLocked(ctx); err != nil {
					return nil, err
				}
				return rules, nil
			}
			rule = r
		}
	}
	if !closed && !found {
		return rules, nil
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
			recovery, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			restoreErr = s.applyAdvancedChangeLocked(recovery, rule, !closed, safetyPort)
		}
		return nil, errors.Join(err, restoreErr)
	}
	return next, nil
}
