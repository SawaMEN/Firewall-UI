package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

func normalizeFirewallLabelUnicode(label string) string {
	label = strings.TrimSpace(label)
	if len(label) <= 120 {
		return label
	}
	var out strings.Builder
	out.Grow(120)
	for _, r := range label {
		width := utf8.RuneLen(r)
		if width < 0 || out.Len()+width > 120 {
			break
		}
		out.WriteRune(r)
	}
	return out.String()
}

func appendFrozenInboundRules(desired, managed []FirewallRule) []FirewallRule {
	seen := make(map[string]bool, len(desired)+len(managed))
	out := make([]FirewallRule, 0, len(desired)+len(managed))
	for _, rule := range desired {
		key := firewallRuleSpec(rule)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, rule)
	}
	for _, rule := range managed {
		key := firewallRuleSpec(rule)
		if key == "" || seen[key] || rule.Source != "service" {
			continue
		}
		seen[key] = true
		out = append(out, rule)
	}
	sortFirewallRules(out)
	return out
}

func (s *FirewallService) syncManagedSafeLocked(ctx context.Context, backend firewallBackend, safetyPort int) (err error) {
	// Keep the DNAT/FORWARD container policy synchronized with managed ports.
	defer func() {
		if err == nil {
			err = s.syncContainerProtectionLocked(ctx)
		}
	}()
	if backend.name != "nftables" && backend.name != "iptables" {
		return s.syncManagedLocked(ctx, backend, safetyPort)
	}

	auto, err := firewallAutoSync()
	if err != nil {
		return err
	}
	desired, err := s.managedDesiredRules(auto, safetyPort)
	if err != nil {
		return err
	}
	if !auto {
		managed, err := loadManagedFirewallRules()
		if err != nil {
			return err
		}
		desired = appendFrozenInboundRules(desired, managed)
	}

	switch backend.name {
	case "nftables":
		if err := applyManagedNftables(ctx, backend.binary, desired); err != nil {
			return err
		}
	case "iptables":
		if err := applyManagedIPTablesSafe(ctx, backend.binary, desired); err != nil {
			// IPv4 may already have been installed when ip6tables fails. Remove
			// both owned chains so a failed operation never leaves a half-enabled
			// firewall behind.
			_ = removeManagedIPTables(ctx, backend.binary)
			return err
		}
	}
	return saveManagedOwnedRules(desired)
}

func decorateFrozenNativeStatus(status FirewallManagedStatus, managed []FirewallRule) FirewallManagedStatus {
	if status.AutoSync || (status.Backend != "nftables" && status.Backend != "iptables") {
		return status
	}
	seen := make(map[string]bool, len(status.Rules)+len(managed))
	for _, rule := range status.Rules {
		if key := firewallRuleSpec(rule); key != "" {
			seen[key] = true
		}
	}
	for _, rule := range managed {
		key := firewallRuleSpec(rule)
		if key == "" || seen[key] || rule.Source != "service" {
			continue
		}
		rule.Exists = status.Enabled
		rule.Owned = true
		status.Rules = append(status.Rules, rule)
		seen[key] = true
	}
	sortFirewallRules(status.Rules)
	return status
}

func (s *FirewallService) managedStatusSafeLocked(ctx context.Context, safetyPort int) (FirewallManagedStatus, error) {
	status, err := s.managedStatusLocked(ctx, safetyPort)
	if err != nil {
		return FirewallManagedStatus{}, err
	}
	managed, err := loadManagedFirewallRules()
	if err != nil {
		return FirewallManagedStatus{}, err
	}
	status = decorateFrozenNativeStatus(status, managed)
	// Enabled always mirrors the live host firewall, not the saved UI preference.
	// UFW/firewalld can be toggled outside Firewall-UI, so reflect that state.
	return status, nil
}

func (s *FirewallService) GetManagedStatusSafe(ctx context.Context, safetyPort int) (FirewallManagedStatus, error) {
	firewallMu.Lock()
	defer firewallMu.Unlock()
	return s.managedStatusSafeLocked(ctx, safetyPort)
}

func (s *FirewallService) SetManagedEnabledSafe(ctx context.Context, enabled bool, safetyPort int) (FirewallManagedStatus, error) {
	firewallMu.Lock()
	defer firewallMu.Unlock()
	backend, err := detectManagedFirewallBackend(ctx)
	if err != nil {
		return FirewallManagedStatus{}, err
	}
	if enabled {
		if err := s.syncManagedSafeLocked(ctx, backend, safetyPort); err != nil {
			return FirewallManagedStatus{}, err
		}
		if backend.name == "ufw" || backend.name == "firewalld" {
			on, stateErr := backend.enabled(ctx)
			if stateErr != nil {
				return FirewallManagedStatus{}, stateErr
			}
			if !on {
				if err := setFirewallBackendEnabled(ctx, backend, true); err != nil {
					return FirewallManagedStatus{}, err
				}
			}
			if err := s.syncManagedSafeLocked(ctx, backend, safetyPort); err != nil {
				return FirewallManagedStatus{}, err
			}
			// In particular, do not claim UFW was enabled merely because
			// the enable command exited with code zero.
			active, activeErr := backend.enabled(ctx)
			if activeErr != nil {
				return FirewallManagedStatus{}, activeErr
			}
			if !active {
				return FirewallManagedStatus{}, fmt.Errorf("%s remains inactive after enabling", backend.name)
			}
		}
		if backend.name == "ufw" {
			if err := syncUFWAdvancedRulesLocked(ctx, backend); err != nil {
				return FirewallManagedStatus{}, err
			}
		} else if backend.name == "firewalld" {
			advanced, err := loadAdvancedFirewallRules()
			if err != nil {
				return FirewallManagedStatus{}, err
			}
			for _, rule := range advanced {
				if err := applySystemAdvancedRule(ctx, backend, rule, true); err != nil {
					return FirewallManagedStatus{}, err
				}
			}
		}
		if err := setFirewallManagedEnabledPreference(true); err != nil {
			return FirewallManagedStatus{}, err
		}
	} else {
		if backend.name == "ufw" || backend.name == "firewalld" {
			// This switch intentionally controls the host firewall itself.
			// Never delete its existing rules or the administrator's policy.
			on, stateErr := backend.enabled(ctx)
			if stateErr != nil {
				return FirewallManagedStatus{}, stateErr
			}
			if on {
				if err := setFirewallBackendEnabled(ctx, backend, false); err != nil {
					return FirewallManagedStatus{}, err
				}
			}
			stillOn, stateErr := backend.enabled(ctx)
			if stateErr != nil {
				return FirewallManagedStatus{}, stateErr
			}
			if stillOn {
				return FirewallManagedStatus{}, fmt.Errorf("%s remains active after disabling", backend.name)
			}
		} else {
			// Native nftables/iptables are Firewall-UI-owned chains only.
			if err := disableManagedBackendSafe(ctx, backend); err != nil {
				return FirewallManagedStatus{}, err
			}
		}
		if err := setFirewallManagedEnabledPreference(false); err != nil {
			return FirewallManagedStatus{}, err
		}
	}
	if err := s.syncContainerProtectionLocked(ctx); err != nil {
		return FirewallManagedStatus{}, err
	}
	if err := s.reconcileManagedPingStateLocked(enabled); err != nil {
		return FirewallManagedStatus{}, err
	}
	return s.managedStatusSafeLocked(ctx, safetyPort)
}

func (s *FirewallService) SetManagedAutoSyncPreferenceSafe(ctx context.Context, enabled bool, safetyPort int) (FirewallManagedStatus, error) {
	firewallMu.Lock()
	defer firewallMu.Unlock()

	before, err := firewallAutoSync()
	if err != nil {
		return FirewallManagedStatus{}, err
	}
	var backend firewallBackend
	shouldSync := false
	if enabled {
		// Validate the backend before persisting the requested switch, so a
		// failed lookup cannot leave a misleading auto-sync preference.
		backend, err = detectManagedFirewallBackend(ctx)
		if err != nil {
			return FirewallManagedStatus{}, err
		}
		on, err := backend.enabled(ctx)
		if err != nil {
			return FirewallManagedStatus{}, err
		}
		desiredEnabled, configured, err := firewallManagedEnabledPreference()
		if err != nil {
			return FirewallManagedStatus{}, err
		}
		shouldSync = on && (!isManagedNativeFirewall(backend.name) || !configured || desiredEnabled)
	}
	if err := (&SettingService{}).setBool(firewallAutoSyncKey, enabled); err != nil {
		return FirewallManagedStatus{}, err
	}
	if shouldSync {
		if err := s.syncManagedSafeLocked(ctx, backend, safetyPort); err != nil {
			restoreErr := (&SettingService{}).setBool(firewallAutoSyncKey, before)
			if restoreErr == nil {
				recovery, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				restoreErr = s.syncManagedSafeLocked(recovery, backend, safetyPort)
			}
			return FirewallManagedStatus{}, errors.Join(err, restoreErr)
		}
	}
	return s.managedStatusSafeLocked(ctx, safetyPort)
}

func (s *FirewallService) SyncManagedSafe(ctx context.Context, safetyPort int) (FirewallManagedStatus, error) {
	firewallMu.Lock()
	defer firewallMu.Unlock()
	backend, err := detectManagedFirewallBackend(ctx)
	if err != nil {
		return FirewallManagedStatus{}, err
	}
	desiredEnabled, configured, err := firewallManagedEnabledPreference()
	if err != nil {
		return FirewallManagedStatus{}, err
	}
	if isManagedNativeFirewall(backend.name) && configured && !desiredEnabled {
		return s.managedStatusSafeLocked(ctx, safetyPort)
	}
	if err := s.syncManagedSafeLocked(ctx, backend, safetyPort); err != nil {
		return FirewallManagedStatus{}, err
	}
	return s.managedStatusSafeLocked(ctx, safetyPort)
}

func (s *FirewallService) AddManagedManualRuleSafe(ctx context.Context, port int, protocol, label string, safetyPort int) (FirewallManagedStatus, error) {
	return s.changeManagedManualRuleSafe(ctx, port, protocol, label, safetyPort, true)
}

func (s *FirewallService) DeleteManagedManualRuleSafe(ctx context.Context, port int, protocol string, safetyPort int) (FirewallManagedStatus, error) {
	return s.changeManagedManualRuleSafe(ctx, port, protocol, "", safetyPort, false)
}

func (s *FirewallService) changeManagedManualRuleSafe(ctx context.Context, port int, protocol, label string, safetyPort int, add bool) (FirewallManagedStatus, error) {
	firewallMu.Lock()
	defer firewallMu.Unlock()
	if port < 1 || port > 65535 {
		return FirewallManagedStatus{}, fmt.Errorf("%w: invalid port %d", ErrInvalidFirewallChange, port)
	}
	protocols, err := normalizeFirewallProtocols(protocol)
	if err != nil {
		return FirewallManagedStatus{}, fmt.Errorf("%w: %v", ErrInvalidFirewallChange, err)
	}
	manual, err := loadManualFirewallRules()
	if err != nil {
		return FirewallManagedStatus{}, err
	}
	labels, err := loadFirewallManualLabels()
	if err != nil {
		return FirewallManagedStatus{}, err
	}
	set := make(map[string]FirewallManualRule, len(manual)+2)
	for _, rule := range manual {
		set[firewallRuleKey(rule.Port, rule.Protocol)] = rule
	}
	label = normalizeFirewallLabelUnicode(label)
	for _, proto := range protocols {
		key := firewallRuleKey(port, proto)
		if add {
			set[key] = FirewallManualRule{Port: port, Protocol: proto}
			if label != "" {
				labels[key] = label
			} else {
				delete(labels, key)
			}
		} else {
			delete(set, key)
			delete(labels, key)
		}
	}
	// Keep a durable copy: manual[:0] would overwrite the original
	// backing array, preventing rollback after a failed host operation.
	beforeManual := append([]FirewallManualRule(nil), manual...)
	beforeLabels := cloneStringMap(labels)
	next := make([]FirewallManualRule, 0, len(set))
	for _, rule := range set {
		next = append(next, rule)
	}
	sort.Slice(next, func(i, j int) bool {
		return next[i].Port < next[j].Port || (next[i].Port == next[j].Port && next[i].Protocol < next[j].Protocol)
	})
	backend, err := detectManagedFirewallBackend(ctx)
	if err != nil {
		return FirewallManagedStatus{}, err
	}
	on, err := backend.enabled(ctx)
	if err != nil {
		return FirewallManagedStatus{}, err
	}
	desiredEnabled, configured, err := firewallManagedEnabledPreference()
	if err != nil {
		return FirewallManagedStatus{}, err
	}
	encode := func(rules []FirewallManualRule, labels map[string]string) (map[string]string, error) {
		rulesJSON, err := json.Marshal(rules)
		if err != nil {
			return nil, err
		}
		labelsJSON, err := json.Marshal(labels)
		if err != nil {
			return nil, err
		}
		return map[string]string{
			firewallManualRulesKey:  string(rulesJSON),
			firewallManualLabelsKey: string(labelsJSON),
		}, nil
	}
	changes, err := encode(next, labels)
	if err != nil {
		return FirewallManagedStatus{}, err
	}
	// Save rules and labels together. Previously a failure in the second
	// write left inconsistent state; a sync failure also left rules saved
	// that were never successfully applied to the host.
	if err := (&SettingService{}).setStrings(changes); err != nil {
		return FirewallManagedStatus{}, err
	}
	if on && (!isManagedNativeFirewall(backend.name) || !configured || desiredEnabled) {
		if err := s.syncManagedSafeLocked(ctx, backend, safetyPort); err != nil {
			previous, encodeErr := encode(beforeManual, beforeLabels)
			if encodeErr != nil {
				return FirewallManagedStatus{}, errors.Join(err, encodeErr)
			}
			restoreErr := (&SettingService{}).setStrings(previous)
			if restoreErr == nil {
				recovery, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				restoreErr = s.syncManagedSafeLocked(recovery, backend, safetyPort)
			}
			return FirewallManagedStatus{}, errors.Join(err, restoreErr)
		}
	}
	return s.managedStatusSafeLocked(ctx, safetyPort)
}
