package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type FirewallBackup struct {
	Version        int                    `json:"version"`
	CreatedAt      time.Time              `json:"createdAt"`
	AutoSync       bool                   `json:"autoSync"`
	ManagedEnabled bool                   `json:"managedEnabled"`
	PingEnabled    bool                   `json:"pingEnabled"`
	ManualRules    []FirewallManualRule   `json:"manualRules"`
	ManualLabels   map[string]string      `json:"manualLabels,omitempty"`
	AdvancedRules  []FirewallAdvancedRule `json:"advancedRules"`
}

func (s *FirewallService) ExportBackup() (FirewallBackup, error) {
	firewallMu.Lock()
	defer firewallMu.Unlock()
	return exportFirewallBackupLocked()
}

func exportFirewallBackupLocked() (FirewallBackup, error) {
	auto, err := firewallAutoSync()
	if err != nil {
		return FirewallBackup{}, err
	}
	enabled, configured, err := firewallManagedEnabledPreference()
	if err != nil {
		return FirewallBackup{}, err
	}
	if !configured {
		enabled = false
	}
	ping, err := (&FirewallService{}).ManagedPingEnabled()
	if err != nil {
		return FirewallBackup{}, err
	}
	manual, err := loadManualFirewallRules()
	if err != nil {
		return FirewallBackup{}, err
	}
	labels, err := loadFirewallManualLabels()
	if err != nil {
		return FirewallBackup{}, err
	}
	advanced, err := loadAdvancedFirewallRules()
	if err != nil {
		return FirewallBackup{}, err
	}
	return FirewallBackup{
		Version:        1,
		CreatedAt:      time.Now().UTC(),
		AutoSync:       auto,
		ManagedEnabled: enabled,
		PingEnabled:    ping,
		ManualRules:    append([]FirewallManualRule(nil), manual...),
		ManualLabels:   cloneStringMap(labels),
		AdvancedRules:  append([]FirewallAdvancedRule(nil), advanced...),
	}, nil
}

func ValidateFirewallBackup(backup FirewallBackup) error {
	_, err := validatedFirewallBackup(backup)
	return err
}

func validatedFirewallBackup(backup FirewallBackup) (FirewallBackup, error) {
	if backup.Version != 1 {
		return FirewallBackup{}, fmt.Errorf("unsupported firewall backup version %d", backup.Version)
	}
	// Validate a private copy before touching either saved state or live rules.
	backup.ManualRules = append([]FirewallManualRule(nil), backup.ManualRules...)
	backup.AdvancedRules = append([]FirewallAdvancedRule(nil), backup.AdvancedRules...)
	if err := validateManualFirewallRules(backup.ManualRules); err != nil {
		return FirewallBackup{}, err
	}
	ids := make(map[string]bool, len(backup.AdvancedRules))
	for i := range backup.AdvancedRules {
		if err := validateAdvancedRule(&backup.AdvancedRules[i]); err != nil {
			return FirewallBackup{}, fmt.Errorf("advanced rule %d: %w", i+1, err)
		}
		rule := &backup.AdvancedRules[i]
		if rule.ID == "" || ids[rule.ID] {
			return FirewallBackup{}, fmt.Errorf("advanced rule %d: missing or duplicate ID", i+1)
		}
		if strings.HasPrefix(rule.ID, "close-port-") && !isClosePortRule(*rule) {
			return FirewallBackup{}, fmt.Errorf("advanced rule %d: invalid reserved port rule", i+1)
		}
		ids[rule.ID] = true
	}
	return backup, nil
}

func (s *FirewallService) RestoreBackup(ctx context.Context, backup FirewallBackup, safetyPort int) error {
	firewallMu.Lock()
	defer firewallMu.Unlock()
	var err error
	backup, err = validatedFirewallBackup(backup)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidFirewallChange, err)
	}
	currentAdvanced, err := loadAdvancedFirewallRules()
	if err != nil {
		return err
	}
	backend, backendErr := detectManagedFirewallBackend(ctx)
	if backendErr != nil && backup.ManagedEnabled {
		return backendErr
	}
	on := false
	if backendErr == nil {
		on, err = backend.enabled(ctx)
		if err != nil {
			return err
		}
	}
	if on && (backend.name == "ufw" || backend.name == "firewalld") {
		for _, rule := range currentAdvanced {
			if err := applySystemAdvancedRule(ctx, backend, rule, false); err != nil {
				return err
			}
		}
	}

	sortAdvancedRules(backup.AdvancedRules)
	changes := map[string]string{
		firewallAutoSyncKey:       strconv.FormatBool(backup.AutoSync),
		firewallManagedEnabledKey: strconv.FormatBool(backup.ManagedEnabled),
		firewallPingEnabledKey:    strconv.FormatBool(backup.PingEnabled),
	}
	for key, value := range map[string]any{
		firewallManualRulesKey:   backup.ManualRules,
		firewallManualLabelsKey:  cloneStringMap(backup.ManualLabels),
		firewallAdvancedRulesKey: backup.AdvancedRules,
	} {
		raw, err := json.Marshal(value)
		if err != nil {
			return err
		}
		changes[key] = string(raw)
	}
	if err := (&SettingService{}).setStrings(changes); err != nil {
		return err
	}

	if backendErr != nil {
		return nil
	}
	if !backup.ManagedEnabled {
		if err := disableManagedBackendSafe(ctx, backend); err != nil {
			return err
		}
		return s.reconcileManagedPingStateLocked(false)
	}
	if (backend.name == "ufw" || backend.name == "firewalld") && !on {
		if err := setFirewallBackendEnabled(ctx, backend, true); err != nil {
			return err
		}
	}
	if err := s.syncManagedSafeLocked(ctx, backend, safetyPort); err != nil {
		return err
	}
	if backend.name == "ufw" || backend.name == "firewalld" {
		for _, rule := range backup.AdvancedRules {
			if err := applySystemAdvancedRule(ctx, backend, rule, true); err != nil {
				return err
			}
		}
	}
	return s.reconcileManagedPingStateLocked(true)
}

func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
