package service

import (
	"context"
	"fmt"
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

func (s *FirewallService) RestoreBackup(ctx context.Context, backup FirewallBackup, safetyPort int) error {
	firewallMu.Lock()
	defer firewallMu.Unlock()
	if backup.Version != 1 {
		return fmt.Errorf("unsupported firewall backup version %d", backup.Version)
	}
	for i := range backup.AdvancedRules {
		if err := validateAdvancedRule(&backup.AdvancedRules[i]); err != nil {
			return fmt.Errorf("advanced rule %d: %w", i+1, err)
		}
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
		on, _ = backend.enabled(ctx)
	}
	if on && (backend.name == "ufw" || backend.name == "firewalld") {
		for _, rule := range currentAdvanced {
			_ = applyLegacyAdvancedRule(ctx, backend, rule, false)
		}
	}

	if err := saveFirewallJSON(firewallManualRulesKey, backup.ManualRules); err != nil {
		return err
	}
	if err := saveFirewallManualLabels(cloneStringMap(backup.ManualLabels)); err != nil {
		return err
	}
	sortAdvancedRules(backup.AdvancedRules)
	if err := saveFirewallJSON(firewallAdvancedRulesKey, backup.AdvancedRules); err != nil {
		return err
	}
	settings := &SettingService{}
	if err := settings.setBool(firewallAutoSyncKey, backup.AutoSync); err != nil {
		return err
	}
	if err := setFirewallManagedEnabledPreference(backup.ManagedEnabled); err != nil {
		return err
	}
	if err := writeFirewallPingEnabled(backup.PingEnabled); err != nil {
		return err
	}

	if backendErr != nil {
		return nil
	}
	if !backup.ManagedEnabled {
		return disableManagedBackendSafe(ctx, backend)
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
			if err := applyLegacyAdvancedRule(ctx, backend, rule, true); err != nil {
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
