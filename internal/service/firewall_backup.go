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
	Version             int                    `json:"version"`
	CreatedAt           time.Time              `json:"createdAt"`
	SyncIntervalSeconds *int                   `json:"syncIntervalSeconds,omitempty"`
	AutoSync            bool                   `json:"autoSync"`
	ManagedEnabled      bool                   `json:"managedEnabled"`
	PingEnabled         bool                   `json:"pingEnabled"`
	ContainerProtection bool                   `json:"containerProtection"`
	Zone                string                 `json:"zone,omitempty"`
	ManualRules         []FirewallManualRule   `json:"manualRules"`
	ManualLabels        map[string]string      `json:"manualLabels,omitempty"`
	AdvancedRules       []FirewallAdvancedRule `json:"advancedRules"`
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
	// UFW/firewalld can be enabled or disabled outside the panel. A backup
	// is used for rollback, so saving the old preference instead of live
	// state can unexpectedly disable an active host firewall on recovery.
	probe, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if backend, detectErr := detectManagedFirewallBackend(probe); detectErr == nil &&
		(backend.name == "ufw" || backend.name == "firewalld") {
		enabled, err = backend.enabled(probe)
		if err != nil {
			return FirewallBackup{}, fmt.Errorf("read live %s state for backup: %w", backend.name, err)
		}
	} else if !configured {
		enabled = false
	}
	ping, err := (&FirewallService{}).ManagedPingEnabled()
	if err != nil {
		return FirewallBackup{}, err
	}
	containerProtection, err := containerProtectionEnabled()
	if err != nil {
		return FirewallBackup{}, err
	}
	zone, err := configuredFirewalldZone()
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
	interval, err := (&FirewallService{}).SyncIntervalSeconds()
	if err != nil {
		return FirewallBackup{}, err
	}
	return FirewallBackup{
		SyncIntervalSeconds: &interval,
		Version:             1,
		CreatedAt:           time.Now().UTC(),
		AutoSync:            auto,
		ManagedEnabled:      enabled,
		PingEnabled:         ping,
		ContainerProtection: containerProtection,
		Zone:                zone,
		ManualRules:         append([]FirewallManualRule(nil), manual...),
		ManualLabels:        cloneStringMap(labels),
		AdvancedRules:       append([]FirewallAdvancedRule(nil), advanced...),
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
	if backup.SyncIntervalSeconds != nil {
		if err := ValidateFirewallSyncInterval(*backup.SyncIntervalSeconds); err != nil {
			return FirewallBackup{}, err
		}
	}
	if backup.Zone != "" && !interfacePattern.MatchString(backup.Zone) {
		return FirewallBackup{}, fmt.Errorf("invalid firewalld zone %q", backup.Zone)
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
	oldZone, err := configuredFirewalldZone()
	if err != nil {
		return err
	}
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
	if backendErr == nil && backend.name == "firewalld" && on && backup.Zone != oldZone {
		return fmt.Errorf("%w: stop firewalld before restoring a different zone", ErrInvalidFirewallChange)
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
		containerProtectionKey:    strconv.FormatBool(backup.ContainerProtection),
		firewalldZoneKey:          backup.Zone,
	}
	// Old backups omit the interval and preserve the current preference.
	if backup.SyncIntervalSeconds != nil {
		changes[firewallSyncIntervalKey] = strconv.Itoa(*backup.SyncIntervalSeconds)
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
		return s.syncContainerProtectionLocked(ctx)
	}
	// Select the restored zone before recreating its owned rules.
	backend, backendErr = detectManagedFirewallBackend(ctx)
	if backendErr != nil {
		return backendErr
	}
	if !backup.ManagedEnabled {
		// The main switch now represents the host firewall itself. A backup
		// with the switch off must not leave UFW/firewalld running while only
		// removing Firewall-UI's rules (and must preserve administrator rules).
		if backend.name == "ufw" || backend.name == "firewalld" {
			if on {
				if err := setFirewallBackendEnabled(ctx, backend, false); err != nil {
					return err
				}
			}
			active, err := backend.enabled(ctx)
			if err != nil {
				return err
			}
			if active {
				return fmt.Errorf("%s remains active after restoring disabled firewall", backend.name)
			}
		} else if err := disableManagedBackendSafe(ctx, backend); err != nil {
			return err
		}
		if err := s.reconcileManagedPingStateLocked(false); err != nil {
			return err
		}
		return s.syncContainerProtectionLocked(ctx)
	}
	if (backend.name == "ufw" || backend.name == "firewalld") && !on {
		if err := setFirewallBackendEnabled(ctx, backend, true); err != nil {
			return err
		}
	}
	if err := s.syncManagedSafeLocked(ctx, backend, safetyPort); err != nil {
		return err
	}
	if backend.name == "ufw" {
		// Reconcile rather than blindly adding duplicates every time an
		// existing backup is restored.
		if err := syncUFWAdvancedRulesLocked(ctx, backend); err != nil {
			return err
		}
	} else if backend.name == "firewalld" {
		for _, rule := range backup.AdvancedRules {
			if err := applySystemAdvancedRule(ctx, backend, rule, true); err != nil {
				return err
			}
		}
	}
	if err := s.reconcileManagedPingStateLocked(true); err != nil {
		return err
	}
	return s.syncContainerProtectionLocked(ctx)
}

func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
