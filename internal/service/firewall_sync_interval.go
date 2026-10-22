package service

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

const firewallSyncIntervalKey = "firewallSyncIntervalSeconds"
const defaultFirewallSyncIntervalSeconds = 60

// An intentionally bounded interval keeps automatic reconciliation responsive
// without allowing repeated expensive host command invocations every second.
func ValidateFirewallSyncInterval(seconds int) error {
	switch seconds {
	case 30, 60, 120, 300, 600:
		return nil
	default:
		return fmt.Errorf("%w: sync interval must be 30, 60, 120, 300 or 600 seconds", ErrInvalidFirewallChange)
	}
}

func (s *FirewallService) SyncIntervalSeconds() (int, error) {
	raw, err := firewallSetting(firewallSyncIntervalKey, strconv.Itoa(defaultFirewallSyncIntervalSeconds))
	if err != nil {
		return 0, err
	}
	seconds, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("invalid saved firewall sync interval: %w", err)
	}
	if err := ValidateFirewallSyncInterval(seconds); err != nil {
		return 0, err
	}
	return seconds, nil
}

func (s *FirewallService) SetSyncIntervalSeconds(seconds int) error {
	if err := ValidateFirewallSyncInterval(seconds); err != nil {
		return err
	}
	return (&SettingService{}).setInt(firewallSyncIntervalKey, seconds)
}

func (s *FirewallService) syncInterval() time.Duration {
	seconds, err := s.SyncIntervalSeconds()
	if err != nil {
		return defaultFirewallSyncIntervalSeconds * time.Second
	}
	return time.Duration(seconds) * time.Second
}
