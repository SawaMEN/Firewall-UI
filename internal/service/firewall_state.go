package service

import (
	"errors"
	"os"
	"strconv"
	"strings"
)

const firewallManagedEnabledKey = "firewallManagedEnabled"

func firewallManagedEnabledPreference() (enabled, configured bool, err error) {
	setting, err := (&SettingService{}).getSetting(firewallManagedEnabledKey)
	if errors.Is(err, os.ErrNotExist) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	raw := strings.TrimSpace(setting.Value)
	if raw == "" {
		return false, true, nil
	}
	enabled, err = strconv.ParseBool(raw)
	return enabled, true, err
}

func setFirewallManagedEnabledPreference(enabled bool) error {
	return (&SettingService{}).setBool(firewallManagedEnabledKey, enabled)
}

func isManagedNativeFirewall(backend string) bool {
	return backend == "nftables" || backend == "iptables"
}

func shouldRestoreManagedNativeFirewall(backend string, active, desired bool) bool {
	return isManagedNativeFirewall(backend) && !active && desired
}
