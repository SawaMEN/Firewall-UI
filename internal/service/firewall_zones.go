package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/SawaMEN/Firewall-UI/internal/hostexec"
)

const firewalldZoneKey = "firewalldManagedZone"

type FirewalldZoneInfo struct {
	Name       string   `json:"name"`
	Interfaces []string `json:"interfaces"`
	Active     bool     `json:"active"`
}

type FirewalldZonesStatus struct {
	Supported bool                `json:"supported"`
	Selected  string              `json:"selected"`
	Default   string              `json:"default"`
	Zones     []FirewalldZoneInfo `json:"zones"`
	Message   string              `json:"message,omitempty"`
}

func configuredFirewalldZone() (string, error) {
	raw, err := firewallSetting(firewalldZoneKey, "")
	return strings.TrimSpace(raw), err
}

// parseFirewalldActiveZones handles the section format of firewall-cmd
// --get-active-zones. A zone may own multiple interfaces and/or source sets.
func parseFirewalldActiveZones(output string) map[string][]string {
	zones := make(map[string][]string)
	current := ""
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			current = strings.TrimSpace(line)
			zones[current] = []string{}
		} else if current != "" {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) > 1 && fields[0] == "interfaces:" {
				zones[current] = append(zones[current], fields[1:]...)
			}
		}
	}
	return zones
}

func (s *FirewallService) FirewalldZones(ctx context.Context) (FirewalldZonesStatus, error) {
	path, err := hostexec.LookPath("firewall-cmd")
	if err != nil {
		return FirewalldZonesStatus{Zones: []FirewalldZoneInfo{}, Message: "firewalld is not installed"}, nil
	}
	result := FirewalldZonesStatus{Supported: true, Zones: []FirewalldZoneInfo{}}
	defaultZone, err := runFirewallCommand(ctx, path, "--get-default-zone")
	if err != nil {
		return result, err
	}
	result.Default = strings.TrimSpace(defaultZone)
	result.Selected, err = configuredFirewalldZone()
	if err != nil {
		return result, err
	}
	if result.Selected == "" {
		result.Selected = result.Default
	}
	all, err := runFirewallCommand(ctx, path, "--get-zones")
	if err != nil {
		return result, err
	}
	activeText, err := runFirewallCommand(ctx, path, "--get-active-zones")
	if err != nil {
		return result, err
	}
	active := parseFirewalldActiveZones(activeText)
	for _, zone := range strings.Fields(all) {
		interfaces, ok := active[zone]
		result.Zones = append(result.Zones, FirewalldZoneInfo{Name: zone, Interfaces: interfaces, Active: ok})
	}
	sort.Slice(result.Zones, func(i, j int) bool { return result.Zones[i].Name < result.Zones[j].Name })
	return result, nil
}

// Requiring management to be disabled avoids an interval in which the same
// firewall-ui-owned rules could be left behind in the old zone. The user can
// reenable management in the selected zone using the existing safe toggle.
func (s *FirewallService) SetFirewalldZone(ctx context.Context, zone string) (FirewalldZonesStatus, error) {
	firewallMu.Lock()
	defer firewallMu.Unlock()
	backend, err := detectManagedFirewallBackend(ctx)
	if err != nil {
		return FirewalldZonesStatus{}, err
	}
	if backend.name != "firewalld" {
		return FirewalldZonesStatus{}, errors.New("firewalld must be the active firewall backend")
	}
	preferred, configured, err := firewallManagedEnabledPreference()
	if err != nil {
		return FirewalldZonesStatus{}, err
	}
	if !configured || preferred {
		return FirewalldZonesStatus{}, errors.New("disable Firewall-UI firewall management before changing firewalld zone")
	}
	selected := strings.TrimSpace(zone)
	status, err := s.FirewalldZones(ctx)
	if err != nil {
		return status, err
	}
	if selected == "auto" || selected == "" {
		selected = ""
	} else {
		found := false
		for _, item := range status.Zones {
			if item.Name == selected {
				found = true
				break
			}
		}
		if !found {
			return status, fmt.Errorf("unknown firewalld zone %q", selected)
		}
	}
	if err := (&SettingService{}).setString(firewalldZoneKey, selected); err != nil {
		return status, err
	}
	return s.FirewalldZones(ctx)
}
