package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestAppendObservedFirewallAllowsKeepsExternalRulesSeparate(t *testing.T) {
	expected := FirewallRule{Port: 8088, Protocol: "tcp", Source: "panel", Label: "Panel", Owned: true, Exists: true}
	observed := map[string]bool{
		"8088/tcp":      true,
		"1332/tcp":      true,
		"1332/udp":      true,
		"2000-2010/tcp": true,
		"4444/tcp":      false,
		"invalid/tcp":   true,
	}
	result := appendObservedFirewallAllows([]FirewallRule{expected}, observed, true)
	if len(result) != 4 {
		t.Fatalf("expected one managed and three external rows, got %+v", result)
	}
	for _, rule := range result {
		if rule.Port == 8088 {
			if rule.Source != "panel" || !rule.Owned {
				t.Fatalf("managed rule lost its identity: %+v", rule)
			}
			continue
		}
		if rule.Source != "external" || rule.Owned || !rule.Exists {
			t.Fatalf("external rule was claimed as managed: %+v", rule)
		}
		if rule.Port == 0 && rule.PortRange != "2000-2010" {
			t.Fatalf("unexpected ranged rule: %+v", rule)
		}
	}
	if result[0].Port != 1332 || result[1].Port != 1332 ||
		result[2].PortRange != "2000-2010" || result[3].Port != 8088 {
		t.Fatalf("observed rules did not sort by port: %+v", result)
	}
	if len(appendObservedFirewallAllows([]FirewallRule{expected}, observed, false)) != 1 {
		t.Fatal("disabled firewall must not list persisted ALLOW as live")
	}
}

func TestAppendObservedFirewallAllowsDoesNotMutateDesiredOrAdoptExternal(t *testing.T) {
	expected := []FirewallRule{{Port: 1332, Protocol: "udp", Source: "manual", Exists: false}}
	observed := map[string]bool{"1332/udp": true, "5000/tcp": true}
	result := appendObservedFirewallAllows(expected, observed, true)
	if len(result) != 2 || result[0].Source != "manual" || result[1].Source != "external" {
		t.Fatalf("lost expected source or duplicated a port: %+v", result)
	}
	if expected[0].Exists || len(expected) != 1 {
		t.Fatal("merged status mutated the desired policy")
	}
}

func TestManagedStatusReadsExternalUFWChanges(t *testing.T) {
	root := t.TempDir()
	script := `#!/bin/sh
case "$*" in
	status) echo 'Status: active';;
	'status verbose')
		echo 'Status: active'
		echo 'Default: deny (incoming), allow (outgoing), disabled (routed)';;
	'show added')
		echo "ufw allow 8088/tcp comment 'Firewall-UI managed'"
		echo "ufw allow 9234/udp comment 'external administrator'"
		echo "ufw allow from 10.0.0.0/8 to any port 9999 proto tcp";;
esac
`
	if err := os.WriteFile(filepath.Join(root, "ufw"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root)
	Configure(filepath.Join(root, "state.json"), 8088, 0)
	if err := (&SettingService{}).setBool(firewallAutoSyncKey, false); err != nil {
		t.Fatal(err)
	}
	status, err := (&FirewallService{}).GetManagedStatusSafe(context.Background(), 8088)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Enabled || status.Backend != "ufw" {
		t.Fatalf("unexpected firewall backend: %+v", status)
	}
	hasExternal, hasRestricted, panelCount := false, false, 0
	for _, rule := range status.Rules {
		if rule.Port == 9234 && rule.Protocol == "udp" && rule.Source == "external" && rule.Exists && !rule.Owned {
			hasExternal = true
		}
		if rule.Port == 9999 {
			hasRestricted = true
		}
		if rule.Port == 8088 && rule.Protocol == "tcp" {
			panelCount++
		}
	}
	if !hasExternal || hasRestricted || panelCount != 1 {
		t.Fatalf("host firewall changes were not correctly observed: %+v", status.Rules)
	}
}
