package service

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestContainerRangesAndBindScope(t *testing.T) {
	row := containerPSRow{Ports: "192.0.2.10:8000-8002->9000-9002/tcp, [::1]:5353->53/udp"}
	ports := parseContainerPorts("docker", row)
	if len(ports) != 4 || ports[0].HostPort != 8000 || ports[2].ContainerPort != 9002 || !ports[0].Public || ports[3].Public {
		t.Fatalf("incorrect range or bind scope: %+v", ports)
	}
	for _, mapping := range []string{"0.0.0.0:80->0/tcp", "0.0.0.0:80->65536/tcp", "0.0.0.0:80-81->90/tcp", "0.0.0.0:81-80->90-91/tcp", "invalid:80->90/tcp", "0.0.0.0:80->90/invalid"} {
		if got := parseContainerPorts("docker", containerPSRow{Ports: mapping}); len(got) != 0 {
			t.Fatalf("accepted invalid mapping %q: %+v", mapping, got)
		}
	}
}

func TestProtocolOnlyNFTAndFirewalldPriority(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		rule := FirewallAdvancedRule{Action: "deny", Protocol: protocol, Priority: -10}
		if got := advancedNFTExpression(rule); got != "meta l4proto "+protocol+" drop" {
			t.Fatalf("invalid protocol-only NFT expression: %s", got)
		}
		if got := firewalldRichRule(rule); !strings.Contains(got, `priority="-10"`) {
			t.Fatalf("priority was lost: %s", got)
		}
	}
}

func TestAdvancedIDsAndExactUFWOwnership(t *testing.T) {
	for _, id := range []string{"bad\nID", "bad ID", strings.Repeat("a", 65)} {
		rule := FirewallAdvancedRule{ID: id, Action: "allow", Protocol: "tcp"}
		if err := validateAdvancedRule(&rule); err == nil {
			t.Fatalf("accepted unsafe ID %q", id)
		}
	}
	status := "[ 1] 443/tcp ALLOW IN Anywhere # Firewall-UI advanced abc-extra\n[ 2] 443/tcp ALLOW IN Anywhere # Firewall-UI advanced abc"
	if number := findUFWManagedRuleNumber(status, "Firewall-UI advanced abc", ""); number != 2 {
		t.Fatalf("selected another rule: %d", number)
	}
	if args := ownedUFWDeleteArgs("ufw allow 443/tcp comment 'Firewall-UI advanced my_rule'"); args == nil {
		t.Fatal("a valid rule ID cannot be cleaned up")
	}
}

func TestBackupRejectsInvalidRulesBeforeChangingState(t *testing.T) {
	old := statePath
	defer func() { statePath = old }()
	statePath = filepath.Join(t.TempDir(), "state.json")
	raw := []byte(`{"sentinel":"untouched"}`)
	if err := os.WriteFile(statePath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	base := FirewallAdvancedRule{ID: "one", Action: "allow", Protocol: "tcp", PortStart: 80}
	cases := []FirewallBackup{
		{Version: 1, ManualRules: []FirewallManualRule{{Port: 0, Protocol: "tcp"}}},
		{Version: 1, ManualRules: []FirewallManualRule{{Port: 80, Protocol: "any"}}},
		{Version: 1, ManualRules: []FirewallManualRule{{Port: 80, Protocol: "tcp"}, {Port: 80, Protocol: "tcp"}}},
		{Version: 1, AdvancedRules: []FirewallAdvancedRule{base, base}},
		{Version: 1, AdvancedRules: []FirewallAdvancedRule{{Action: "allow", Protocol: "tcp"}}},
		{Version: 1, AdvancedRules: []FirewallAdvancedRule{{ID: "close-port-80-tcp", Action: "allow", Protocol: "tcp", PortStart: 80}}},
	}
	for _, backup := range cases {
		if err := (&FirewallService{}).RestoreBackup(context.Background(), backup, 8088); err == nil {
			t.Fatalf("accepted invalid backup: %+v", backup)
		}
		got, err := os.ReadFile(statePath)
		if err != nil || string(got) != string(raw) {
			t.Fatalf("invalid backup changed state: %s, %v", got, err)
		}
	}
	if cases[3].AdvancedRules[0].PortEnd != 0 {
		t.Fatal("validation mutated the caller's backup")
	}
}

func TestNullSettingsAndLabels(t *testing.T) {
	old := statePath
	defer func() { statePath = old }()
	statePath = filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(statePath, []byte("null"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := (&SettingService{}).setBool("test", true); err == nil {
		t.Fatal("null settings were silently overwritten")
	}
	if err := os.WriteFile(statePath, []byte(`{"firewallManualRuleLabels":"null"}`), 0600); err != nil {
		t.Fatal(err)
	}
	labels, err := loadFirewallManualLabels()
	if err != nil || labels == nil {
		t.Fatalf("null label map cannot be edited: %v", err)
	}
	label := normalizeFirewallLabelUnicode(strings.Repeat("я", 59) + "€")
	if !utf8.ValidString(label) || len(label) > 120 {
		t.Fatal("label truncation broke UTF-8")
	}
}

func TestSubscribeAfterMonitorStopped(t *testing.T) {
	monitor := NewPortMonitor("/proc", time.Second)
	monitor.closeSubscribers()
	ch, cancel := monitor.Subscribe()
	defer cancel()
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("stopped monitor delivered a sample")
		}
	default:
		t.Fatal("subscription after shutdown was not closed")
	}
}

func TestDuplicateAdvancedIDDoesNotRemoveExistingRule(t *testing.T) {
	old := statePath
	defer func() { statePath = old }()
	statePath = filepath.Join(t.TempDir(), "state.json")
	existing := FirewallAdvancedRule{ID: "one", Action: "allow", Protocol: "tcp", PortStart: 80, PortEnd: 80}
	if err := saveFirewallJSON(firewallAdvancedRulesKey, []FirewallAdvancedRule{existing}); err != nil {
		t.Fatal(err)
	}
	if _, err := (&FirewallService{}).AddAdvancedRuleSafe(context.Background(), existing, 8088); err == nil {
		t.Fatal("accepted duplicate ID")
	}
	rules, err := loadAdvancedFirewallRules()
	if err != nil || len(rules) != 1 || rules[0] != existing {
		t.Fatalf("duplicate addition changed the original rule: %+v, %v", rules, err)
	}
}

func TestLargeContainerStatusRowIsNotDropped(t *testing.T) {
	dir := t.TempDir()
	row := containerPSRow{ID: "one", Names: "container", Ports: strings.Repeat(" ", 70*1024) + "0.0.0.0:443->443/tcp"}
	raw, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte("#!/bin/sh\nprintf '%s\n' '"+string(raw)+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	ports := ReadContainerPorts(context.Background())
	if len(ports) != 1 || ports[0].HostPort != 443 {
		t.Fatalf("large status row was dropped: %+v", ports)
	}
}
