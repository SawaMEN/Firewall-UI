package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func auditCommand(t *testing.T, name, script string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNFTReplacementUsesOneAtomicBatch(t *testing.T) {
	root := t.TempDir()
	Configure(filepath.Join(root, "state.json"), 8088, 0)
	logPath, batchPath := filepath.Join(root, "commands"), filepath.Join(root, "batch")
	t.Setenv("AUDIT_COMMAND_LOG", logPath)
	t.Setenv("AUDIT_BATCH", batchPath)
	binary := auditCommand(t, "nft", `printf '%s\n' "$*" >> "$AUDIT_COMMAND_LOG"
case "$*" in
 '-j list ruleset') echo '{"nftables":[]}';;
 'list tables') echo 'table inet firewall_ui';;
 '-f -') /bin/cat > "$AUDIT_BATCH"; echo 'rejected batch' >&2; exit 2;;
esac
`)
	err := applyManagedNftables(context.Background(), binary, []FirewallRule{{Port: 8088, Protocol: "tcp", Source: "panel"}})
	if err == nil {
		t.Fatal("failed batch reported success")
	}
	commands, _ := os.ReadFile(logPath)
	batch, _ := os.ReadFile(batchPath)
	if strings.Contains(string(commands), "delete table") || !strings.HasPrefix(string(batch), "delete table inet firewall_ui\n") || !strings.Contains(string(batch), "meta l4proto ipv6-icmp accept") {
		t.Fatalf("non-atomic replacement: %s; %s", commands, batch)
	}
}

func TestNFTDisableReportsDeletionFailure(t *testing.T) {
	binary := auditCommand(t, "nft", `case "$*" in
 'list tables') echo 'table inet firewall_ui';;
 'delete table inet firewall_ui') echo denied >&2; exit 2;;
esac
`)
	if err := disableManagedBackend(context.Background(), firewallBackend{name: "nftables", binary: binary}); err == nil {
		t.Fatal("deletion failure ignored")
	}
}

func TestIPTablesCheckDoesNotHideOperationalErrors(t *testing.T) {
	for _, code := range []string{"1", "2", "3"} {
		binary := auditCommand(t, "iptables", "exit "+code+"\n")
		exists, err := managedIPTablesJumpExists(context.Background(), binary)
		if exists || (err == nil) != (code == "1") {
			t.Fatalf("exit %s: exists=%v err=%v", code, exists, err)
		}
	}
}

func TestIPTablesRemovalReportsJumpDeleteFailure(t *testing.T) {
	binary := auditCommand(t, "iptables", `case "$*" in
 '-S') echo '-N FIREWALL-UI';;
 '-C INPUT -j FIREWALL-UI') exit 0;;
 '-D INPUT -j FIREWALL-UI') echo denied >&2; exit 2;;
esac
`)
	t.Setenv("PATH", filepath.Dir(binary))
	if err := removeManagedIPTables(context.Background(), binary); err == nil {
		t.Fatal("failed deletion ignored")
	}
}

func TestStoredAdvancedRulesRejectDuplicateAndReservedIDs(t *testing.T) {
	Configure(filepath.Join(t.TempDir(), "state.json"), 8088, 0)
	allow := FirewallAdvancedRule{ID: "one", Action: "allow", Protocol: "tcp", PortStart: 9000}
	badClose := FirewallAdvancedRule{ID: "close-port-9000-tcp", Action: "deny", Protocol: "tcp", PortStart: 9000, PortEnd: 9000, IPVersion: "any", Priority: 100}
	for _, rules := range [][]FirewallAdvancedRule{{allow, allow}, {badClose}, {{Action: "allow", Protocol: "tcp"}}} {
		if err := saveFirewallJSON(firewallAdvancedRulesKey, rules); err != nil {
			t.Fatal(err)
		}
		if _, err := loadAdvancedFirewallRules(); err == nil {
			t.Fatalf("accepted ambiguous rules %+v", rules)
		}
	}
}

func TestStatusDoesNotClaimStoppedUFWIsEnabled(t *testing.T) {
	binary := auditCommand(t, "ufw", `case "$*" in
 status) echo 'Status: inactive';;
 'show added') echo '';;
esac
`)
	t.Setenv("PATH", filepath.Dir(binary))
	Configure(filepath.Join(t.TempDir(), "state.json"), 8088, 0)
	if err := setFirewallManagedEnabledPreference(true); err != nil {
		t.Fatal(err)
	}
	if err := (&SettingService{}).setBool(firewallAutoSyncKey, false); err != nil {
		t.Fatal(err)
	}
	status, err := (&FirewallService{}).GetManagedStatusSafe(context.Background(), 8088)
	if err != nil || status.Enabled {
		t.Fatalf("stopped UFW shown active: %+v %v", status, err)
	}
}

func TestDesiredRulesReuseFreshMonitorAndKeepAllOwners(t *testing.T) {
	Configure(filepath.Join(t.TempDir(), "state.json"), 8088, 0)
	t.Setenv("PATH", t.TempDir())
	monitor := NewPortMonitor("/unreadable-proc", time.Second)
	monitor.publish(PortSnapshot{UpdatedAt: time.Now(), Ports: []Port{
		{Port: 51234, Protocol: "tcp", Listening: true, Processes: []Process{{PID: 1, Name: "first"}}},
		{Port: 51234, Protocol: "tcp", Listening: true, Processes: []Process{{PID: 2, Name: "second"}}},
	}}, [32]byte{})
	rules, err := (&FirewallService{PortMonitor: monitor}).desiredRules(true, 8088)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range rules {
		if rule.Port == 51234 {
			if rule.Label != "first, second" {
				t.Fatalf("lost owners: %+v", rule)
			}
			return
		}
	}
	t.Fatal("fresh monitored listener missing")
}

func TestBackupRemovalFailureDoesNotReplaceSavedSettings(t *testing.T) {
	binary := auditCommand(t, "ufw", `case "$*" in
 status) echo 'Status: active';;
 'status numbered') echo denied >&2; exit 2;;
esac
`)
	t.Setenv("PATH", filepath.Dir(binary))
	Configure(filepath.Join(t.TempDir(), "state.json"), 8088, 0)
	if err := saveFirewallJSON(firewallAdvancedRulesKey, []FirewallAdvancedRule{{ID: "old", Action: "deny", Protocol: "tcp", PortStart: 9000}}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(statePath)
	err := (&FirewallService{}).RestoreBackup(context.Background(), FirewallBackup{Version: 1, ManagedEnabled: true, PingEnabled: true}, 8088)
	after, _ := os.ReadFile(statePath)
	if err == nil || string(before) != string(after) {
		t.Fatalf("failed removal replaced backup state: %v %s", err, after)
	}
}

func TestPartialSyncRetainsOwnershipForRecovery(t *testing.T) {
	Configure(filepath.Join(t.TempDir(), "state.json"), 8088, 0)
	if err := (&SettingService{}).setBool(firewallAutoSyncKey, false); err != nil {
		t.Fatal(err)
	}
	if err := saveFirewallJSON(firewallManualRulesKey, []FirewallManualRule{{Port: 9000, Protocol: "tcp"}}); err != nil {
		t.Fatal(err)
	}
	binary := auditCommand(t, "ufw", `case "$*" in
 'show added') echo '';;
 'allow 9000/tcp comment Firewall-UI managed') echo 'add failed' >&2; exit 2;;
 allow*) exit 0;;
 esac
 `)
	if err := (&FirewallService{}).syncManagedLocked(context.Background(), firewallBackend{name: "ufw", binary: binary}, 8088); err == nil {
		t.Fatal("failed sync succeeded")
	}
	ledger, err := loadManagedFirewallRules()
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range ledger {
		if rule.Port == 8088 && rule.Owned {
			return
		}
	}
	t.Fatalf("orphaned rule: %+v", ledger)
}

func TestContainerRuntimeRequestsPresentationFields(t *testing.T) {
	binary := auditCommand(t, "podman", `case "$3" in
 *'{{json .Names}}'*'{{json .Ports}}'*) echo '{"ID":"fixture","Names":"web","Image":"nginx","Ports":"0.0.0.0:9000->80/tcp"}';;
 *) echo '{"ID":"fixture","Names":["web"],"Ports":[]}';;
 esac
 `)
	t.Setenv("PATH", filepath.Dir(binary))
	ports := ReadContainerPorts(context.Background())
	if len(ports) != 1 || ports[0].Runtime != "podman" || ports[0].HostPort != 9000 {
		t.Fatalf("Podman port lost: %+v", ports)
	}
}

func TestFirewalldPartialAllowCleansPermanentRule(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "commands")
	t.Setenv("AUDIT_COMMAND_LOG", logPath)
	binary := auditCommand(t, "firewall-cmd", `printf '%s\n' "$*" >> "$AUDIT_COMMAND_LOG"
 case "$*" in
 '--state') echo running;;
 '--zone=public --add-port=9000/tcp') echo failure >&2; exit 2;;
 esac
 `)
	err := addFirewallRule(context.Background(), firewallBackend{name: "firewalld", binary: binary, zone: "public", enabled: func(context.Context) (bool, error) { return true, nil }}, FirewallRule{Port: 9000, Protocol: "tcp"})
	log, _ := os.ReadFile(logPath)
	if err == nil || !strings.Contains(string(log), "--permanent --zone=public --remove-port=9000/tcp") {
		t.Fatalf("orphaned permanent port: %v %s", err, log)
	}
}
