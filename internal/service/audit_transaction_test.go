package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManualRulesRollbackAfterUFWFailure(t *testing.T) {
	root := t.TempDir()
	ufw := "#!/bin/sh\ncase \"$*\" in\n status) echo 'Status: active';;\n 'show added') :;;\n allow*) exit 31;;\nesac\n"
	if err := os.WriteFile(filepath.Join(root, "ufw"), []byte(ufw), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root)
	Configure(filepath.Join(root, "state.json"), 8088, 0)
	before := []FirewallManualRule{{Port: 8080, Protocol: "udp"}}
	if err := saveFirewallJSON(firewallManualRulesKey, before); err != nil {
		t.Fatal(err)
	}
	if err := saveFirewallManualLabels(map[string]string{firewallRuleKey(8080, "udp"): "existing"}); err != nil {
		t.Fatal(err)
	}
	if err := (&SettingService{}).setBool(firewallAutoSyncKey, false); err != nil {
		t.Fatal(err)
	}
	_, err := (&FirewallService{}).AddManagedManualRuleSafe(context.Background(), 1332, "udp", "new", 8088)
	if err == nil {
		t.Fatal("failed UFW command must not report success")
	}
	after, err := loadManualFirewallRules()
	if err != nil || len(after) != 1 || after[0] != before[0] {
		t.Fatalf("failed mutation overwrote existing manual rule: %v %v", after, err)
	}
	labels, err := loadFirewallManualLabels()
	if err != nil || len(labels) != 1 || labels[firewallRuleKey(8080, "udp")] != "existing" {
		t.Fatalf("failed mutation overwrote labels: %v %v", labels, err)
	}
}

func TestRestoreDisabledBackupActuallyStopsUFW(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "ufw-state")
	logPath := filepath.Join(root, "commands")
	if err := os.WriteFile(state, []byte("active\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AUDIT_UFW_STATE", state)
	t.Setenv("AUDIT_UFW_LOG", logPath)
	ufw := `#!/bin/sh
echo "$*" >> "$AUDIT_UFW_LOG"
case "$*" in
 status*)
   if /bin/grep -q active "$AUDIT_UFW_STATE"; then echo 'Status: active'; else echo 'Status: inactive'; fi;;
 'show added') echo "ufw allow 9000/tcp comment 'administrator'";;
 disable) echo inactive > "$AUDIT_UFW_STATE";;
esac
`
	if err := os.WriteFile(filepath.Join(root, "ufw"), []byte(ufw), 0755); err != nil {
		t.Fatal(err)
	}
	pingFile := filepath.Join(root, "ping")
	if err := os.WriteFile(pingFile, []byte("0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	oldPaths := firewallPingSysctlPaths
	firewallPingSysctlPaths = []string{pingFile}
	t.Cleanup(func() { firewallPingSysctlPaths = oldPaths })
	t.Setenv("PATH", root)
	Configure(filepath.Join(root, "state.json"), 8088, 0)
	backup := FirewallBackup{Version: 1, ManagedEnabled: false, PingEnabled: true}
	if err := (&FirewallService{}).RestoreBackup(context.Background(), backup, 8088); err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(state)
	if err != nil || strings.TrimSpace(string(current)) != "inactive" {
		t.Fatalf("UFW not switched off by disabled backup: %s, %v", current, err)
	}
	commands, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(commands), "disable\n") || strings.Contains(string(commands), "delete") {
		t.Fatalf("restore failed to disable host UFW safely: %s", commands)
	}
}

func TestBackupRecordsActualUFWStateInsteadOfStalePreference(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "ufw-state")
	if err := os.WriteFile(state, []byte("active\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AUDIT_UFW_STATE", state)
	ufw := `#!/bin/sh
case "$*" in
 status)
   if /bin/grep -q active "$AUDIT_UFW_STATE"; then echo 'Status: active'; else echo 'Status: inactive'; fi;;
esac
`
	if err := os.WriteFile(filepath.Join(root, "ufw"), []byte(ufw), 0755); err != nil {
		t.Fatal(err)
	}
	pingFile := filepath.Join(root, "ping")
	if err := os.WriteFile(pingFile, []byte("0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	previousPaths := firewallPingSysctlPaths
	firewallPingSysctlPaths = []string{pingFile}
	t.Cleanup(func() { firewallPingSysctlPaths = previousPaths })
	t.Setenv("PATH", root)
	Configure(filepath.Join(root, "state.json"), 8088, 0)
	if err := setFirewallManagedEnabledPreference(false); err != nil {
		t.Fatal(err)
	}
	backup, err := (&FirewallService{}).ExportBackup()
	if err != nil {
		t.Fatal(err)
	}
	if !backup.ManagedEnabled {
		t.Fatal("UFW active but backup captured disabled legacy preference")
	}
	if err := os.WriteFile(state, []byte("inactive\n"), 0600); err != nil {
		t.Fatal(err)
	}
	backup, err = (&FirewallService{}).ExportBackup()
	if err != nil {
		t.Fatal(err)
	}
	if backup.ManagedEnabled {
		t.Fatal("UFW inactive but backup captured enabled")
	}
}
