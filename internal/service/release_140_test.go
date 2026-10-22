package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBackupSyncIntervalRoundTripAndLegacyCompatibility(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PATH", root)
	if err := os.WriteFile(filepath.Join(root, "ufw"), []byte("#!/bin/sh\ncase \"$*\" in\n status*) echo 'Status: inactive';;\n 'show added') :;;\nesac\n"), 0755); err != nil {
		t.Fatal(err)
	}
	ping := filepath.Join(root, "ping")
	if err := os.WriteFile(ping, []byte("0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	beforePaths := firewallPingSysctlPaths
	firewallPingSysctlPaths = []string{ping}
	t.Cleanup(func() { firewallPingSysctlPaths = beforePaths })
	Configure(filepath.Join(root, "state.json"), 8088, 0)
	svc := &FirewallService{}
	if err := svc.SetSyncIntervalSeconds(300); err != nil {
		t.Fatal(err)
	}
	backup, err := svc.ExportBackup()
	if err != nil {
		t.Fatal(err)
	}
	if backup.SyncIntervalSeconds == nil || *backup.SyncIntervalSeconds != 300 {
		t.Fatalf("interval missing from backup: %+v", backup)
	}
	if err := svc.SetSyncIntervalSeconds(30); err != nil {
		t.Fatal(err)
	}
	if err := svc.RestoreBackup(context.Background(), backup, 8088); err != nil {
		t.Fatal(err)
	}
	if got, err := svc.SyncIntervalSeconds(); err != nil || got != 300 {
		t.Fatalf("restored interval %d: %v", got, err)
	}
	backup.SyncIntervalSeconds = nil
	if err := svc.RestoreBackup(context.Background(), backup, 8088); err != nil {
		t.Fatal(err)
	}
	if got, err := svc.SyncIntervalSeconds(); err != nil || got != 300 {
		t.Fatalf("legacy backup changed interval: %d %v", got, err)
	}
	invalid := 1
	backup.SyncIntervalSeconds = &invalid
	if err := svc.RestoreBackup(context.Background(), backup, 8088); err == nil {
		t.Fatal("invalid interval accepted")
	}
	if got, _ := svc.SyncIntervalSeconds(); got != 300 {
		t.Fatal("invalid restore changed saved interval")
	}
}

func TestRestoreCannotSwitchLiveFirewalldZoneWithStalePreference(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PATH", root)
	logPath := filepath.Join(root, "commands")
	t.Setenv("RELEASE_TEST_LOG", logPath)
	script := `#!/bin/sh
echo "$*" >> "$RELEASE_TEST_LOG"
case "$*" in
 --state) echo running;;
 --get-default-zone) echo public;;
esac
`
	if err := os.WriteFile(filepath.Join(root, "firewall-cmd"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	Configure(filepath.Join(root, "state.json"), 8088, 0)
	if err := setFirewallManagedEnabledPreference(false); err != nil {
		t.Fatal(err)
	}
	if err := (&SettingService{}).setString(firewalldZoneKey, "public"); err != nil {
		t.Fatal(err)
	}
	err := (&FirewallService{}).RestoreBackup(context.Background(), FirewallBackup{Version: 1, Zone: "trusted"}, 8088)
	if err == nil || !strings.Contains(err.Error(), "stop firewalld") {
		t.Fatalf("live zone switch accepted: %v", err)
	}
	if zone, _ := configuredFirewalldZone(); zone != "public" {
		t.Fatalf("zone changed: %s", zone)
	}
	commands, _ := os.ReadFile(logPath)
	if strings.Contains(string(commands), "--remove") {
		t.Fatalf("rejected restore mutated live rules: %s", commands)
	}
}
