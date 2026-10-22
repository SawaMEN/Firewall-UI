package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUFWStatusDistinguishesHostFromManagedRules(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "ufw")
	script := `#!/bin/sh
case "$*" in
  status) echo 'Status: active';;
  'status verbose')
    echo 'Status: active'
    echo 'Default: allow (incoming), deny (outgoing), disabled (routed)';;
  'show added') echo '';;
esac
`
	if err := os.WriteFile(binary, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root)
	Configure(filepath.Join(root, "state.json"), 8088, 0)
	if err := setFirewallManagedEnabledPreference(false); err != nil {
		t.Fatal(err)
	}
	if err := (&SettingService{}).setBool(firewallAutoSyncKey, false); err != nil {
		t.Fatal(err)
	}

	status, err := (&FirewallService{}).GetManagedStatusSafe(context.Background(), 8088)
	if err != nil {
		t.Fatal(err)
	}
	if status.Backend != "ufw" || !status.SystemActive || !status.Enabled || status.IncomingPolicy != "allow" {
		t.Fatalf("UFW status does not show the actual host state: %+v", status)
	}
}

func TestUFWNoOpAllowCommandDoesNotReportAppliedRules(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "ufw")
	script := `#!/bin/sh
case "$*" in
  'show added') echo '';;
  allow*) exit 0;;
esac
`
	if err := os.WriteFile(binary, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	Configure(filepath.Join(root, "state.json"), 8088, 0)
	if err := (&SettingService{}).setBool(firewallAutoSyncKey, false); err != nil {
		t.Fatal(err)
	}
	svc := &FirewallService{}
	err := svc.syncManagedLocked(context.Background(), firewallBackend{name: "ufw", binary: binary}, 8088)
	if err == nil || !strings.Contains(err.Error(), "did not persist expected") {
		t.Fatalf("successful but ineffective UFW allow reported success: %v", err)
	}
	ledger, err := loadManagedFirewallRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(ledger) == 0 {
		t.Fatal("the ownership ledger was lost on failed verification")
	}
}
