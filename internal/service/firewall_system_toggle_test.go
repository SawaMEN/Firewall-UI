package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// UFW must be disabled at the host level, not merely have the rules created
// by Firewall-UI removed. Existing administrator rules must survive toggling.
func TestUFWSystemSwitchChangesHostStateWithoutDeletingRules(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "ufw-state")
	rules := filepath.Join(root, "ufw-rules")
	commands := filepath.Join(root, "ufw-commands")
	if err := os.WriteFile(state, []byte("active\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rules, []byte("ufw allow 8088/tcp comment 'administrator'\nufw allow 9000/tcp comment 'third party'\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FWUI_UFW_STATE", state)
	t.Setenv("FWUI_UFW_RULES", rules)
	t.Setenv("FWUI_UFW_COMMANDS", commands)
	stub := `#!/bin/sh
printf '%s\n' "$*" >> "$FWUI_UFW_COMMANDS"
case "$*" in
  status|'status verbose'|'status numbered')
    if /bin/grep -q '^active' "$FWUI_UFW_STATE"; then
      echo 'Status: active'
    else
      echo 'Status: inactive'
    fi;;
  'show added') /bin/cat "$FWUI_UFW_RULES";;
  disable) echo inactive > "$FWUI_UFW_STATE";;
  '--force enable') echo active > "$FWUI_UFW_STATE";;
  allow*) echo "ufw allow $2" >> "$FWUI_UFW_RULES";;
esac
`
	if err := os.WriteFile(filepath.Join(root, "ufw"), []byte(stub), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root)
	Configure(filepath.Join(root, "state.json"), 8088, 0)
	if err := setFirewallManagedEnabledPreference(true); err != nil {
		t.Fatal(err)
	}
	svc := &FirewallService{}
	ctx := context.Background()
	disabled, err := svc.SetManagedEnabledSafe(ctx, false, 8088)
	if err != nil {
		t.Fatal(err)
	}
	if disabled.Enabled || disabled.SystemActive {
		t.Fatalf("UFW still active after switching off: %+v", disabled)
	}
	afterOff, err := os.ReadFile(rules)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(afterOff), "ufw allow 9000/tcp") {
		t.Fatal("unrelated UFW rules were lost")
	}
	enabled, err := svc.SetManagedEnabledSafe(ctx, true, 8088)
	if err != nil {
		t.Fatal(err)
	}
	if !enabled.Enabled || !enabled.SystemActive {
		t.Fatalf("UFW not active after switching on: %+v", enabled)
	}
	log, err := os.ReadFile(commands)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(log), "disable\n") || !strings.Contains(string(log), "--force enable\n") {
		t.Fatalf("host UFW was not toggled: %s", log)
	}
	if strings.Contains(string(log), "delete") || strings.Contains(string(log), "reset") {
		t.Fatalf("toggle must preserve system firewall rules: %s", log)
	}
}
