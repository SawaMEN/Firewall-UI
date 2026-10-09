package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClosePortOverridesAutoAndProtectsAccess(t *testing.T) {
	root := t.TempDir()
	logPath := filepath.Join(root, "commands")
	t.Setenv("FW_TEST_LOG", logPath)
	ufw := `#!/bin/sh
printf '%s\n' "$*" >> "$FW_TEST_LOG"
case "$*" in
 status) echo 'Status: active';;
 'status numbered') echo 'Status: active';;
 'show added') echo 'ufw allow 9000/tcp';;
esac
`
	if err := os.WriteFile(filepath.Join(root, "ufw"), []byte(ufw), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root)
	Configure(filepath.Join(root, "state.json"), 8088, 443)
	s := &FirewallService{}
	ctx := context.Background()
	for _, port := range []int{8088, 443, 22} {
		if _, err := s.SetPortClosedSafe(ctx, port, "tcp", true, 8088); err == nil {
			t.Fatalf("protected port %d closed", port)
		}
	}
	rules, err := s.SetPortClosedSafe(ctx, 9000, "tcp", true, 8088)
	if err != nil || len(rules) != 1 {
		t.Fatalf("close failed: %v %v", rules, err)
	}
	raw, _ := os.ReadFile(logPath)
	if !strings.Contains(string(raw), "insert 1 deny to any port 9000 proto tcp comment Firewall-UI advanced close-port-9000-tcp") {
		t.Fatalf("deny not inserted before allow: %s", raw)
	}
	rich := firewalldRichRule(rules[0])
	if !strings.Contains(rich, `priority="-1000"`) || !strings.HasSuffix(rich, "drop") {
		t.Fatalf("firewalld close lacks priority: %s", rich)
	}
	again, err := s.SetPortClosedSafe(ctx, 9000, "tcp", true, 8088)
	if err != nil || len(again) != 1 {
		t.Fatal("duplicate close rule")
	}
	opened, err := s.SetPortClosedSafe(ctx, 9000, "tcp", false, 8088)
	if err != nil || len(opened) != 0 {
		t.Fatal("reopen did not remove explicit denial")
	}
}

func TestCleanupInactiveUFWPreservesForeignRules(t *testing.T) {
	root := t.TempDir()
	logPath := filepath.Join(root, "commands")
	t.Setenv("FW_TEST_LOG", logPath)
	ufw := `#!/bin/sh
printf '%s\n' "$*" >> "$FW_TEST_LOG"
case "$*" in
 'show added')
 echo "ufw allow 22/tcp comment 'SSH administrator'"
 echo "ufw allow 8443/tcp comment 'Firewall-UI access'"
 echo "ufw deny to any port 9000 proto tcp comment 'Firewall-UI advanced close-port-9000-tcp'";;
 status*) echo 'Status: inactive';;
esac
`
	if err := os.WriteFile(filepath.Join(root, "ufw"), []byte(ufw), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root)
	Configure(filepath.Join(root, "state.json"), 8088, 0)
	if err := (&FirewallService{}).CleanupOwnedRules(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(logPath)
	if strings.Contains(string(raw), "delete allow 22") || strings.Contains(string(raw), "disable") || strings.Contains(string(raw), "reset") {
		t.Fatalf("foreign firewall changed: %s", raw)
	}
	if !strings.Contains(string(raw), "delete allow 8443/tcp") || !strings.Contains(string(raw), "delete deny to any port 9000") {
		t.Fatalf("owned rules remain: %s", raw)
	}
}
