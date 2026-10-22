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
	ufwRule := filepath.Join(root, "deny-installed")
	nftRules := filepath.Join(root, "nft-rules")
	t.Setenv("FW_TEST_LOG", logPath)
	t.Setenv("FW_TEST_UFW_RULE", ufwRule)
	t.Setenv("FW_TEST_NFT_RULES", nftRules)
	ufw := `#!/bin/sh
printf '%s\n' "$*" >> "$FW_TEST_LOG"
case "$*" in
 status) echo 'Status: active';;
 'status numbered')
   echo 'Status: active'
   if [ -f "$FW_TEST_UFW_RULE" ]; then
     echo '[ 1] 9000/tcp DENY IN Anywhere # Firewall-UI advanced close-port-9000-tcp'
   fi;;
 'show added') echo 'ufw allow 9000/tcp';;
 'insert 1 deny'*) : > "$FW_TEST_UFW_RULE";;
 '--force delete 1') /bin/rm -f "$FW_TEST_UFW_RULE";;
esac
`
	if err := os.WriteFile(filepath.Join(root, "ufw"), []byte(ufw), 0755); err != nil {
		t.Fatal(err)
	}
	nft := `#!/bin/sh
case "$*" in
 'list tables')
   if [ -f "$FW_TEST_NFT_RULES" ]; then echo 'table inet firewall_ui_containers'; fi;;
 '-f -') /bin/cat > "$FW_TEST_NFT_RULES";;
 'delete table inet firewall_ui_containers') /bin/rm -f "$FW_TEST_NFT_RULES";;
esac
`
	if err := os.WriteFile(filepath.Join(root, "nft"), []byte(nft), 0755); err != nil {
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
	forward, err := os.ReadFile(nftRules)
	if err != nil {
		t.Fatalf("explicit close never installed FORWARD hook: %v", err)
	}
	if !strings.Contains(string(forward), "meta l4proto tcp ct status dnat ct original proto-dst 9000 counter drop") {
		t.Fatalf("DNAT port is not blocked: %s", forward)
	}
	if strings.Contains(string(forward), "fwui-container-block:") {
		t.Fatalf("closed port unexpectedly enabled broad container protection: %s", forward)
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
	if _, err := os.Stat(nftRules); !os.IsNotExist(err) {
		t.Fatalf("reopen left the independent FORWARD hook installed: %v", err)
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

func TestClosedPortDNATDropPrecedesEstablishedAndManualAllow(t *testing.T) {
	closeRule := FirewallAdvancedRule{
		ID: closeRuleID(9000, "tcp"), Action: "deny", Protocol: "tcp",
		PortStart: 9000, PortEnd: 9000, IPVersion: "any", Priority: -1000,
	}
	script := buildContainerForwardRules(
		[]ContainerPort{{HostPort: 9000, HostIP: "0.0.0.0", Protocol: "tcp", Public: true}},
		[]FirewallManualRule{{Port: 9000, Protocol: "tcp"}},
		[]FirewallAdvancedRule{closeRule},
	)
	deny := "meta l4proto tcp ct status dnat ct original proto-dst 9000 counter drop"
	if strings.Index(script, deny) < 0 {
		t.Fatalf("DNAT close was not generated: %s", script)
	}
	if strings.Index(script, deny) > strings.Index(script, "ct state established,related accept") {
		t.Fatalf("established flow would bypass an explicit close: %s", script)
	}
	if strings.Index(script, deny) > strings.Index(script, "fwui-container-allow:") {
		t.Fatalf("manual allow takes priority over a close: %s", script)
	}
	if strings.Contains(script, "fwui-container-rule:"+closeRule.ID) {
		t.Fatalf("closed port was duplicated in per-container rules: %s", script)
	}
}

func TestUFWCloseRejectsSuccessfulButIneffectiveInsert(t *testing.T) {
	root := t.TempDir()
	ufw := `#!/bin/sh
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
	_, err := (&FirewallService{}).SetPortClosedSafe(context.Background(), 9000, "tcp", true, 8088)
	if err == nil || !strings.Contains(err.Error(), "did not install the highest-priority DENY") {
		t.Fatalf("successful UFW no-op incorrectly treated as a closed port: %v", err)
	}
	rules, err := loadAdvancedFirewallRules()
	if err != nil || len(rules) != 0 {
		t.Fatalf("ineffective close was persisted: %v, %v", rules, err)
	}
}
