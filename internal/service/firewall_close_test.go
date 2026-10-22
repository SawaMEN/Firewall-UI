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
 'prepend deny'*) : > "$FW_TEST_UFW_RULE";;
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
 'list chain inet firewall_ui_containers input') /bin/cat "$FW_TEST_NFT_RULES";;
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
	if !strings.Contains(string(raw), "prepend deny to any port 9000 proto tcp comment Firewall-UI advanced close-port-9000-tcp") {
		t.Fatalf("deny not inserted before allow: %s", raw)
	}
	forward, err := os.ReadFile(nftRules)
	if err != nil {
		t.Fatalf("explicit close never installed FORWARD hook: %v", err)
	}
	if !strings.Contains(string(forward), "meta l4proto tcp ct status dnat ct original proto-dst 9000 counter drop") {
		t.Fatalf("DNAT port is not blocked: %s", forward)
	}
	if !strings.Contains(string(forward), "chain input { type filter hook input priority -50; policy accept;") ||
		!strings.Contains(string(forward), "meta l4proto tcp th dport 9000 counter drop") {
		t.Fatalf("ordinary host INPUT access is not blocked by kernel: %s", forward)
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
	if err == nil || !strings.Contains(err.Error(), "nftables") {
		t.Fatalf("successful UFW no-op incorrectly treated as a closed port: %v", err)
	}
	rules, err := loadAdvancedFirewallRules()
	if err != nil || len(rules) != 0 {
		t.Fatalf("ineffective close was persisted: %v, %v", rules, err)
	}
}

func TestUFWClose1332WithoutNumberedComments(t *testing.T) {
	root := t.TempDir()
	activeDeny := filepath.Join(root, "owned-deny")
	nftRules := filepath.Join(root, "nft-rules")
	t.Setenv("UFW_CLOSE_STATE", activeDeny)
	t.Setenv("UFW_CLOSE_NFT", nftRules)
	ufw := `#!/bin/sh
case "$*" in
  status) echo 'Status: active';;
  'status numbered')
    echo 'Status: active'
    echo '[ 1] 22/tcp ALLOW IN Anywhere'
    if [ -f "$UFW_CLOSE_STATE" ]; then echo '[ 2] 1332/tcp DENY IN Anywhere'; fi;;
  'show added')
    echo "ufw allow 22/tcp comment 'administrator'"
    if [ -f "$UFW_CLOSE_STATE" ]; then
      echo "ufw deny to any port 1332 proto tcp comment 'Firewall-UI advanced close-port-1332-tcp'"
    fi;;
  'prepend deny'*) : > "$UFW_CLOSE_STATE";;
  '--force delete deny to any port 1332 proto tcp comment Firewall-UI advanced close-port-1332-tcp')
    /bin/rm -f "$UFW_CLOSE_STATE";;
esac
`
	if err := os.WriteFile(filepath.Join(root, "ufw"), []byte(ufw), 0755); err != nil {
		t.Fatal(err)
	}
	nft := `#!/bin/sh
case "$*" in
 'list tables')
   if [ -f "$UFW_CLOSE_NFT" ]; then echo 'table inet firewall_ui_containers'; fi;;
 'list chain inet firewall_ui_containers input') /bin/cat "$UFW_CLOSE_NFT";;
 '-f -') /bin/cat > "$UFW_CLOSE_NFT";;
 'delete table inet firewall_ui_containers') /bin/rm -f "$UFW_CLOSE_NFT";;
esac
`
	if err := os.WriteFile(filepath.Join(root, "nft"), []byte(nft), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root)
	Configure(filepath.Join(root, "state.json"), 8088, 443)
	svc := &FirewallService{}
	ctx := context.Background()
	rules, err := svc.SetPortClosedSafe(ctx, 1332, "tcp", true, 8088)
	if err != nil || len(rules) != 1 {
		t.Fatalf("commentless UFW numbered output must not reject DENY: %v %#v", err, rules)
	}
	rules, err = svc.SetPortClosedSafe(ctx, 1332, "tcp", true, 8088)
	if err != nil || len(rules) != 1 {
		t.Fatalf("reconciliation duplicated or rejected saved close: %v %#v", err, rules)
	}
	rules, err = svc.SetPortClosedSafe(ctx, 1332, "tcp", false, 8088)
	if err != nil || len(rules) != 0 {
		t.Fatalf("reopen with hidden comments failed: %v %#v", err, rules)
	}
	if _, err := os.Stat(activeDeny); !os.IsNotExist(err) {
		t.Fatalf("UFW deny persisted after reopening: %v", err)
	}
}

func TestUFWCloseRepairsShadowed1332UDPAllow(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "ufw-state")
	logPath := filepath.Join(root, "ufw-log")
	nftPath := filepath.Join(root, "nft-rules")
	if err := os.WriteFile(state, []byte("shadowed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FW_TEST_STATE", state)
	t.Setenv("FW_TEST_LOG", logPath)
	t.Setenv("FW_TEST_NFT", nftPath)
	ufw := `#!/bin/sh
echo "$*" >> "$FW_TEST_LOG"
state="$(/bin/cat "$FW_TEST_STATE")"
case "$*" in
  status) echo 'Status: active';;
  'status numbered')
    echo 'Status: active'
    if [ "$state" = fixed ]; then echo '[ 1] 1332/udp DENY IN Anywhere'; fi
    echo '[ 2] 22/tcp ALLOW IN Anywhere'
    echo '[ 5] 1332/udp ALLOW IN Anywhere'
    if [ "$state" = shadowed ]; then echo '[ 6] 1332/udp DENY IN Anywhere'; fi;;
  'show added')
    echo "ufw allow 1332/udp comment 'administrator'"
    if [ "$state" != allow_only ]; then
       echo "ufw deny to any port 1332 proto udp comment 'Firewall-UI advanced close-port-1332-udp'"
    fi;;
  '--force delete deny to any port 1332 proto udp comment Firewall-UI advanced close-port-1332-udp')
    echo allow_only > "$FW_TEST_STATE";;
  'prepend deny to any port 1332 proto udp comment Firewall-UI advanced close-port-1332-udp')
    if [ "$state" = allow_only ]; then echo fixed > "$FW_TEST_STATE"; fi;;
esac
`
	if err := os.WriteFile(filepath.Join(root, "ufw"), []byte(ufw), 0755); err != nil {
		t.Fatal(err)
	}
	nft := `#!/bin/sh
case "$*" in
 'list tables')
    if [ -f "$FW_TEST_NFT" ]; then echo 'table inet firewall_ui_containers'; fi;;
 'list chain inet firewall_ui_containers input') /bin/cat "$FW_TEST_NFT";;
 '-f -') /bin/cat > "$FW_TEST_NFT";;
esac
`
	if err := os.WriteFile(filepath.Join(root, "nft"), []byte(nft), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root)
	Configure(filepath.Join(root, "panel.json"), 8088, 443)
	svc := &FirewallService{}
	ctx := context.Background()
	rules, err := svc.SetPortClosedSafe(ctx, 1332, "udp", true, 8088)
	if err != nil || len(rules) != 1 {
		t.Fatalf("shadowed 1332/udp DENY was not repaired: %v %#v", err, rules)
	}
	gotState, err := os.ReadFile(state)
	if err != nil || strings.TrimSpace(string(gotState)) != "fixed" {
		t.Fatalf("port remained exposed: state %q, err %v", gotState, err)
	}
	log, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(log), "--force delete deny to any port 1332 proto udp comment Firewall-UI advanced close-port-1332-udp") ||
		!strings.Contains(string(log), "prepend deny to any port 1332 proto udp comment Firewall-UI advanced close-port-1332-udp") {
		t.Fatalf("the stale owned DENY was not replaced with a top-priority rule: %s", log)
	}
	if strings.Contains(string(log), "delete allow 1332/udp") {
		t.Fatalf("administrator ALLOW was modified: %s", log)
	}
}

func TestUFWClose1332UDPWhenEarlierAllowCannotBeReordered(t *testing.T) {
	root := t.TempDir()
	nftRules := filepath.Join(root, "nft-kernel")
	t.Setenv("FWUI_KERNEL_RULES", nftRules)
	t.Setenv("PATH", root)
	// Reproduces the reported failure: UFW repeatedly claims success but
	// retains its administrator-owned ALLOW for 1332/udp at position 5.
	ufw := `#!/bin/sh
case "$*" in
  status) echo 'Status: active';;
  'status numbered')
    echo 'Status: active'
    echo '[ 1] 22/tcp ALLOW IN Anywhere'
    echo '[ 5] 1332/udp ALLOW IN Anywhere'
    echo '[ 6] 1332/udp (v6) ALLOW IN Anywhere (v6)';;
  'show added') echo "ufw allow 1332/udp comment 'administrator'";;
  'prepend deny'*) exit 0;;
esac
`
	nft := `#!/bin/sh
case "$*" in
  'list tables')
    if [ -f "$FWUI_KERNEL_RULES" ]; then echo 'table inet firewall_ui_containers'; fi;;
  'list chain inet firewall_ui_containers input')
    # nft normalizes the source expression when it displays live rules.
    /bin/sed 's/meta l4proto udp th dport 1332/udp dport 1332/g' "$FWUI_KERNEL_RULES";;
  '-f -') /bin/cat > "$FWUI_KERNEL_RULES";;
  'delete table inet firewall_ui_containers')
    /bin/rm -f "$FWUI_KERNEL_RULES";;
esac
`
	for name, script := range map[string]string{"ufw": ufw, "nft": nft} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
	}
	Configure(filepath.Join(root, "state.json"), 8088, 443)
	svc := &FirewallService{}
	ctx := context.Background()
	rules, err := svc.SetPortClosedSafe(ctx, 1332, "udp", true, 8088)
	if err != nil || len(rules) != 1 {
		t.Fatalf("kernel-enforced UFW closed port rejected: %v, rules=%+v", err, rules)
	}
	script, err := os.ReadFile(nftRules)
	if err != nil {
		t.Fatal(err)
	}
	for _, clause := range []string{
		"chain input { type filter hook input priority -50; policy accept;",
		"meta l4proto udp th dport 1332 counter drop",
		"meta l4proto udp ct status dnat ct original proto-dst 1332 counter drop",
	} {
		if !strings.Contains(string(script), clause) {
			t.Fatalf("kernel did not block 1332/udp: missing %q in %s", clause, script)
		}
	}
	// Simulate another service changing this table while the desired-policy
	// cache is fresh. Closing the port again must repair the missing kernel
	// rule rather than reporting a false success or returning an error.
	withoutDrop := strings.Replace(string(script),
		"meta l4proto udp th dport 1332 counter drop comment \"fwui-closed-input:close-port-1332-udp\"",
		"", 1)
	if withoutDrop == string(script) {
		t.Fatal("test fixture did not remove its INPUT DROP")
	}
	if err := os.WriteFile(nftRules, []byte(withoutDrop), 0600); err != nil {
		t.Fatal(err)
	}
	// Auto-sync/idempotent closes must not start a loop of UFW repairs.
	if _, err := svc.SetPortClosedSafe(ctx, 1332, "udp", true, 8088); err != nil {
		t.Fatalf("repeated close could not repair a missing kernel INPUT drop: %v", err)
	}
	repaired, err := os.ReadFile(nftRules)
	if err != nil || !strings.Contains(string(repaired), "fwui-closed-input:close-port-1332-udp") {
		t.Fatalf("fresh policy cache hid a removed kernel DROP: %s; err: %v", repaired, err)
	}
	if _, err := svc.SetPortClosedSafe(ctx, 1332, "udp", false, 8088); err != nil {
		t.Fatalf("failed to reopen kernel-blocked UDP port: %v", err)
	}
	if _, err := os.Stat(nftRules); !os.IsNotExist(err) {
		t.Fatalf("kernel drop remains after reopening: %v", err)
	}
}
