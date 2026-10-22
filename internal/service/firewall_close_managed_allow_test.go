package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClosePortRemovesOwnedUFWAllowAndKeepsAdministratorAllow(t *testing.T) {
	for _, proto := range []string{"tcp", "udp"} {
		t.Run(proto, func(t *testing.T) {
			root := t.TempDir()
			managedAllow := filepath.Join(root, "managed-allow")
			adminAllow := filepath.Join(root, "admin-allow")
			denied := filepath.Join(root, "denied")
			nftFile := filepath.Join(root, "nft-rules")
			logFile := filepath.Join(root, "ufw-log")
			for _, name := range []string{managedAllow, adminAllow} {
				if err := os.WriteFile(name, []byte("1"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("FW_TEST_MANAGED", managedAllow)
			t.Setenv("FW_TEST_ADMIN", adminAllow)
			t.Setenv("FW_TEST_DENIED", denied)
			t.Setenv("FW_TEST_NFT", nftFile)
			t.Setenv("FW_TEST_LOG", logFile)
			t.Setenv("FW_TEST_PROTO", proto)
			ufw := `#!/bin/sh
echo "$*" >> "$FW_TEST_LOG"
case "$*" in
 status) echo 'Status: active';;
 'status numbered')
    echo 'Status: active'
    if [ -f "$FW_TEST_DENIED" ]; then
      echo "[ 1] 1332/$FW_TEST_PROTO DENY IN Anywhere # Firewall-UI advanced close-port-1332-$FW_TEST_PROTO"
      echo "[ 2] 1332/$FW_TEST_PROTO (v6) DENY IN Anywhere (v6) # Firewall-UI advanced close-port-1332-$FW_TEST_PROTO"
    fi
    if [ -f "$FW_TEST_MANAGED" ]; then
      echo "[ 3] 1332/$FW_TEST_PROTO ALLOW IN Anywhere # Firewall-UI managed"
    fi
    if [ -f "$FW_TEST_ADMIN" ]; then
      echo "[ 5] 1332/$FW_TEST_PROTO ALLOW IN Anywhere # administrator"
    fi;;
 'show added')
    if [ -f "$FW_TEST_MANAGED" ]; then echo "ufw allow 1332/$FW_TEST_PROTO comment 'Firewall-UI managed'"; fi
    if [ -f "$FW_TEST_ADMIN" ]; then echo "ufw allow 1332/$FW_TEST_PROTO comment 'administrator'"; fi
    if [ -f "$FW_TEST_DENIED" ]; then echo "ufw deny to any port 1332 proto $FW_TEST_PROTO comment 'Firewall-UI advanced close-port-1332-$FW_TEST_PROTO'"; fi;;
 '--force delete 3'| '--force delete allow 1332/'*' comment Firewall-UI managed')
    /bin/rm -f "$FW_TEST_MANAGED";;
 '--force delete 1'| '--force delete deny '*)
    /bin/rm -f "$FW_TEST_DENIED";;
 'prepend deny '*|'insert 1 deny '*)
    : > "$FW_TEST_DENIED";;
esac
`
			nft := `#!/bin/sh
case "$*" in
 'list tables') if [ -f "$FW_TEST_NFT" ]; then echo 'table inet firewall_ui_containers'; fi;;
 '-j list table inet firewall_ui_containers')
    if [ -f "$FW_TEST_NFT" ]; then echo '` + closedPortNFTFixture(proto, 1332) + `'; else exit 1; fi;;
 '-f -') /bin/cat > "$FW_TEST_NFT";;
 'delete table inet firewall_ui_containers') /bin/rm -f "$FW_TEST_NFT";;
esac
`
			for name, script := range map[string]string{"ufw": ufw, "nft": nft} {
				if err := os.WriteFile(filepath.Join(root, name), []byte(script), 0755); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("PATH", root)
			Configure(filepath.Join(root, "state.json"), 8088, 443)
			if _, err := (&FirewallService{}).SetPortClosedSafe(context.Background(), 1332, proto, true, 8088); err != nil {
				t.Fatalf("close port: %v", err)
			}
			if _, err := os.Stat(managedAllow); !os.IsNotExist(err) {
				t.Fatalf("owned managed ALLOW remains after close: %v", err)
			}
			if _, err := os.Stat(adminAllow); err != nil {
				t.Fatalf("administrator ALLOW was incorrectly deleted: %v", err)
			}
			if _, err := os.Stat(denied); err != nil {
				t.Fatalf("leading DENY was not installed: %v", err)
			}
			log, err := os.ReadFile(logFile)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(log), "--force delete") || !strings.Contains(string(log), "prepend deny") {
				t.Fatalf("managed ALLOW was not removed before close: %s", log)
			}
		})
	}
}

func TestManagedDesiredRulesDoNotReopenExplicitClose(t *testing.T) {
	root := t.TempDir()
	Configure(filepath.Join(root, "state.json"), 8088, 443)
	manual := []FirewallManualRule{{Port: 1332, Protocol: "udp"}, {Port: 1444, Protocol: "tcp"}}
	if err := saveFirewallJSON(firewallManualRulesKey, manual); err != nil {
		t.Fatal(err)
	}
	closed := []FirewallAdvancedRule{{
		ID: closeRuleID(1332, "udp"), Action: "deny", Protocol: "udp",
		PortStart: 1332, PortEnd: 1332, IPVersion: "any", Priority: -1000,
	}}
	if err := saveFirewallJSON(firewallAdvancedRulesKey, closed); err != nil {
		t.Fatal(err)
	}
	rules, err := (&FirewallService{}).managedDesiredRules(false, 8088)
	if err != nil {
		t.Fatal(err)
	}
	seenOpen, seenOther := false, false
	for _, r := range rules {
		switch firewallRuleSpec(r) {
		case "1332/udp":
			seenOpen = true
		case "1444/tcp":
			seenOther = true
		}
	}
	if seenOpen || !seenOther {
		t.Fatalf("closed 1332/udp is still being auto-allowed, or unrelated 1444/tcp was lost: %+v", rules)
	}
}
