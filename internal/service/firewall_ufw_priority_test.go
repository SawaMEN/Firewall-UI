package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUFWCloseKeepsAdminAllowButAddsLeadingDeny(t *testing.T) {
	for _, proto := range []string{"tcp", "udp"} {
		t.Run(proto, func(t *testing.T) {
			root := t.TempDir()
			active := filepath.Join(root, "ufw-owned")
			logFile := filepath.Join(root, "ufw-calls")
			nftFile := filepath.Join(root, "nft-table")
			t.Setenv("FWUI_TEST_UFW_ACTIVE", active)
			t.Setenv("FWUI_TEST_UFW_LOG", logFile)
			t.Setenv("FWUI_TEST_NFT", nftFile)
			t.Setenv("FWUI_TEST_PROTOCOL", proto)
			ufw := `#!/bin/sh
echo "$*" >> "$FWUI_TEST_UFW_LOG"
case "$*" in
 status) echo 'Status: active';;
 'status numbered')
   echo 'Status: active'
   if [ -f "$FWUI_TEST_UFW_ACTIVE" ]; then
     echo "[ 1] 1332/$FWUI_TEST_PROTOCOL DENY IN Anywhere # Firewall-UI advanced close-port-1332-$FWUI_TEST_PROTOCOL"
     echo "[ 2] 1332/$FWUI_TEST_PROTOCOL (v6) DENY IN Anywhere (v6) # Firewall-UI advanced close-port-1332-$FWUI_TEST_PROTOCOL"
   fi
   echo "[ 5] 1332/$FWUI_TEST_PROTOCOL ALLOW IN Anywhere"
   echo "[ 6] 1332/$FWUI_TEST_PROTOCOL (v6) ALLOW IN Anywhere (v6)";;
 'show added')
   echo "ufw allow 1332/$FWUI_TEST_PROTOCOL comment 'administrator'"
   if [ -f "$FWUI_TEST_UFW_ACTIVE" ]; then
     echo "ufw deny to any port 1332 proto $FWUI_TEST_PROTOCOL comment 'Firewall-UI advanced close-port-1332-$FWUI_TEST_PROTOCOL'"
   fi;;
 'prepend deny'*) : ;; # Simulate UFW silently failing to reorder.
 'insert 1 deny'*) : > "$FWUI_TEST_UFW_ACTIVE";;
 '--force delete 1') /bin/rm -f "$FWUI_TEST_UFW_ACTIVE";;
esac
`
			nft := `#!/bin/sh
case "$*" in
 'list tables') if [ -f "$FWUI_TEST_NFT" ]; then echo 'table inet firewall_ui_containers'; fi;;
 '-j list table inet firewall_ui_containers')
   if [ -f "$FWUI_TEST_NFT" ]; then
     echo '` + closedPortNFTFixture(proto, 1332) + `'
   else
     exit 1
   fi;;
 '-f -') /bin/cat > "$FWUI_TEST_NFT";;
 'delete table inet firewall_ui_containers') /bin/rm -f "$FWUI_TEST_NFT";;
esac
`
			for name, script := range map[string]string{"ufw": ufw, "nft": nft} {
				if err := os.WriteFile(filepath.Join(root, name), []byte(script), 0755); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("PATH", root)
			Configure(filepath.Join(root, "state.json"), 8088, 443)
			svc := &FirewallService{}
			ctx := context.Background()
			if _, err := svc.SetPortClosedSafe(ctx, 1332, proto, true, 8088); err != nil {
				t.Fatalf("close %s: %v", proto, err)
			}
			status, err := runFirewallCommand(ctx, filepath.Join(root, "ufw"), "status", "numbered")
			if err != nil {
				t.Fatal(err)
			}
			for _, ipv6 := range []bool{false, true} {
				if n, action := findUFWPortDecisionFamily(status, "1332/"+proto, ipv6); action != "DENY" || (n != 1 && n != 2) {
					t.Fatalf("first UFW decision for ipv6=%v = %d %s: %s", ipv6, n, action, status)
				}
			}
			log, err := os.ReadFile(logFile)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(log), "insert 1 deny to any port 1332 proto "+proto) {
				t.Fatalf("UFW priority insertion did not happen: %s", log)
			}
			if strings.Contains(string(log), "delete allow 1332/") {
				t.Fatalf("admin ALLOW was removed: %s", log)
			}
			// Repeated close and background reconciliation must preserve UFW
			// priority and not introduce a duplicate owned DENY.
			if _, err := svc.SetPortClosedSafe(ctx, 1332, proto, true, 8088); err != nil {
				t.Fatalf("repeat close: %v", err)
			}
			if err := syncUFWAdvancedRulesLocked(ctx, firewallBackend{name: "ufw", binary: filepath.Join(root, "ufw")}); err != nil {
				t.Fatalf("background reconciliation: %v", err)
			}
			if _, err := svc.SetPortClosedSafe(ctx, 1332, proto, false, 8088); err != nil {
				t.Fatalf("reopen: %v", err)
			}
			if _, err := os.Stat(active); !os.IsNotExist(err) {
				t.Fatalf("owned DENY was not removed on reopen: %v", err)
			}
		})
	}
}
