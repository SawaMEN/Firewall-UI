package service

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClosedTCPRepairsStaleCachedNftInputDrop(t *testing.T) {
	root := t.TempDir()
	kernel := filepath.Join(root, "kernel-chain")
	t.Setenv("FWUI_TEST_KERNEL", kernel)
	t.Setenv("PATH", root)
	ufw := `#!/bin/sh
case "$*" in
 status) echo 'Status: active';;
 'status numbered') echo 'Status: active'; echo '[ 1] 1332/tcp DENY IN Anywhere';;
 'show added') echo "ufw deny to any port 1332 proto tcp comment 'Firewall-UI advanced close-port-1332-tcp'";;
esac
`
	liveJSON := filepath.Join(root, "kernel.json")
	desiredJSON := filepath.Join(root, "desired.json")
	if err := os.WriteFile(liveJSON, []byte(`{"nftables":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(desiredJSON, []byte(closedPortNFTFixture("tcp", 1332)), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FWUI_TEST_KERNEL_JSON", liveJSON)
	t.Setenv("FWUI_TEST_DESIRED_JSON", desiredJSON)
	nft := `#!/bin/sh
case "$*" in
 'list tables') echo 'table inet firewall_ui_containers';;
 '-j list table inet firewall_ui_containers') /bin/cat "$FWUI_TEST_KERNEL_JSON";;
 '-f -') /bin/cat > "$FWUI_TEST_KERNEL"; /bin/cp "$FWUI_TEST_DESIRED_JSON" "$FWUI_TEST_KERNEL_JSON";;
esac
`
	for name, script := range map[string]string{"ufw": ufw, "nft": nft} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
	}
	// A real INPUT base chain is present, but another firewall process
	// removed the port DROP without deleting the table itself.
	stale := "table inet firewall_ui_containers {\n chain input { type filter hook input priority -50; policy accept;\n }\n}\n"
	if err := os.WriteFile(kernel, []byte(stale), 0600); err != nil {
		t.Fatal(err)
	}
	Configure(filepath.Join(root, "state.json"), 8088, 443)
	rule := FirewallAdvancedRule{
		ID: closeRuleID(1332, "tcp"), Action: "deny", Protocol: "tcp",
		PortStart: 1332, PortEnd: 1332, IPVersion: "any", Priority: -1000,
	}
	oldHash, oldCheck := containerPolicyHash, containerPolicyLastCheck
	containerPolicyHash = sha256.Sum256([]byte(buildContainerForwardRules(nil, nil, []FirewallAdvancedRule{rule})))
	containerPolicyLastCheck = time.Now()
	t.Cleanup(func() {
		containerPolicyHash, containerPolicyLastCheck = oldHash, oldCheck
	})
	if _, err := (&FirewallService{}).SetPortClosedSafe(context.Background(), 1332, "tcp", true, 8088); err != nil {
		t.Fatalf("failed to rebuild missing live kernel INPUT drop: %v", err)
	}
	data, err := os.ReadFile(kernel)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "meta l4proto tcp th dport 1332 counter drop") {
		t.Fatalf("nftables INPUT DROP was not restored: %s", data)
	}
}
