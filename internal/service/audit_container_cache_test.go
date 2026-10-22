package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestContainerForwardPolicyRepairsDriftAfterCachePeriod(t *testing.T) {
	root := t.TempDir()
	logPath := filepath.Join(root, "nft-writes")
	t.Setenv("FW_AUDIT_NFT_LOG", logPath)
	ufw := "#!/bin/sh\ncase \"$*\" in\n status) echo 'Status: active';;\nesac\n"
	nft := `#!/bin/sh
case "$*" in
  'list tables') echo 'table inet firewall_ui_containers';;
  '-f -') /bin/cat >/dev/null; echo apply >> "$FW_AUDIT_NFT_LOG";;
esac
`
	for filename, script := range map[string]string{"ufw": ufw, "nft": nft} {
		if err := os.WriteFile(filepath.Join(root, filename), []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", root)
	Configure(filepath.Join(root, "state.json"), 8088, 0)
	if err := setFirewallManagedEnabledPreference(true); err != nil {
		t.Fatal(err)
	}
	rules := []FirewallAdvancedRule{{
		ID: closeRuleID(1332, "udp"), Action: "deny", Protocol: "udp",
		PortStart: 1332, PortEnd: 1332, IPVersion: "any", Priority: -1000,
	}}
	if err := saveFirewallJSON(firewallAdvancedRulesKey, rules); err != nil {
		t.Fatal(err)
	}
	oldHash, oldTime := containerPolicyHash, containerPolicyLastCheck
	containerPolicyHash = [32]byte{}
	containerPolicyLastCheck = time.Time{}
	t.Cleanup(func() { containerPolicyHash, containerPolicyLastCheck = oldHash, oldTime })
	svc := &FirewallService{}
	check := func(want int) {
		t.Helper()
		if err := svc.SyncContainerProtection(context.Background()); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatal(err)
		}
		if n := strings.Count(string(data), "apply"); n != want {
			t.Fatalf("nft updates = %d, want %d", n, want)
		}
	}
	check(1)
	check(1)
	containerPolicyLastCheck = time.Now().Add(-2*time.Minute)
	check(2)
}
