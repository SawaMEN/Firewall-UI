package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestContainerForwardPolicyChecksDriftWithoutResettingCounters(t *testing.T) {
	root := t.TempDir()
	logPath := filepath.Join(root, "nft-writes")
	t.Setenv("FW_AUDIT_NFT_LOG", logPath)
	live := filepath.Join(root, "live.json")
	t.Setenv("FW_AUDIT_NFT_LIVE", live)
	desired := filepath.Join(root, "desired.json")
	t.Setenv("FW_AUDIT_NFT_DESIRED", desired)
	if err := os.WriteFile(desired, []byte(closedPortNFTFixture("udp", 1332)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(live, []byte(closedPortNFTFixture("udp", 1332)), 0600); err != nil {
		t.Fatal(err)
	}
	ufw := "#!/bin/sh\ncase \"$*\" in\n status) echo 'Status: active';;\nesac\n"
	nft := `#!/bin/sh
case "$*" in
  'list tables') echo 'table inet firewall_ui_containers';;
  '-j list table inet firewall_ui_containers') /bin/cat "$FW_AUDIT_NFT_LIVE";;
  '-f -') /bin/cat >/dev/null; /bin/cp "$FW_AUDIT_NFT_DESIRED" "$FW_AUDIT_NFT_LIVE"; echo apply >> "$FW_AUDIT_NFT_LOG";;
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
	oldHash, oldTime, oldObserved := containerPolicyHash, containerPolicyLastCheck, containerPolicyObservedHash
	containerPolicyHash = [32]byte{}
	containerPolicyLastCheck = time.Time{}
	t.Cleanup(func() {
		containerPolicyHash, containerPolicyLastCheck, containerPolicyObservedHash = oldHash, oldTime, oldObserved
	})
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
	containerPolicyLastCheck = time.Now().Add(-2 * time.Minute)
	check(1) // An aged but unchanged ruleset must keep its counters.
	if err := os.WriteFile(live, []byte(`{"nftables":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	check(2) // Drift must repair immediately, even inside the old cache period.
}
