package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdvancedRulesLiveNeverTreatsSavedCloseAsEffective(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PATH", root)
	ufw := `#!/bin/sh
case "$*" in
 status) echo 'Status: active';;
 'status numbered') echo '[ 1] 1332/tcp ALLOW IN Anywhere';;
 'show added') echo "ufw allow 1332/tcp comment 'administrator'";;
esac
`
	nft := "#!/bin/sh\ncase \"$*\" in\n '-j list table inet firewall_ui_containers') echo '" + closedPortNFTFixture("tcp", 1332) + "';;\nesac\n"
	for name, script := range map[string]string{"ufw": ufw, "nft": nft} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
	}
	Configure(filepath.Join(root, "state.json"), 8088, 443)
	rule := FirewallAdvancedRule{ID: closeRuleID(1332, "tcp"), Action: "deny", Protocol: "tcp", PortStart: 1332, PortEnd: 1332, IPVersion: "any", Priority: -1000}
	if err := saveFirewallJSON(firewallAdvancedRulesKey, []FirewallAdvancedRule{rule}); err != nil {
		t.Fatal(err)
	}
	observed, err := (&FirewallService{}).AdvancedRulesLive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(observed) != 1 || observed[0].Enforced == nil || *observed[0].Enforced {
		t.Fatalf("a persisted close cannot hide a leading UFW ALLOW: %+v", observed)
	}
	if !strings.Contains(observed[0].EnforcementError, "UFW DENY") {
		t.Fatalf("missing warning: %+v", observed[0])
	}
	persisted, err := loadAdvancedFirewallRules()
	if err != nil {
		t.Fatal(err)
	}
	if persisted[0].Enforced != nil || persisted[0].EnforcementError != "" {
		t.Fatalf("live status was persisted: %+v", persisted[0])
	}
}

func TestAdvancedRulesLiveRejectsMissingNftHook(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PATH", root)
	ufw := `#!/bin/sh
case "$*" in
 status) echo 'Status: active';;
 'status numbered') echo '[ 1] 1332/tcp DENY IN Anywhere # Firewall-UI advanced close-port-1332-tcp';;
 'show added') echo "ufw deny to any port 1332 proto tcp comment 'Firewall-UI advanced close-port-1332-tcp'";;
esac
`
	nft := "#!/bin/sh\nexit 1\n"
	for name, script := range map[string]string{"ufw": ufw, "nft": nft} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
	}
	Configure(filepath.Join(root, "state.json"), 8088, 443)
	rule := FirewallAdvancedRule{ID: closeRuleID(1332, "tcp"), Action: "deny", Protocol: "tcp", PortStart: 1332, PortEnd: 1332, IPVersion: "any", Priority: -1000}
	if err := saveFirewallJSON(firewallAdvancedRulesKey, []FirewallAdvancedRule{rule}); err != nil {
		t.Fatal(err)
	}
	observed, err := (&FirewallService{}).AdvancedRulesLive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(observed) != 1 || observed[0].Enforced == nil || *observed[0].Enforced {
		t.Fatalf("UFW DENY without nftables INPUT/FORWARD is not verified: %+v", observed)
	}
}
