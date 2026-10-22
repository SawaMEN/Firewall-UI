package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNftInputCloseRecognizesKernelNormalizedPortRules(t *testing.T) {
	for _, proto := range []string{"tcp", "udp"} {
		t.Run(proto, func(t *testing.T) {
			rule := FirewallAdvancedRule{
				ID: closeRuleID(1332, proto), Action: "deny",
				Protocol: proto, PortStart: 1332, PortEnd: 1332,
				IPVersion: "any", Priority: -1000,
			}
			original := "meta l4proto " + proto + " th dport 1332 counter drop"
			normalized := proto + " dport 1332 counter packets 0 bytes 0 drop"
			header := "table inet firewall_ui_containers {\n chain input {\n type filter hook input priority -50; policy accept;\n"
			comment := " comment \"fwui-closed-input:" + rule.ID + "\"\n }\n}\n"
			for _, form := range []string{original, normalized} {
				t.Run(strings.Fields(form)[0], func(t *testing.T) {
					if !nftInputClosePresent(header+form+comment, rule) {
						t.Fatalf("valid installed %s drop was rejected: %s", proto, form)
					}
				})
			}
			invalid := []struct{ name, text string }{
				{"wrong protocol", header + strings.Replace(normalized, proto+" dport", "udp dport", 1) + comment},
				{"wrong port", header + strings.Replace(normalized, "1332", "13320", 1) + comment},
				{"accept verdict", header + strings.Replace(normalized, " drop", " accept", 1) + comment},
				{"missing owner", header + normalized + " comment \"other-rule\"\n }\n}\n"},
				{"unhooked chain", "table inet firewall_ui_containers {\n chain input {\n" + normalized + comment},
				{"wrong chain hook", strings.Replace(header, "hook input", "hook forward", 1) + normalized + comment},
				{"marker only in comment", header + "counter accept comment \"fwui-closed-input:" + rule.ID + " " + normalized + "\"\n }\n}\n"},
			}
			for _, tc := range invalid {
				if tc.name == "wrong protocol" && proto == "udp" {
					tc.text = strings.Replace(tc.text, "udp dport", "tcp dport", 1)
				}
				t.Run(tc.name, func(t *testing.T) {
					if nftInputClosePresent(tc.text, rule) {
						t.Fatalf("incorrectly accepted nonblocking rule: %s", tc.text)
					}
				})
			}
		})
	}
}

func TestUFWClose1332TCPWithRealNftListedFormatting(t *testing.T) {
	root := t.TempDir()
	nftState := filepath.Join(root, "nft-rules")
	t.Setenv("FWUI_NFT_RULES", nftState)
	t.Setenv("PATH", root)
	// UFW refuses to re-order the administrator's ALLOW at position 5.
	ufw := `#!/bin/sh
case "$*" in
 status) echo 'Status: active';;
 'status numbered')
   echo 'Status: active'
   echo '[ 1] 22/tcp ALLOW IN Anywhere'
   echo '[ 5] 1332/tcp ALLOW IN Anywhere'
   echo '[ 6] 1332/tcp (v6) ALLOW IN Anywhere (v6)';;
 'show added') echo "ufw allow 1332/tcp comment 'administrator'";;
 'prepend deny'*) exit 0;;
esac
`
	// Unlike old mocks, return nft's normalized live rule representation.
	// An input of "meta l4proto tcp th dport" is rendered "tcp dport"
	// and the counter displays live packet/byte totals.
	nft := `#!/bin/sh
case "$*" in
 'list tables')
   if [ -f "$FWUI_NFT_RULES" ]; then echo 'table inet firewall_ui_containers'; fi;;
 'list chain inet firewall_ui_containers input')
   /bin/sed -e 's/meta l4proto tcp th dport/tcp dport/g' \
     -e 's/counter drop/counter packets 0 bytes 0 drop/g' "$FWUI_NFT_RULES";;
 '-f -') /bin/cat > "$FWUI_NFT_RULES";;
 'delete table inet firewall_ui_containers') /bin/rm -f "$FWUI_NFT_RULES";;
esac
`
	for path, content := range map[string]string{"ufw": ufw, "nft": nft} {
		if err := os.WriteFile(filepath.Join(root, path), []byte(content), 0755); err != nil {
			t.Fatal(err)
		}
	}
	Configure(filepath.Join(root, "state.json"), 8088, 443)
	svc := &FirewallService{}
	ctx := context.Background()
	rules, err := svc.SetPortClosedSafe(ctx, 1332, "tcp", true, 8088)
	if err != nil || len(rules) != 1 {
		t.Fatalf("failed to block 1332/tcp with nft-normalized input chain: %v, %+v", err, rules)
	}
	if err := verifyNftInputClose(ctx, rules[0]); err != nil {
		t.Fatalf("live kernel verifier rejected blocked 1332/tcp: %v", err)
	}
	backend, err := detectManagedFirewallBackend(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := syncUFWAdvancedRulesLocked(ctx, backend); err != nil {
		t.Fatalf("background sync required UFW rule despite working nft DROP: %v", err)
	}
	if _, err := svc.SetPortClosedSafe(ctx, 1332, "tcp", true, 8088); err != nil {
		t.Fatalf("repeated close failed: %v", err)
	}
	if _, err := svc.SetPortClosedSafe(ctx, 1332, "tcp", false, 8088); err != nil {
		t.Fatalf("reopening port failed: %v", err)
	}
	if _, err := os.Stat(nftState); !os.IsNotExist(err) {
		t.Fatalf("INPUT drop still present after reopening: %v", err)
	}
}
