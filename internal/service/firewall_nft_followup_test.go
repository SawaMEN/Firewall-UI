package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNFTContainerApplyRequiresLiveHookAndCloses(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		closed    bool
	}{
		{"empty", `{"nftables":[]}`, false},
		{"invalid", `{}`, false},
		{"read failure", ``, false},
		{"wrong hook", strings.Replace(closedPortNFTFixture("tcp", 1332), `"hook":"forward"`, `"hook":"output"`, 1), true},
		{"missing close", strings.ReplaceAll(closedPortNFTFixture("tcp", 1332), `"right":1332`, `"right":13320`), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			Configure(filepath.Join(root, "state.json"), 8088, 0)
			t.Setenv("PATH", root)
			if err := (&SettingService{}).setBool(containerProtectionKey, true); err != nil {
				t.Fatal(err)
			}
			if tc.closed {
				if err := saveFirewallJSON(firewallAdvancedRulesKey, []FirewallAdvancedRule{{ID: closeRuleID(1332, "tcp"), Action: "deny", Protocol: "tcp", PortStart: 1332, PortEnd: 1332, IPVersion: "any", Priority: -1000}}); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("NFT_FOLLOWUP_RAW", filepath.Join(root, "raw"))
			if err := os.WriteFile(filepath.Join(root, "raw"), []byte(tc.raw), 0600); err != nil {
				t.Fatal(err)
			}
			for name, script := range map[string]string{
				"ufw": "#!/bin/sh\necho 'Status: active'\n",
				"nft": `#!/bin/sh
case "$*" in
 'list tables') :;;
 '-f -') /bin/cat >/dev/null;;
 '-j list table inet firewall_ui_containers') test -s "$NFT_FOLLOWUP_RAW" && /bin/cat "$NFT_FOLLOWUP_RAW";;
esac
`,
			} {
				if err := os.WriteFile(filepath.Join(root, name), []byte(script), 0755); err != nil {
					t.Fatal(err)
				}
			}
			oldDesired, oldObserved := containerPolicyHash, containerPolicyObservedHash
			containerPolicyHash, containerPolicyObservedHash = [32]byte{}, [32]byte{}
			t.Cleanup(func() { containerPolicyHash, containerPolicyObservedHash = oldDesired, oldObserved })
			svc := &FirewallService{PortMonitor: NewPortMonitor("/proc", time.Second)}
			if err := svc.SyncContainerProtection(context.Background()); err == nil {
				t.Fatal("unverified auxiliary policy reported success")
			}
			if containerPolicyHash != ([32]byte{}) || containerPolicyObservedHash != ([32]byte{}) {
				t.Fatal("unverified policy primed no-op cache")
			}
		})
	}
}

func TestNFTDisableRejectsSuccessfulNoopDelete(t *testing.T) {
	Configure(filepath.Join(t.TempDir(), "state.json"), 8088, 0)
	binary := auditCommand(t, "nft", `case "$*" in
 'list tables') echo 'table inet firewall_ui';;
 'delete table inet firewall_ui') :;;
esac
`)
	if err := disableManagedBackend(context.Background(), firewallBackend{name: "nftables", binary: binary}); err == nil || !strings.Contains(err.Error(), "remains") {
		t.Fatalf("noop disable accepted: %v", err)
	}
}

func TestNFTPredictionsRejectChangedOrUnverifiedSnapshots(t *testing.T) {
	raw := []byte(nativeNFTFixture("8088/tcp"))
	hash, err := normalizedNFTRulesetFingerprint(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyNFTSnapshotFingerprint(raw, hash); err != nil {
		t.Fatal(err)
	}
	if err := verifyNFTSnapshotFingerprint(raw, [32]byte{}); err == nil {
		t.Fatal("unverified snapshot accepted")
	}
	changed := []byte(strings.Replace(string(raw), `"accept":null`, `"drop":null`, 1))
	if err := verifyNFTSnapshotFingerprint(changed, hash); err == nil {
		t.Fatal("changed verdict accepted")
	}
	for _, raw := range []string{"null", "{}", `{"nftables":null}`, `{"nftables":{}}`} {
		if _, err := parseNFTTraffic([]byte(raw), managedNftTable); err == nil {
			t.Fatalf("invalid counters snapshot accepted: %s", raw)
		}
	}
}

func TestNFTAuxiliaryProtectsExplicitRequestPort(t *testing.T) {
	root := t.TempDir()
	Configure(filepath.Join(root, "state.json"), 8088, 0)
	t.Setenv("PATH", root)
	t.Setenv("NFT_FOLLOWUP_BATCH", filepath.Join(root, "batch"))
	if err := (&SettingService{}).setBool(containerProtectionKey, true); err != nil {
		t.Fatal(err)
	}
	for name, script := range map[string]string{
		"ufw": "#!/bin/sh\necho 'Status: active'\n",
		"nft": `#!/bin/sh
case "$*" in
 'list tables') :;;
 '-f -') /bin/cat > "$NFT_FOLLOWUP_BATCH";;
 '-j list table inet firewall_ui_containers') echo '{"nftables":[{"chain":{"family":"inet","table":"firewall_ui_containers","name":"forward","type":"filter","hook":"forward","prio":-50,"policy":"accept"}}]}';;
esac
`,
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
	}
	svc := &FirewallService{PortMonitor: NewPortMonitor("/proc", time.Second)}
	oldDesired, oldObserved := containerPolicyHash, containerPolicyObservedHash
	t.Cleanup(func() { containerPolicyHash, containerPolicyObservedHash = oldDesired, oldObserved })
	if err := svc.syncContainerProtectionLocked(context.Background(), 8443); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "batch"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "fwui-container-safety:8443/tcp") {
		t.Fatalf("request safety port lost: %s", raw)
	}
}

func TestNFTMarkedPolicyRequiresRulesOrderAndVerdicts(t *testing.T) {
	script := "table inet firewall_ui {\n chain input {\n counter drop comment \"fwui-advanced:first\"\n counter accept comment \"fwui-advanced:second\"\n }\n}"
	first := `{"rule":{"family":"inet","table":"firewall_ui","chain":"input","comment":"fwui-advanced:first","expr":[{"counter":{"packets":1}},{"drop":null}]}}`
	second := `{"rule":{"family":"inet","table":"firewall_ui","chain":"input","comment":"fwui-advanced:second","expr":[{"counter":{"packets":2}},{"accept":null}]}}`
	valid := `{"nftables":[` + first + `,` + second + `]}`
	if err := verifyNFTMarkedRules([]byte(valid), script, managedNftTable, "fwui-advanced:"); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`{"nftables":[]}`, `{"nftables":[` + second + `,` + first + `]}`, strings.Replace(valid, `"drop":null`, `"accept":null`, 1), strings.Replace(valid, `"chain":"input"`, `"chain":"output"`, 1)} {
		if err := verifyNFTMarkedRules([]byte(raw), script, managedNftTable, "fwui-advanced:"); err == nil {
			t.Fatalf("incomplete/reordered policy accepted: %s", raw)
		}
	}
}

func TestNFTForwardSafetyPredictionRequiresTheActualException(t *testing.T) {
	rule := FirewallRule{Port: 1332, Protocol: "tcp", Source: "session"}
	raw := strings.Replace(closedPortNFTFixture("tcp", 1332), "fwui-closed-port:close-port-1332-tcp", "fwui-container-safety:1332/tcp", 1)
	raw = strings.ReplaceAll(raw, `"drop":null`, `"accept":null`)
	if !nftForwardSafetyAllow([]byte(raw), rule) {
		t.Fatal("actual safety exception rejected")
	}
	rule.Port = 8443
	if nftForwardSafetyAllow([]byte(raw), rule) {
		t.Fatal("new request port invented a live safety exception")
	}
	rule.Port = 1332
	raw = strings.ReplaceAll(raw, `"right":1332`, `"right":13320`)
	if nftForwardSafetyAllow([]byte(raw), rule) {
		t.Fatal("marker alone invented a safety exception")
	}
}
