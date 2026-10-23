package service

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func nativeNFTFixture(spec string) string {
	parts := strings.SplitN(spec, "/", 2)
	port := parts[0]
	if a, b, ok := strings.Cut(port, "-"); ok {
		port = `{"range":[` + a + `,` + b + `]}`
	}
	return `{"nftables":[{"chain":{"family":"inet","table":"firewall_ui","name":"input","type":"filter","hook":"input","prio":100,"policy":"drop"}},` +
		`{"rule":{"family":"inet","table":"firewall_ui","chain":"input","comment":"fwui-managed:` + spec + `","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"` + parts[1] + `","field":"dport"}},"right":` + port + `}},{"counter":{"packets":1,"bytes":64}},{"accept":null}]}}]}`
}

func TestNativeNFTStatusRequiresLiveHookAndExactAllows(t *testing.T) {
	for _, spec := range []string{"1332/tcp", "1332/udp", "8000-8100/tcp"} {
		raw := nativeNFTFixture(spec)
		active, allows, err := nativeNFTState([]byte(raw))
		if err != nil || !active || !allows[spec] {
			t.Fatalf("valid %s not recognized: %v %v %v", spec, active, allows, err)
		}
		for _, bad := range []string{
			strings.Replace(raw, `{"nftables":[`, `{"nftables":[{"table":{"family":"inet","name":"firewall_ui","flags":["dormant"]}},`, 1),
			strings.Replace(raw, `{"nftables":[`, `{"nftables":[{"table":{"family":"inet","name":"firewall_ui","flags":"dormant"}},`, 1),
			strings.Replace(raw, `{"nftables":[`, `{"nftables":[{"table":{"family":"inet","name":"firewall_ui","flags":"firewall_ui"}},`, 1),
			strings.Replace(raw, `"hook":"input"`, `"hook":"output"`, 1),
			strings.Replace(raw, `"policy":"drop"`, `"policy":"accept"`, 1),
			strings.Replace(raw, `"prio":100`, `"prio":0`, 1),
			`{"nftables":[]}`,
		} {
			active, _, err := nativeNFTState([]byte(bad))
			if err != nil || active {
				t.Fatalf("detached/wrong-policy table marked active: %s", bad)
			}
		}
		for _, bad := range []string{
			strings.Replace(raw, `"field":"dport"`, `"field":"sport"`, 1),
			strings.Replace(raw, `"accept":null`, `"drop":null`, 1),
			strings.Replace(raw, `{"accept":null}`, `{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"eth0"}},{"accept":null}`, 1),
		} {
			_, allows, err := nativeNFTState([]byte(bad))
			if err != nil || allows[spec] {
				t.Fatalf("incorrect ALLOW accepted: %s %v", bad, err)
			}
		}
	}
	for _, bad := range []string{"null", "{}", `{"nftables":null}`, `{"nftables":{}}`} {
		if _, _, err := nativeNFTState([]byte(bad)); err == nil {
			t.Fatalf("invalid policy JSON accepted: %s", bad)
		}
		if _, err := normalizedNFTRulesetFingerprint([]byte(bad)); err == nil {
			t.Fatalf("invalid fingerprint accepted: %s", bad)
		}
	}
}

func TestNFTRangeAllowDoesNotAcceptSinglePort(t *testing.T) {
	var doc nftPolicySnapshot
	if err := json.Unmarshal([]byte(nativeNFTFixture("8000/tcp")), &doc); err != nil {
		t.Fatal(err)
	}
	if nftAllowExpressionsMatch(doc.Nftables[1].Rule.Expr, FirewallRule{PortRange: "8000-8100", Protocol: "tcp"}) {
		t.Fatal("one port claimed full range coverage")
	}
}

func TestNativeFrozenRulesCannotReintroduceClosedAllows(t *testing.T) {
	root := t.TempDir()
	Configure(filepath.Join(root, "state.json"), 8088, 0)
	if err := (&SettingService{}).setBool(firewallAutoSyncKey, false); err != nil {
		t.Fatal(err)
	}
	if err := saveFirewallJSON(firewallManagedRulesKey, []FirewallRule{{Port: 1332, Protocol: "tcp", Source: "service", Owned: true}}); err != nil {
		t.Fatal(err)
	}
	rule := FirewallAdvancedRule{ID: closeRuleID(1332, "tcp"), Action: "deny", Protocol: "tcp", PortStart: 1332, PortEnd: 1332, IPVersion: "any", Priority: -1000}
	if err := saveFirewallJSON(firewallAdvancedRulesKey, []FirewallAdvancedRule{rule}); err != nil {
		t.Fatal(err)
	}
	batch := filepath.Join(root, "batch")
	t.Setenv("AUDIT_BATCH", batch)
	binary := auditCommand(t, "nft", `case "$*" in
 '-j list ruleset') echo '{"nftables":[]}';;
 'list tables') :;;
 '-f -') /bin/cat > "$AUDIT_BATCH"; echo 'stop after capture' >&2; exit 2;;
esac
`)
	_ = (&FirewallService{}).syncManagedSafeLocked(context.Background(), firewallBackend{name: "nftables", binary: binary}, 8088)
	raw, err := os.ReadFile(batch)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `fwui-managed:1332/tcp`) || !strings.Contains(string(raw), `fwui-advanced:close-port-1332-tcp`) {
		t.Fatalf("closed frozen port reopened: %s", raw)
	}
}

func TestBackupCannotCloseCurrentPanelOrSSH(t *testing.T) {
	root := t.TempDir()
	Configure(filepath.Join(root, "state.json"), 8088, 443)
	t.Setenv("PATH", t.TempDir())
	for _, port := range []int{8088, 443, 22, 8443} {
		rule := FirewallAdvancedRule{ID: closeRuleID(port, "tcp"), Action: "deny", Protocol: "tcp", PortStart: port, PortEnd: port, IPVersion: "any", Priority: -1000}
		before, _ := os.ReadFile(statePath)
		err := (&FirewallService{}).RestoreBackup(context.Background(), FirewallBackup{Version: 1, AdvancedRules: []FirewallAdvancedRule{rule}}, 8443)
		after, _ := os.ReadFile(statePath)
		if err == nil || !strings.Contains(err.Error(), "protected") || string(before) != string(after) {
			t.Fatalf("unsafe backup changed state for %d: %v", port, err)
		}
	}
}

func TestContainerProtectionStatusDoesNotConfuseExplicitCloseWithOptIn(t *testing.T) {
	root := t.TempDir()
	Configure(filepath.Join(root, "state.json"), 8088, 0)
	binary := auditCommand(t, "nft", `echo 'table inet firewall_ui_containers'`)
	t.Setenv("PATH", filepath.Dir(binary))
	status, err := (&FirewallService{}).ContainerProtectionStatus(context.Background())
	if err != nil || status.Enabled || status.Active {
		t.Fatalf("disabled broad container protection shown active: %+v %v", status, err)
	}
}

func TestNFTInspectDoesNotPredictSavedCloseWithoutKernelEvidence(t *testing.T) {
	root := t.TempDir()
	Configure(filepath.Join(root, "state.json"), 8088, 0)
	script := `#!/bin/sh
case "$*" in
 'list table inet firewall_ui') echo 'table inet firewall_ui {}';;
 '-j list table inet firewall_ui') echo '` + nativeNFTFixture("8088/tcp") + `';;
 '-j list table inet firewall_ui_containers') echo '{"nftables":[]}';;
esac
`
	if err := os.WriteFile(filepath.Join(root, "nft"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root)
	rule := FirewallAdvancedRule{ID: closeRuleID(1332, "tcp"), Action: "deny", Protocol: "tcp", PortStart: 1332, PortEnd: 1332, IPVersion: "any", Priority: -1000}
	if err := saveFirewallJSON(firewallAdvancedRulesKey, []FirewallAdvancedRule{rule}); err != nil {
		t.Fatal(err)
	}
	svc := &FirewallService{PortMonitor: NewPortMonitor("/proc", time.Second)}
	svc.PortMonitor.snapshot.Containers = []ContainerPort{{HostPort: 1332, Protocol: "tcp", Public: true}}
	diagnosis, err := svc.InspectAccess(context.Background(), 8088, AccessProbe{SourceIP: "192.0.2.1", Port: 1332, Protocol: "tcp"})
	if err != nil || diagnosis.Verdict != "unknown" || !strings.Contains(diagnosis.Reason, "no verified") {
		t.Fatalf("unverified saved close claimed blocked: %+v %v", diagnosis, err)
	}
}

func TestNFTNoopWriteCannotReportSuccessfulPolicy(t *testing.T) {
	Configure(filepath.Join(t.TempDir(), "state.json"), 8088, 0)
	binary := auditCommand(t, "nft", `case "$*" in
 '-j list ruleset'|'-j list table inet firewall_ui') echo '{"nftables":[]}';;
 'list tables') :;;
 '-f -') /bin/cat >/dev/null;;
esac
`)
	err := applyManagedNftables(context.Background(), binary, []FirewallRule{{Port: 8088, Protocol: "tcp", Source: "panel"}})
	if err == nil || !strings.Contains(err.Error(), "INPUT hook") {
		t.Fatalf("no-op native apply claimed success: %v", err)
	}
}

func TestNativeBackupMigratesLiveEnabledStateWhenPreferenceIsAbsent(t *testing.T) {
	root := t.TempDir()
	Configure(filepath.Join(root, "state.json"), 8088, 0)
	binary := auditCommand(t, "nft", `case "$*" in
 'list table inet firewall_ui') echo 'table inet firewall_ui {}';;
esac
`)
	t.Setenv("PATH", filepath.Dir(binary))
	ping := filepath.Join(root, "ping")
	if err := os.WriteFile(ping, []byte("0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	previous := firewallPingSysctlPaths
	firewallPingSysctlPaths = []string{ping}
	t.Cleanup(func() { firewallPingSysctlPaths = previous })
	backup, err := (&FirewallService{}).ExportBackup()
	if err != nil || !backup.ManagedEnabled {
		t.Fatalf("active native firewall backed up as disabled: %+v %v", backup, err)
	}
}

func TestDormantNFTCloseTableIsNotEnforced(t *testing.T) {
	raw := strings.Replace(closedPortNFTFixture("tcp", 1332), `{"nftables":[`, `{"nftables":[{"table":{"family":"inet","name":"firewall_ui_containers","flags":["dormant"]}},`, 1)
	rule := FirewallAdvancedRule{ID: closeRuleID(1332, "tcp"), Action: "deny", Protocol: "tcp", PortStart: 1332, PortEnd: 1332, IPVersion: "any", Priority: -1000}
	for _, raw := range []string{raw, strings.Replace(raw, `["dormant"]`, `"dormant"`, 1), strings.Replace(raw, `["dormant"]`, `"firewall_ui_containers"`, 1)} {
		if err := verifyNFTClosedPortJSON([]byte(raw), rule); err == nil {
			t.Fatal("dormant table claimed packet enforcement")
		}
	}
}

func TestContainerForwardPreservesPanelBeforeBroadDeny(t *testing.T) {
	script := buildContainerForwardRules([]ContainerPort{{HostPort: 8088, Protocol: "tcp", Public: true}}, nil,
		[]FirewallAdvancedRule{{ID: "broad", Action: "deny", Protocol: "any", IPVersion: "any", Priority: -900}},
		FirewallRule{Port: 8088, Protocol: "tcp", Source: "panel"})
	safe := strings.Index(script, `fwui-container-safety:8088/tcp`)
	deny := strings.Index(script, `fwui-container-rule:broad`)
	if safe < 0 || deny < 0 || safe > deny {
		t.Fatalf("panel FORWARD access can be shadowed: %s", script)
	}
}

func TestNFTDisableCleansAuxiliaryDespiteForeignHook(t *testing.T) {
	root := t.TempDir()
	Configure(filepath.Join(root, "state.json"), 8088, 0)
	t.Setenv("PATH", root)
	if err := setFirewallManagedEnabledPreference(false); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(root, "calls")
	t.Setenv("NFT_AUDIT_DISABLE_LOG", logPath)
	script := `#!/bin/sh
echo "$*" >> "$NFT_AUDIT_DISABLE_LOG"
case "$*" in
 'list table inet firewall_ui') exit 1;;
 '-j list ruleset') echo '{"nftables":[{"chain":{"family":"inet","table":"administrator","name":"input","hook":"input"}}]}';;
 'list tables') echo 'table inet administrator'; echo 'table inet firewall_ui_containers';;
 'delete table inet firewall_ui_containers') :;;
esac
`
	if err := os.WriteFile(filepath.Join(root, "nft"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	if err := (&FirewallService{}).SyncContainerProtection(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "delete table inet firewall_ui_containers") || strings.Contains(string(raw), "delete table inet administrator") {
		t.Fatalf("unsafe/incomplete cleanup: %s", raw)
	}
}

func TestNFTUnconditionalAdvancedRulesKeepCounters(t *testing.T) {
	for _, action := range []string{"allow", "deny"} {
		t.Run(action, func(t *testing.T) {
			root := t.TempDir()
			Configure(filepath.Join(root, "state.json"), 8088, 0)
			if err := saveFirewallJSON(firewallAdvancedRulesKey, []FirewallAdvancedRule{{ID: "all", Action: action, Protocol: "any", IPVersion: "any", Priority: 100}}); err != nil {
				t.Fatal(err)
			}
			batch := filepath.Join(root, "batch")
			t.Setenv("NFT_COUNTER_BATCH", batch)
			binary := auditCommand(t, "nft", `case "$*" in
 '-j list ruleset') echo '{"nftables":[]}';;
 'list tables') :;;
 '-f -') /bin/cat > "$NFT_COUNTER_BATCH"; exit 2;;
esac
`)
			_ = applyManagedNftables(context.Background(), binary, nil)
			raw, err := os.ReadFile(batch)
			if err != nil {
				t.Fatal(err)
			}
			verdict := "accept"
			if action == "deny" {
				verdict = "drop"
			}
			if !strings.Contains(string(raw), `counter `+verdict+` comment "fwui-advanced:all"`) {
				t.Fatalf("unconditional rule lost counter/identity: %s", raw)
			}
		})
	}
}
