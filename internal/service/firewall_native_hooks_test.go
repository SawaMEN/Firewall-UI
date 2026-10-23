package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeNFTAllowsOnlyItsOwnCloseHook(t *testing.T) {
	for _, tc := range []struct {
		name, chain string
		safe        bool
	}{
		{"owned close hook", `{"family":"inet","table":"firewall_ui_containers","name":"input","type":"filter","hook":"input","prio":-50,"policy":"accept"}`, true},
		{"foreign hook", `{"family":"inet","table":"administrator","name":"input","type":"filter","hook":"input","prio":0,"policy":"drop"}`, false},
		{"foreign chain in owned table", `{"family":"inet","table":"firewall_ui_containers","name":"extra","type":"filter","hook":"input","prio":-50,"policy":"accept"}`, false},
		{"changed close priority", `{"family":"inet","table":"firewall_ui_containers","name":"input","type":"filter","hook":"input","prio":0,"policy":"accept"}`, false},
		{"changed close policy", `{"family":"inet","table":"firewall_ui_containers","name":"input","type":"filter","hook":"input","prio":-50,"policy":"drop"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			binary := filepath.Join(root, "nft")
			raw := `{"nftables":[{"chain":` + tc.chain + `}]}`
			script := "#!/bin/sh\nprintf '%s' '" + raw + "'\n"
			if err := os.WriteFile(binary, []byte(script), 0755); err != nil {
				t.Fatal(err)
			}
			safe, err := nftablesSafeForManagedFirewall(context.Background(), binary)
			if err != nil || safe != tc.safe {
				t.Fatalf("safe=%v err=%v, want %v", safe, err, tc.safe)
			}
		})
	}
}

func TestNativeNFTConflictPreservesWorkingPolicy(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "nft")
	logPath := filepath.Join(root, "calls")
	t.Setenv("FWUI_HOOK_LOG", logPath)
	script := `#!/bin/sh
echo "$*" >> "$FWUI_HOOK_LOG"
case "$*" in
 '-j list ruleset') echo '{"nftables":[{"chain":{"family":"inet","table":"administrator","name":"input","hook":"input"}}]}';;
 'list tables') echo 'table inet firewall_ui';;
esac
`
	if err := os.WriteFile(binary, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	if err := applyManagedNftables(context.Background(), binary, nil); err == nil {
		t.Fatal("foreign hook must reject policy change")
	}
	calls, _ := os.ReadFile(logPath)
	if strings.Contains(string(calls), "delete") || strings.Contains(string(calls), "-f -") {
		t.Fatalf("conflict removed working protection: %s", calls)
	}
}

func TestNativeNFTCloseReopenAndRecovery(t *testing.T) {
	for _, proto := range []string{"tcp", "udp"} {
		t.Run(proto, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("PATH", root)
			t.Setenv("FWUI_HOOK_ROOT", root)
			Configure(filepath.Join(root, "state.json"), 8088, 0)
			pingPath := filepath.Join(root, "ping")
			if err := os.WriteFile(pingPath, []byte("0\n"), 0600); err != nil {
				t.Fatal(err)
			}
			previousPingPaths := firewallPingSysctlPaths
			firewallPingSysctlPaths = []string{pingPath}
			t.Cleanup(func() { firewallPingSysctlPaths = previousPingPaths })
			if err := os.WriteFile(filepath.Join(root, "main"), []byte("owned main policy"), 0600); err != nil {
				t.Fatal(err)
			}
			fixture := strings.ReplaceAll(closedPortNFTFixture(proto, 1332), `"prio":-50}`, `"prio":-50,"policy":"accept"}`)
			if err := os.WriteFile(filepath.Join(root, "closed.json"), []byte(fixture), 0600); err != nil {
				t.Fatal(err)
			}
			script := `#!/bin/sh
case "$*" in
 'list table inet firewall_ui') test -f "$FWUI_HOOK_ROOT/main";;
 'list tables')
  if test -f "$FWUI_HOOK_ROOT/main"; then echo 'table inet firewall_ui'; fi
  if test -f "$FWUI_HOOK_ROOT/aux"; then echo 'table inet firewall_ui_containers'; fi;;
 '-j list ruleset')
  if test -f "$FWUI_HOOK_ROOT/aux"; then /bin/cat "$FWUI_HOOK_ROOT/closed.json"; else echo '{"nftables":[]}'; fi;;
 '-j list table inet firewall_ui_containers') test -f "$FWUI_HOOK_ROOT/aux" && /bin/cat "$FWUI_HOOK_ROOT/closed.json";;
 '-j list table inet firewall_ui') echo '{"nftables":[]}';;
 '-f -')
  /bin/cat > "$FWUI_HOOK_ROOT/batch"
  if /bin/grep -q 'table inet firewall_ui {' "$FWUI_HOOK_ROOT/batch"; then
   /bin/cp "$FWUI_HOOK_ROOT/batch" "$FWUI_HOOK_ROOT/main"
  else
   /bin/cp "$FWUI_HOOK_ROOT/batch" "$FWUI_HOOK_ROOT/aux"
  fi;;
 'delete table inet firewall_ui_containers') /bin/rm -f "$FWUI_HOOK_ROOT/aux";;
 'delete table inet firewall_ui') /bin/rm -f "$FWUI_HOOK_ROOT/main";;
esac
`
			if err := os.WriteFile(filepath.Join(root, "nft"), []byte(script), 0755); err != nil {
				t.Fatal(err)
			}
			svc := &FirewallService{}
			ctx := context.Background()
			for _, closed := range []bool{true, true, false, true} {
				if _, err := svc.SetPortClosedSafe(ctx, 1332, proto, closed, 8088); err != nil {
					t.Fatalf("closed=%v: %v", closed, err)
				}
				if _, err := os.Stat(filepath.Join(root, "main")); err != nil {
					t.Fatalf("main protection disappeared: %v", err)
				}
				if closed {
					live, err := svc.AdvancedRulesLive(ctx)
					if err != nil || len(live) != 1 || live[0].Enforced == nil || !*live[0].Enforced {
						t.Fatalf("native close not verified: %+v %v", live, err)
					}
				}
			}
			// Reproduce recovery from the old bug: only the owned close hook remains.
			if err := os.Remove(filepath.Join(root, "main")); err != nil {
				t.Fatal(err)
			}
			if _, err := svc.SetManagedEnabledSafe(ctx, true, 8088); err != nil {
				t.Fatalf("cannot recover with owned hook still installed: %v", err)
			}
			if _, err := svc.SetPortClosedSafe(ctx, 1332, proto, false, 8088); err != nil {
				t.Fatalf("cannot reopen after recovery: %v", err)
			}
		})
	}
}
