package service

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCleanupFindsFinalNativeTableAndChain(t *testing.T) {
	root := t.TempDir()
	log := filepath.Join(root, "commands")
	t.Setenv("PATH", root)
	t.Setenv("FW_TEST_LOG", log)
	scripts := map[string]string{
		"nft": `#!/bin/sh
printf 'nft %s\n' "$*" >> "$FW_TEST_LOG"
case "$*" in
 'list tables') printf 'table inet foreign\ntable inet firewall_ui';;
esac
`,
		"iptables": `#!/bin/sh
printf 'iptables %s\n' "$*" >> "$FW_TEST_LOG"
case "$*" in
 '-S') printf '%s\n%s' '-P INPUT ACCEPT' '-N FIREWALL-UI';;
 '-C INPUT -j FIREWALL-UI') exit 1;;
esac
`,
		"ip6tables": `#!/bin/sh
echo 'Address family not supported by protocol' >&2
exit 3
`,
	}
	for name, script := range scripts {
		if err := os.WriteFile(filepath.Join(root, name), []byte(script), 0755); err != nil {
			t.Fatal(err)
		}
	}
	Configure(filepath.Join(root, "state.json"), 8088, 0)
	if err := (&FirewallService{}).CleanupOwnedRules(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"nft delete table inet firewall_ui", "iptables -F FIREWALL-UI", "iptables -X FIREWALL-UI"} {
		if !strings.Contains(string(raw), command) {
			t.Fatalf("missing cleanup %q: %s", command, raw)
		}
	}
	if strings.Contains(string(raw), "delete table inet foreign") {
		t.Fatal("foreign table deleted")
	}
}

func TestCleanupRejectsPermissionFailure(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PATH", root)
	if err := os.WriteFile(filepath.Join(root, "nft"), []byte("#!/bin/sh\necho 'Operation not permitted' >&2\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}
	Configure(filepath.Join(root, "state.json"), 8088, 0)
	if err := (&FirewallService{}).CleanupOwnedRules(context.Background()); err == nil {
		t.Fatal("permission error ignored")
	}
}

func TestCleanupDoesNotMatchForeignNames(t *testing.T) {
	if firewallOutputHasFields("table inet firewall_ui_backup", "table", "inet", managedNftTable) || firewallOutputHasFields("-N FIREWALL-UI-OTHER", "-N", managedIPTablesChain) {
		t.Fatal("foreign policy matched")
	}
}

func TestCleanupAbsentFirewalldRuleWithErrorOutput(t *testing.T) {
	root := t.TempDir()
	binary := filepath.Join(root, "firewall-cmd")
	// firewalld emits NOT_ENABLED on stderr as well as returning exit code 1.
	if err := os.WriteFile(binary, []byte("#!/bin/sh\necho 'NOT_ENABLED: rule not present' >&2\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}
	backend := firewallBackend{binary: binary, zone: "public", enabled: func(context.Context) (bool, error) { return true, nil }}
	if err := removeFirewalldRichRule(context.Background(), backend, `rule port port="9000" protocol="tcp" drop`); err != nil {
		t.Fatal(err)
	}
}

func TestOwnedUFWDeleteArgs(t *testing.T) {
	tests := []struct {
		line string
		want []string
	}{
		{"ufw allow 8443/tcp comment 'Firewall-UI access'", []string{"--force", "delete", "allow", "8443/tcp", "comment", "Firewall-UI access"}},
		{`ufw deny from 10.0.0.0/8 to any port 443 proto tcp comment 'Firewall-UI advanced abc123'`, []string{"--force", "delete", "deny", "from", "10.0.0.0/8", "to", "any", "port", "443", "proto", "tcp", "comment", "Firewall-UI advanced abc123"}},
		{`ufw allow 22/tcp comment 'Administrator SSH'`, nil},
		{`ufw allow 443/tcp comment 'Firewall-UI managed backup'`, nil},
		{`ufw allow 22/tcp`, nil},
		{`ufw allow --reset comment 'Firewall-UI access'`, nil},
		{"ufw allow 22/tcp comment 'Firewall-UI access'; ufw reset", nil},
	}
	for _, test := range tests {
		if got := ownedUFWDeleteArgs(test.line); !reflect.DeepEqual(got, test.want) {
			t.Errorf("%q: got %v, want %v", test.line, got, test.want)
		}
	}
}

func TestCleanupRestoresOwnedPingAndDoesNotCreateEmptyState(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PATH", root)
	ipv4 := filepath.Join(root, "icmp4")
	ipv6 := filepath.Join(root, "icmp6")
	writePingTestFile(t, ipv4, "1")
	writePingTestFile(t, ipv6, "1")
	useFirewallPingTestPaths(t, ipv4, ipv6)
	parent := filepath.Join(root, "missing-data")
	Configure(filepath.Join(parent, "state.json"), 8088, 0)
	if err := (&FirewallService{}).CleanupOwnedRules(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(parent); !os.IsNotExist(err) {
		t.Fatalf("cleanup created data folder: %v", err)
	}
	raw, _ := os.ReadFile(ipv4)
	if string(raw) != "1\n" {
		t.Fatal("unmanaged ping policy changed")
	}
	if err := (&SettingService{}).setBool(firewallPingEnabledKey, false); err != nil {
		t.Fatal(err)
	}
	if err := (&FirewallService{}).CleanupOwnedRules(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{ipv4, ipv6} {
		raw, err := os.ReadFile(path)
		if err != nil || string(raw) != "0\n" {
			t.Fatalf("ping ban remains: %s %s %v", path, raw, err)
		}
	}
}
