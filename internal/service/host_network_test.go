package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHostFirewallCommandPreservesStdin(t *testing.T) {
	root := t.TempDir()
	t.Setenv("FIREWALL_UI_CONTAINER", "1")
	t.Setenv("FIREWALL_UI_HOST_NETNS", "1")
	t.Setenv("PATH", root)
	script := `#!/bin/sh
printf '%s\n' "$*"
/bin/cat
`
	if err := os.WriteFile(filepath.Join(root, "nsenter"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	cmd := firewallCommand(context.Background(), "/sbin/nft", "-f", "-")
	cmd.Stdin = strings.NewReader("table inet firewall_ui {}")
	out, err := cmd.CombinedOutput()
	if err != nil || string(out) != "--net=/proc/1/ns/net -- /sbin/nft -f -\ntable inet firewall_ui {}" {
		t.Fatalf("namespace command lost arguments/stdin: %s %v", out, err)
	}
	// Access failures must not silently execute against the container firewall.
	if err := os.WriteFile(filepath.Join(root, "nsenter"), []byte("#!/bin/sh\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := CheckHostNetworkNamespace(context.Background()); err == nil {
		t.Fatal("namespace failure ignored")
	}
}

func TestProxyPortsReadHostTablesAndOwners(t *testing.T) {
	root := t.TempDir()
	t.Setenv("FIREWALL_UI_CONTAINER", "1")
	t.Setenv("FIREWALL_UI_HOST_NETNS", "1")
	for _, dir := range []string{"net", "1/net", "100/fd"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, table := range []string{"tcp", "udp"} {
		host := "header\n"
		container := "header\n"
		if table == "tcp" {
			host += "0: 00000000:01BB 00000000:0000 0A 0:0 0:0 0 0 0 42\n"
			container += "0: 00000000:1F98 00000000:0000 0A 0:0 0:0 0 0 0 99\n"
		}
		for file, raw := range map[string]string{filepath.Join(root, "1/net", table): host, filepath.Join(root, "net", table): container} {
			if err := os.WriteFile(file, []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.WriteFile(filepath.Join(root, "100/comm"), []byte("host-service\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[42]", filepath.Join(root, "100/fd/3")); err != nil {
		t.Fatal(err)
	}
	ports, err := ReadPorts(root)
	if err != nil || len(ports) != 1 || ports[0].Port != 443 || len(ports[0].Processes) != 1 || ports[0].Processes[0].PID != 100 {
		t.Fatalf("host ports/owners missing: %+v %v", ports, err)
	}
	if err := os.Remove(filepath.Join(root, "1/net/tcp")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPorts(root); err == nil {
		t.Fatal("silently fell back to container sockets")
	}
}

func TestProxyProtectsExternalPortWithoutOpeningInternalPort(t *testing.T) {
	t.Setenv("FIREWALL_UI_CONTAINER", "1")
	t.Setenv("FIREWALL_UI_HOST_NETNS", "1")
	// Avoid real sshd subprocesses: the actual SSH config remains read-only.
	t.Setenv("PATH", t.TempDir())
	Configure(filepath.Join(t.TempDir(), "state.json"), 8088, 443)
	rules, err := (&FirewallService{}).desiredRules(false, 8088)
	if err != nil {
		t.Fatal(err)
	}
	protected := false
	for _, rule := range rules {
		if rule.Port == 8088 {
			t.Fatal("internal-only HTTP port opened on host")
		}
		if rule.Port == 443 {
			protected = true
		}
	}
	if !protected {
		t.Fatal("proxy HTTPS port not protected")
	}
}
