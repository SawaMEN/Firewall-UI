package hostexec

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestHostCommandKeepsArgumentsAndEntersHostRoot(t *testing.T) {
	t.Setenv("FIREWALL_UI_CONTAINER", "1")
	t.Setenv("FIREWALL_UI_HOST_FIREWALL", "1")
	bin := t.TempDir()
	stub := "#!/bin/sh\nprintf '/usr/sbin/ufw\\n'\n"
	if err := os.WriteFile(filepath.Join(bin, "nsenter"), []byte(stub), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	path, err := LookPath("ufw")
	if err != nil || path != "/usr/sbin/ufw" {
		t.Fatalf("host lookup: %q, %v", path, err)
	}
	cmd := CommandContext(context.Background(), path, "allow", "443/tcp", "comment", "label with $ and spaces")
	want := []string{"nsenter", "--target", "1", "--mount", "--root", "--wd", "--", "/usr/bin/env", "LC_ALL=C", "LANG=C", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "/usr/sbin/ufw", "allow", "443/tcp", "comment", "label with $ and spaces"}
	if !reflect.DeepEqual(cmd.Args, want) {
		t.Fatalf("namespace command lost literal arguments: %q", cmd.Args)
	}
}

func TestNativeCommandsDoNotEnterHost(t *testing.T) {
	t.Setenv("FIREWALL_UI_CONTAINER", "")
	t.Setenv("FIREWALL_UI_HOST_FIREWALL", "1")
	cmd := CommandContext(context.Background(), "/bin/echo", "hello")
	if Enabled() || strings.Contains(strings.Join(cmd.Args, " "), "nsenter") {
		t.Fatal("native command unexpectedly entered a namespace")
	}
}
