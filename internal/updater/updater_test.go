package updater

import (
	"strings"
	"testing"
)

func TestChecksumFor(t *testing.T) {
	raw := []byte(strings.Repeat("a", 64) + "  firewall-ui-linux-amd64\n")
	got, err := checksumFor(raw, "firewall-ui-linux-amd64")
	if err != nil {
		t.Fatal(err)
	}
	if got != strings.Repeat("a", 64) {
		t.Fatalf("checksum = %q", got)
	}
	if _, err := checksumFor(raw, "firewall-ui-linux-arm64"); err == nil {
		t.Fatal("missing checksum accepted")
	}
}

func TestAvailable(t *testing.T) {
	oldVersion, oldCommit, oldChannel := Version, Commit, BuildChannel
	defer func() {
		Version, Commit, BuildChannel = oldVersion, oldCommit, oldChannel
	}()

	Version = "1.0"
	Commit = "abc"
	BuildChannel = "stable"

	if Available(Manifest{Version: "1.0", Commit: "abc", Channel: "stable"}) {
		t.Fatal("identical build reported as update")
	}
	if !Available(Manifest{Version: "dev-def", Commit: "def", Channel: "dev"}) {
		t.Fatal("different build not reported as update")
	}
}
