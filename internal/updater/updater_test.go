package updater

import (
	"testing"

	"github.com/SawaMEN/Firewall-UI/internal/buildinfo"
)

func TestStableVersionNewer(t *testing.T) {
	tests := []struct {
		current string
		latest  string
		want    bool
	}{
		{"1.0.0", "1.0.0", false},
		{"1.0.0", "1.0.1", true},
		{"1.2.0", "1.10.0", true},
		{"2.0.0", "1.9.9", false},
		{"1.0", "1.0.0", false},
		{"dev", "1.0.0", true},
	}
	for _, tt := range tests {
		if got := stableVersionNewer(tt.current, tt.latest); got != tt.want {
			t.Fatalf("stableVersionNewer(%q, %q) = %v, want %v", tt.current, tt.latest, got, tt.want)
		}
	}
}

func TestStatusForChannels(t *testing.T) {
	oldVersion, oldChannel, oldCommit := buildinfo.Version, buildinfo.Channel, buildinfo.Commit
	defer func() {
		buildinfo.Version = oldVersion
		buildinfo.Channel = oldChannel
		buildinfo.Commit = oldCommit
	}()

	buildinfo.Version = "1.0.0"
	buildinfo.Channel = "stable"
	buildinfo.Commit = "abc"

	stable := statusFor("stable", Manifest{Version: "1.0.1", Channel: "stable", Commit: "def"})
	if !stable.Available {
		t.Fatal("newer stable release was not detected")
	}

	dev := statusFor("dev", Manifest{Version: "dev-def", Channel: "dev", Commit: "def"})
	if !dev.Available {
		t.Fatal("switching from stable to dev must install the dev build")
	}

	buildinfo.Version = "dev-def"
	buildinfo.Channel = "dev"
	buildinfo.Commit = "def"
	dev = statusFor("dev", Manifest{Version: "dev-def", Channel: "dev", Commit: "def"})
	if dev.Available {
		t.Fatal("same dev commit reported as an update")
	}
}

func TestValidateAsset(t *testing.T) {
	valid := Asset{
		URL:    "https://github.com/SawaMEN/Firewall-UI/releases/download/dev/firewall-ui-linux-amd64",
		SHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	if err := validateAsset(valid); err != nil {
		t.Fatal(err)
	}
	invalid := valid
	invalid.URL = "http://example.com/firewall-ui"
	if err := validateAsset(invalid); err == nil {
		t.Fatal("accepted insecure update URL")
	}
}
