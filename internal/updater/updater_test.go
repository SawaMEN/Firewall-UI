package updater

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"runtime"
	"strings"
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
		URL:    "https://github.com/SawaMEN/Firewall-UI/releases/download/dev/firewall-ui-linux-" + runtime.GOARCH,
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
	for _, url := range []string{
		"https://github.com/another/repository/releases/download/dev/firewall-ui-linux-" + runtime.GOARCH,
		valid.URL + "?download=1",
		valid.URL + "#asset",
		"https://user@github.com/SawaMEN/Firewall-UI/releases/download/dev/firewall-ui-linux-" + runtime.GOARCH,
		"https://github.com/SawaMEN/Firewall-UI/blob/main/firewall-ui-linux-" + runtime.GOARCH,
		valid.URL + "/../other",
	} {
		invalid.URL = url
		if err := validateAsset(invalid); err == nil {
			t.Fatalf("accepted unexpected asset: %s", url)
		}
	}
}

type manifestTransport func(*http.Request) (*http.Response, error)

func (f manifestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestManifestRejectsTrailingAndOversizedData(t *testing.T) {
	manifest := Manifest{Version: "1.3.1", Commit: "abc", Channel: "stable", Assets: map[string]Asset{
		runtime.GOARCH: {URL: "https://github.com/SawaMEN/Firewall-UI/releases/download/v1.3.1/firewall-ui-linux-" + runtime.GOARCH, SHA256: strings.Repeat("a", 64)},
	}}
	raw, _ := json.Marshal(manifest)
	for _, suffix := range []string{" {}", " garbage", strings.Repeat(" ", maxManifestSize)} {
		m := New(nil)
		m.client.Transport = manifestTransport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(raw) + suffix))}, nil
		})
		if _, err := m.fetchManifest(context.Background(), "stable"); err == nil {
			t.Fatal("accepted trailing or oversized manifest data")
		}
	}
}

func TestCheckCacheAndProgress(t *testing.T) {
	calls := 0
	m := New(nil)
	m.client.Transport = manifestTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		manifest := Manifest{Version: "9.0.0", Channel: "stable", Commit: "next", Assets: map[string]Asset{
			runtime.GOARCH: {URL: "https://github.com/SawaMEN/Firewall-UI/releases/download/v9.0.0/firewall-ui-linux-" + runtime.GOARCH, SHA256: strings.Repeat("a", 64)},
		}}
		body, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
	})
	for i := 0; i < 3; i++ {
		status, err := m.Check(context.Background(), "stable")
		if err != nil || status.LatestVersion != "9.0.0" {
			t.Fatalf("check: %+v, %v", status, err)
		}
	}
	if calls != 1 {
		t.Fatalf("repeated checks fetched %d manifests", calls)
	}
	m.mu.Lock()
	m.applying = true
	m.progress = Status{Applying: true, Phase: "downloading", LatestVersion: "9.0.0"}
	m.mu.Unlock()
	status, err := m.Check(context.Background(), "stable")
	if err != nil || !status.Applying || status.Phase != "downloading" || calls != 1 {
		t.Fatalf("progress check fetched metadata or lost progress: %+v, %v", status, err)
	}
	m.mu.Lock()
	m.applying = false
	m.progress = Status{Restarting: true, Phase: "restarting"}
	m.mu.Unlock()
	if _, err := m.Apply(context.Background(), "stable"); err == nil {
		t.Fatal("accepted a second update during restart")
	}
}
