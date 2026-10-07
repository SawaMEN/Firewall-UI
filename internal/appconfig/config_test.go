package appconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg := Default()
	cfg.ListenHost = "0.0.0.0"
	cfg.ListenPort = 9090
	cfg.ExternalPort = 443
	cfg.SecureCookies = true

	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("permissions = %o, want 600", info.Mode().Perm())
	}

	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != cfg {
		t.Fatalf("loaded config = %#v, want %#v", got, cfg)
	}
}

func TestLoadMissingUsesDefaults(t *testing.T) {
	got, err := Load(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := Default()
	if got != want {
		t.Fatalf("config = %#v, want %#v", got, want)
	}
}

func TestValidateRejectsUnsafeValues(t *testing.T) {
	cfg := Default()
	cfg.ListenHost = "not an ip"
	if err := Validate(cfg); err == nil {
		t.Fatal("accepted invalid listen host")
	}

	cfg = Default()
	cfg.ListenPort = 70000
	if err := Validate(cfg); err == nil {
		t.Fatal("accepted invalid listen port")
	}

	cfg = Default()
	cfg.TLSCert = "/tmp/cert.pem"
	if err := Validate(cfg); err == nil {
		t.Fatal("accepted incomplete TLS configuration")
	}
}
