package appconfig

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg := Default()
	cfg.ListenHost = "0.0.0.0"
	cfg.ListenPort = 9090
	cfg.ExternalPort = 443
	cfg.SecureCookies = true
	cfg.UpdateChannel = "dev"

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
	if !reflect.DeepEqual(got, cfg) {
		t.Fatalf("loaded config = %#v, want %#v", got, cfg)
	}
}

func TestLoadMissingUsesDefaults(t *testing.T) {
	got, err := Load(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := Default()
	if !reflect.DeepEqual(got, want) {
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
	cfg.UpdateChannel = "nightly"
	if err := Validate(cfg); err == nil {
		t.Fatal("accepted invalid update channel")
	}

	cfg = Default()
	cfg.TLSCert = "/tmp/cert.pem"
	if err := Validate(cfg); err == nil {
		t.Fatal("accepted incomplete TLS configuration")
	}
}

func TestTLSFilesAreValidated(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	cert := server.TLS.Certificates[0]
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfg := Default()
	cfg.TLSCert = filepath.Join(dir, "cert.pem")
	cfg.TLSKey = filepath.Join(dir, "key.pem")
	os.WriteFile(cfg.TLSCert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600)
	os.WriteFile(cfg.TLSKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600)
	if err := Validate(cfg); err != nil {
		t.Fatalf("valid TLS pair rejected: %v", err)
	}
	cfg.PublicHost = "127.0.0.1"
	if err := Validate(cfg); err != nil {
		t.Fatalf("matching IP SAN rejected: %v", err)
	}
	cfg.PublicHost = "wrong-panel.invalid"
	if err := Validate(cfg); err == nil {
		t.Fatal("certificate accepted for an unrelated hostname")
	}
	cfg.PublicHost = ""
	os.WriteFile(cfg.TLSKey, []byte("invalid key"), 0600)
	if err := Validate(cfg); err == nil {
		t.Fatal("invalid TLS key accepted")
	}
	cfg.TLSCert = "relative.pem"
	if err := Validate(cfg); err == nil {
		t.Fatal("relative TLS path accepted")
	}
}

func TestPublicConnectionHosts(t *testing.T) {
	for _, host := range []string{"panel.example.com", "203.0.113.10", "2001:db8::1"} {
		cfg := Default()
		cfg.PublicHost = host
		if err := Validate(cfg); err != nil {
			t.Fatalf("host %s rejected: %v", host, err)
		}
	}
	for _, host := range []string{"0.0.0.0", "::", "https://panel.example.com", "panel.example.com:443", "192.0.2.999", "-panel.example.com", "panel..com", "panel.example.com/path"} {
		cfg := Default()
		cfg.PublicHost = host
		if err := Validate(cfg); err == nil {
			t.Fatalf("invalid public host accepted: %s", host)
		}
	}
}
