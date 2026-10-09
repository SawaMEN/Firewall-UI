package server

import (
	"bytes"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/SawaMEN/Firewall-UI/internal/appconfig"
)

func TestLegacyTwoFactorSettingsDoNotPreventLogin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	// An old installation with 2FA enabled must start and accept its password.
	if err := os.WriteFile(path, []byte(`{"totpEnabled":true,"totpSecret":"JBSWY3DPEHPK3PXP"}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := appconfig.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	s := New("admin", "1", 8088, fstest.MapFS{})
	s.ConfigPath = path
	s.RuntimeConfig = cfg
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("POST", "/api/login", bytes.NewBufferString(`{"username":"admin","password":"1"}`)))
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	req := httptest.NewRequest("GET", "/api/security/totp/setup", nil)
	req.AddCookie(cookie)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Fatal("removed 2FA endpoint is still available")
	}
	if err := appconfig.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "totp") {
		t.Fatal("saved configuration retained legacy secrets")
	}
}
