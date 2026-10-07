package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/SawaMEN/Firewall-UI/internal/appconfig"
)

func TestRuntimeSettingsPersistence(t *testing.T) {
	s := New("admin", "long-test-password", 8088, fstest.MapFS{})
	s.ConfigPath = filepath.Join(t.TempDir(), "config.json")

	login := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewBufferString(`{"username":"admin","password":"long-test-password"}`))
	login.RemoteAddr = "127.0.0.1:12345"
	loginResult := httptest.NewRecorder()
	s.ServeHTTP(loginResult, login)
	if loginResult.Code != http.StatusOK {
		t.Fatalf("login failed: %s", loginResult.Body.String())
	}
	cookies := loginResult.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("missing session cookie")
	}
	var loginBody struct {
		Obj struct {
			CSRF string `json:"csrf"`
		} `json:"obj"`
	}
	if err := json.Unmarshal(loginResult.Body.Bytes(), &loginBody); err != nil {
		t.Fatal(err)
	}

	body := `{"listenHost":"0.0.0.0","listenPort":8088,"externalPort":443,"secureCookies":true,"updateChannel":"dev"}`
	req := httptest.NewRequest(http.MethodPost, "/api/settings", bytes.NewBufferString(body))
	req.RemoteAddr = "127.0.0.1:12345"
	req.AddCookie(cookies[0])
	req.Header.Set("X-CSRF-Token", loginBody.Obj.CSRF)
	result := httptest.NewRecorder()
	s.ServeHTTP(result, req)
	if result.Code != http.StatusOK {
		t.Fatalf("settings failed: %s", result.Body.String())
	}

	cfg, err := appconfig.Load(s.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenHost != "0.0.0.0" || cfg.ListenPort != 8088 || cfg.ExternalPort != 443 || !cfg.SecureCookies || cfg.UpdateChannel != "dev" {
		t.Fatalf("unexpected saved config: %#v", cfg)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	getReq.RemoteAddr = "127.0.0.1:12345"
	getReq.AddCookie(cookies[0])
	getResult := httptest.NewRecorder()
	s.ServeHTTP(getResult, getReq)
	if getResult.Code != http.StatusOK {
		t.Fatalf("get settings failed: %s", getResult.Body.String())
	}
}
