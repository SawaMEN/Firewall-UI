package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/SawaMEN/Firewall-UI/internal/appconfig"
)

func TestXUISettingsPersistPreserveAndClearSecret(t *testing.T) {
	s := New("admin", "test", 8088, fstest.MapFS{})
	s.ConfigPath = filepath.Join(t.TempDir(), "config.json")
	send := func(body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.xuiSettings(w, httptest.NewRequest(http.MethodPost, "/api/integrations/3x-ui", strings.NewReader(body)))
		return w
	}
	for _, body := range []string{`{"enabled":true,"url":"http://127.0.0.1:2053/path/","token":"private-api-token"}`, `{"enabled":true,"url":"http://127.0.0.1:2053/path","token":""}`} {
		w := send(body)
		if w.Code != 200 || strings.Contains(w.Body.String(), "private-api-token") {
			t.Fatalf("save failed or secret disclosed: %s", w.Body.String())
		}
		cfg, err := appconfig.Load(s.ConfigPath)
		if err != nil || cfg.XUI.Token != "private-api-token" || !cfg.XUI.Enabled {
			t.Fatal("token not saved/preserved", err)
		}
	}
	w := httptest.NewRecorder()
	s.xuiSettings(w, httptest.NewRequest("GET", "/api/integrations/3x-ui", nil))
	if strings.Contains(w.Body.String(), "private-api-token") {
		t.Fatal("GET disclosed secret")
	}
	var view struct {
		Obj struct {
			TokenConfigured bool `json:"tokenConfigured"`
		}
	}
	_ = json.Unmarshal(w.Body.Bytes(), &view)
	if !view.Obj.TokenConfigured {
		t.Fatal("saved token status missing")
	}
	if send(`{"enabled":false,"url":"http://127.0.0.1:2053/path","clearToken":true}`).Code != 200 {
		t.Fatal("clear failed")
	}
	cfg, _ := appconfig.Load(s.ConfigPath)
	if cfg.XUI.Token != "" || cfg.XUI.Enabled {
		t.Fatal("token not removed")
	}
}

func TestXUIRoutesRequireSession(t *testing.T) {
	s := New("admin", "test", 8088, fstest.MapFS{})
	for _, path := range []string{"/api/integrations/3x-ui", "/api/integrations/3x-ui/test"} {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest("POST", path, strings.NewReader(`{}`)))
		if w.Code != 401 {
			t.Fatalf("unauthenticated access: %s %d", path, w.Code)
		}
	}
}
