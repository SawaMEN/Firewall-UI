package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func TestCredentialRotationPersistsAndRevokesSessions(t *testing.T) {
	s := New("admin", "old", 8088, fstest.MapFS{})
	s.ConfigPath = filepath.Join(t.TempDir(), "config.json")
	send := func(path, body, csrf string, cookie *http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", path, bytes.NewBufferString(body))
		req.RemoteAddr = "127.0.0.1:3456"
		if cookie != nil {
			req.AddCookie(cookie)
		}
		req.Header.Set("X-CSRF-Token", csrf)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		return w
	}
	login := send("/api/login", `{"username":"admin","password":"old"}`, "", nil)
	cookie := login.Result().Cookies()[0]
	var response struct {
		Obj struct {
			CSRF string `json:"csrf"`
		}
	}
	if err := json.Unmarshal(login.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	good := `{"username":"user","password":"1","currentPassword":"old"}`
	if w := send("/api/security/credentials", good, "", cookie); w.Code != 403 {
		t.Fatal("missing CSRF accepted")
	}
	if w := send("/api/security/credentials", `{"username":"user","password":"1","currentPassword":"wrong"}`, response.Obj.CSRF, cookie); w.Code != 403 {
		t.Fatal("wrong current password accepted")
	}
	if w := send("/api/security/credentials", good, response.Obj.CSRF, cookie); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(s.ConfigPath), "environment"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `FIREWALL_UI_PASSWORD="1"`) || !strings.Contains(string(raw), `FIREWALL_UI_USERNAME="user"`) {
		t.Fatal("credentials not persisted")
	}
	info, _ := os.Stat(filepath.Join(filepath.Dir(s.ConfigPath), "environment"))
	if info.Mode().Perm() != 0600 {
		t.Fatal("unsafe permissions")
	}
	if w := send("/api/security/credentials", good, response.Obj.CSRF, cookie); w.Code != 401 {
		t.Fatal("old session survived")
	}
	if w := send("/api/login", `{"username":"admin","password":"old"}`, "", nil); w.Code != 401 {
		t.Fatal("old credentials accepted")
	}
	if w := send("/api/login", `{"username":"user","password":"1"}`, "", nil); w.Code != 200 {
		t.Fatal("new simple password rejected")
	}
}

func TestCredentialSaveFailureKeepsLogin(t *testing.T) {
	s := New("admin", "old", 8088, fstest.MapFS{})
	s.ConfigPath = filepath.Join(t.TempDir(), "missing", "config.json")
	req := httptest.NewRequest("POST", "/api/security/credentials", strings.NewReader(`{"username":"new","password":"1","currentPassword":"old"}`))
	w := httptest.NewRecorder()
	s.credentials(w, req)
	if w.Code != 500 || s.Username != "admin" || s.Password != "old" {
		t.Fatal("failed persistence changed authentication")
	}
}

func TestPortAccessRequiresExplicitAction(t *testing.T) {
	s := New("admin", "old", 8088, fstest.MapFS{})
	req := httptest.NewRequest("POST", "/api/firewall/port", strings.NewReader(`{"port":9000,"protocol":"tcp"}`))
	w := httptest.NewRecorder()
	s.setPortAccess(w, req)
	if w.Code != 400 {
		t.Fatal("missing action opened a port")
	}
}
