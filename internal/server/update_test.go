package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SawaMEN/Firewall-UI/internal/buildinfo"
	"github.com/SawaMEN/Firewall-UI/internal/updater"
)

func TestHealthReportsRunningBuildWithoutSession(t *testing.T) {
	s := New("admin", "1", 8088, nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("health unavailable or cached: %d, %s", w.Code, w.Body)
	}
	var result struct {
		Success bool           `json:"success"`
		Obj     buildinfo.Info `json:"obj"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || !result.Success || result.Obj != buildinfo.Current() {
		t.Fatalf("health did not report the running build: %+v, %v", result, err)
	}
	w = httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/health", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatal("health accepted POST", w.Code)
	}
}

func TestDockerCannotReplaceContainerBinary(t *testing.T) {
	s := New("admin", "1", 8088, nil)
	s.ContainerMode = true
	s.Updater = updater.New(nil)
	w := httptest.NewRecorder()
	s.applyUpdate(w, httptest.NewRequest(http.MethodPost, "/api/update/apply", nil))
	if w.Code != http.StatusConflict {
		t.Fatal("Docker self-update was not rejected", w.Code)
	}
}
