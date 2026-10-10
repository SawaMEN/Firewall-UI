package server

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
	"time"

	"github.com/SawaMEN/Firewall-UI/internal/appconfig"
	"github.com/SawaMEN/Firewall-UI/internal/service"
)

func TestSlowLoginDoesNotLockConfiguration(t *testing.T) {
	s := New("admin", "1", 8088, fstest.MapFS{})
	reader, writer := io.Pipe()
	r := httptest.NewRequest("POST", "/api/login", reader)
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.ServeHTTP(httptest.NewRecorder(), r)
	}()
	defer func() { writer.Close(); <-done }()
	// Wait until the reader is actually blocked in JSON decoding.
	if _, err := writer.Write([]byte(`{"username":`)); err != nil {
		t.Fatal(err)
	}
	locked := make(chan struct{})
	go func() { s.configMu.Lock(); s.configMu.Unlock(); close(locked) }()
	select {
	case <-locked:
	case <-time.After(time.Second):
		t.Fatal("an incomplete login request blocked configuration")
	}
}

func TestOriginRequiresSameSchemeAndAuthority(t *testing.T) {
	for _, origin := range []string{"https://example.com", "http://user@example.com", "http://example.com/path", "http://example.com?query", "http://example.com#fragment"} {
		s := New("admin", "1", 8088, fstest.MapFS{})
		r := httptest.NewRequest("POST", "http://example.com/api/login", bytes.NewBufferString(`{"username":"admin","password":"1"}`))
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("accepted invalid origin %q: %d", origin, w.Code)
		}
	}
}

func TestFullLoginAttemptMapAllowsExistingClient(t *testing.T) {
	s := New("admin", "1", 8088, fstest.MapFS{})
	for i := 0; i < 4096; i++ {
		s.attempts[fmt.Sprintf("192.0.2.%d", i)] = attempt{count: 1, until: time.Now().Add(time.Minute)}
	}
	newRequest := httptest.NewRequest("POST", "/api/login", bytes.NewBufferString(`{"username":"admin","password":"1"}`))
	newRequest.RemoteAddr = "198.51.100.1:1234"
	newResponse := httptest.NewRecorder()
	s.ServeHTTP(newResponse, newRequest)
	if newResponse.Code != http.StatusTooManyRequests || len(s.attempts) != 4096 {
		t.Fatal("login attempt map exceeded its capacity")
	}
	r := httptest.NewRequest("POST", "/api/login", bytes.NewBufferString(`{"username":"admin","password":"1"}`))
	r.RemoteAddr = "192.0.2.1:1234"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("existing client was globally locked out: %d", w.Code)
	}
	if len(s.attempts) != 4095 {
		t.Fatal("successful login did not clear its attempt entry")
	}
}

func TestRuntimeBackupPreservesInvalidCIDRsForValidation(t *testing.T) {
	cfg := applyRuntimeBackup(appconfig.Default(), runtimeBackup{
		ListenHost: "127.0.0.1", ListenPort: 8088, UpdateChannel: "stable",
		AllowedCIDRs: []string{" "}, RollbackSeconds: 45, PortScanInterval: 2,
	})
	if appconfig.Validate(cfg) == nil {
		t.Fatal("runtime backup silently disabled the access restriction")
	}
}

func TestMutationsRejectPendingRollbackBeforeChangingState(t *testing.T) {
	s := New("admin", "1", 8088, fstest.MapFS{})
	pending, err := s.Rollbacks.Begin(service.FirewallBackup{}, time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Rollbacks.Confirm(pending.Token)
	cases := []struct {
		path    string
		body    string
		handler func(http.ResponseWriter, *http.Request)
	}{
		{"/api/firewall/advanced", `{}`, s.advancedRules},
		{"/api/firewall/advanced/delete", `{"id":"one"}`, s.deleteAdvancedRule},
		{"/api/ports/access", `{"port":443,"protocol":"tcp","closed":true}`, s.setPortAccess},
		{"/panel/api/server/firewall/enabled", `{"enabled":true}`, s.manage},
	}
	for _, item := range cases {
		w := httptest.NewRecorder()
		item.handler(w, httptest.NewRequest("POST", item.path, bytes.NewBufferString(item.body)))
		if w.Code != http.StatusConflict {
			t.Fatalf("%s changed state before confirming the previous transaction: %d, %s", item.path, w.Code, w.Body)
		}
	}
}
