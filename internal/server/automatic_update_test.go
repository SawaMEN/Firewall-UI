package server

import (
	"context"
	"github.com/SawaMEN/Firewall-UI/internal/service"
	"github.com/SawaMEN/Firewall-UI/internal/updater"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func TestAutomaticUpdateRespectsRollbackAndSelectedChannel(t *testing.T) {
	s := New("admin", "1", 8088, fstest.MapFS{})
	s.Updater = updater.New(nil)
	s.RuntimeConfig.UpdateChannel = "dev"
	pending, err := s.Rollbacks.Begin(service.FirewallBackup{}, time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Rollbacks.Confirm(pending.Token)
	if _, err := s.ApplyAutomaticUpdate(context.Background(), "dev"); err == nil {
		t.Fatal("automatic update interrupted rollback")
	}
	s.Rollbacks.Confirm(pending.Token)
	s.RuntimeConfig.UpdateChannel = "stable"
	if _, err := s.ApplyAutomaticUpdate(context.Background(), "dev"); err == nil {
		t.Fatal("automatic update ignored changed channel")
	}
}

func TestLocalHealthProbeCanCheckRollbackUnderCIDRRestriction(t *testing.T) {
	s := New("admin", "1", 8088, fstest.MapFS{})
	s.RuntimeConfig.AllowedCIDRs = []string{"192.0.2.0/24"}
	pending, err := s.Rollbacks.Begin(service.FirewallBackup{}, time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Rollbacks.Confirm(pending.Token)
	for _, remote := range []string{"127.0.0.1:1234", "[::1]:1234", "198.51.100.1:1234"} {
		r := httptest.NewRequest("GET", "/api/health", nil)
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if remote == "198.51.100.1:1234" {
			if w.Code != 403 {
				t.Fatal("remote CIDR restriction bypassed")
			}
			continue
		}
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"rollbackPending":true`) {
			t.Fatalf("local probe unavailable: %d %s", w.Code, w.Body.String())
		}
	}
}
