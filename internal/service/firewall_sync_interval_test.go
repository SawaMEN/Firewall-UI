package service

import (
	"path/filepath"
	"testing"
	"time"
)

func TestFirewallSyncIntervalSettings(t *testing.T) {
	Configure(filepath.Join(t.TempDir(), "state.json"), 8088, 0)
	svc := &FirewallService{}
	if got := svc.syncInterval(); got != time.Minute {
		t.Fatalf("default sync interval = %s, want 1m", got)
	}
	for _, seconds := range []int{30, 60, 120, 300, 600} {
		if err := svc.SetSyncIntervalSeconds(seconds); err != nil {
			t.Fatal(err)
		}
		if got, err := svc.SyncIntervalSeconds(); err != nil || got != seconds {
			t.Fatalf("saved sync interval = %d, %v, want %d", got, err, seconds)
		}
	}
	for _, seconds := range []int{-1, 0, 1, 5, 10, 61, 3600} {
		if err := svc.SetSyncIntervalSeconds(seconds); err == nil {
			t.Fatalf("accepted unsafe sync interval %d", seconds)
		}
	}
}
