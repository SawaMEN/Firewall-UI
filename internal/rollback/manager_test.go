package rollback

import (
	"testing"
	"time"

	"github.com/SawaMEN/Firewall-UI/internal/service"
)

func TestConfirmStopsRollback(t *testing.T) {
	manager := NewManager()
	called := make(chan struct{}, 1)
	pending, err := manager.Begin(service.FirewallBackup{}, 20*time.Millisecond, func(service.FirewallBackup) {
		called <- struct{}{}
	})
	if err != nil {
		t.Fatal(err)
	}
	if !manager.Confirm(pending.Token) {
		t.Fatal("confirmation failed")
	}
	select {
	case <-called:
		t.Fatal("rollback ran after confirmation")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestRollbackRunsAfterDeadline(t *testing.T) {
	manager := NewManager()
	called := make(chan struct{}, 1)
	_, err := manager.Begin(service.FirewallBackup{}, 20*time.Millisecond, func(service.FirewallBackup) {
		called <- struct{}{}
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-called:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("rollback did not run")
	}
}

func TestPendingAndRunningRollbackCannotOverlap(t *testing.T) {
	manager := NewManager()
	started := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	pending, err := manager.Begin(service.FirewallBackup{}, 20*time.Millisecond, func(service.FirewallBackup) {
		close(started)
		<-release
	})
	if err != nil {
		t.Fatal(err)
	}
	if !manager.HasPending() {
		t.Fatal("pending transaction was not reported")
	}
	if _, err := manager.Begin(service.FirewallBackup{}, time.Second, nil); err == nil {
		t.Fatal("overlapping rollback was accepted")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("rollback did not start")
	}
	if !manager.HasPending() || manager.Confirm(pending.Token) {
		t.Fatal("running rollback was considered finished or confirmable")
	}
	if _, err := manager.Begin(service.FirewallBackup{}, time.Second, nil); err == nil {
		t.Fatal("new transaction was accepted during rollback execution")
	}
}
