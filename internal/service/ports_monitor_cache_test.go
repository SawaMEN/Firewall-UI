package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPortMonitorDoesNotInspectContainersOnEverySocketScan(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "net"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6"} {
		if err := os.WriteFile(filepath.Join(root, "net", name), []byte("header\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	bin := t.TempDir()
	calls := filepath.Join(root, "calls")
	t.Setenv("PATH", bin)
	t.Setenv("CONTAINER_CALLS", calls)
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\nprintf 'inspect\\n' >> \"$CONTAINER_CALLS\"\nprintf '%s\\n' '{\"ID\":\"a\",\"Names\":\"web\",\"Image\":\"web\",\"Ports\":\"0.0.0.0:8443->443/tcp\"}'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	monitor := NewPortMonitor(root, time.Second)
	monitor.refresh(context.Background())
	monitor.refresh(context.Background())
	monitor.refresh(context.Background())
	raw, err := os.ReadFile(calls)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(raw), "inspect") != 1 || len(monitor.Snapshot().Containers) != 1 {
		t.Fatal("container inspection is repeated or cached publications were lost")
	}
	monitor.containerScanAfter = time.Now().Add(-time.Second)
	monitor.refresh(context.Background())
	raw, _ = os.ReadFile(calls)
	if strings.Count(string(raw), "inspect") != 2 {
		t.Fatal("expired container inspection was not refreshed")
	}
}
