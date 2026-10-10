package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func useFirewallPingTestPaths(t *testing.T, paths ...string) {
	t.Helper()
	previous := firewallPingSysctlPaths
	firewallPingSysctlPaths = paths
	t.Cleanup(func() {
		firewallPingSysctlPaths = previous
	})
}

func writePingTestFile(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestFirewallPingReadWriteIPv4AndIPv6(t *testing.T) {
	dir := t.TempDir()
	ipv4 := filepath.Join(dir, "ipv4")
	ipv6 := filepath.Join(dir, "ipv6")
	writePingTestFile(t, ipv4, "0")
	writePingTestFile(t, ipv6, "0")
	useFirewallPingTestPaths(t, ipv4, ipv6)

	enabled, err := readFirewallPingEnabled()
	if err != nil || !enabled {
		t.Fatalf("initial ping state = %v, %v; want enabled", enabled, err)
	}

	if err := writeFirewallPingEnabled(false); err != nil {
		t.Fatalf("disable ping: %v", err)
	}
	enabled, err = readFirewallPingEnabled()
	if err != nil || enabled {
		t.Fatalf("disabled ping state = %v, %v; want disabled", enabled, err)
	}

	if err := writeFirewallPingEnabled(true); err != nil {
		t.Fatalf("enable ping: %v", err)
	}
	enabled, err = readFirewallPingEnabled()
	if err != nil || !enabled {
		t.Fatalf("restored ping state = %v, %v; want enabled", enabled, err)
	}
}

func TestFirewallPingToleratesMissingIPv6Sysctl(t *testing.T) {
	dir := t.TempDir()
	ipv4 := filepath.Join(dir, "ipv4")
	writePingTestFile(t, ipv4, "0")
	useFirewallPingTestPaths(t, ipv4, filepath.Join(dir, "missing-ipv6"))

	if err := writeFirewallPingEnabled(false); err != nil {
		t.Fatalf("disable ping with IPv6 unavailable: %v", err)
	}
	raw, err := os.ReadFile(ipv4)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "1\n" {
		t.Fatalf("IPv4 sysctl = %q, want 1", raw)
	}
}

func TestFirewallPingDisabledIfEitherFamilyIgnoresEcho(t *testing.T) {
	dir := t.TempDir()
	ipv4 := filepath.Join(dir, "ipv4")
	ipv6 := filepath.Join(dir, "ipv6")
	writePingTestFile(t, ipv4, "0")
	writePingTestFile(t, ipv6, "1")
	useFirewallPingTestPaths(t, ipv4, ipv6)

	enabled, err := readFirewallPingEnabled()
	if err != nil {
		t.Fatal(err)
	}
	if enabled {
		t.Fatal("ping reported enabled while IPv6 echo replies are disabled")
	}
}

func TestPingPreferenceRespectsDisabledManagementWithActiveUFW(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ping")
	writePingTestFile(t, path, "0")
	useFirewallPingTestPaths(t, path)
	if err := os.WriteFile(filepath.Join(dir, "ufw"), []byte("#!/bin/sh\ncase \"$*\" in status*) echo 'Status: active';; esac\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	Configure(filepath.Join(dir, "state.json"), 8088, 0)
	if err := setFirewallManagedEnabledPreference(false); err != nil {
		t.Fatal(err)
	}
	s := &FirewallService{}
	ctx := context.Background()
	if _, err := s.SetManagedPingEnabledSafe(ctx, false, 8088); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReconcileManagedPingState(ctx, 8088); err != nil {
		t.Fatal(err)
	}
	if on, err := readFirewallPingEnabled(); err != nil || !on {
		t.Fatalf("disabled management applied ping ban: %v, %v", on, err)
	}
	if _, err := s.SetManagedEnabledSafe(ctx, true, 8088); err != nil {
		t.Fatal(err)
	}
	if on, err := readFirewallPingEnabled(); err != nil || on {
		t.Fatalf("enable did not apply saved ping ban: %v, %v", on, err)
	}
	if _, err := s.SetManagedEnabledSafe(ctx, false, 8088); err != nil {
		t.Fatal(err)
	}
	if on, err := readFirewallPingEnabled(); err != nil || !on {
		t.Fatalf("disable did not immediately restore ping: %v, %v", on, err)
	}
}
