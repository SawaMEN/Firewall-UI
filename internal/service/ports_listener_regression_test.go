package service

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestAutoSyncUsesListenerEvenWhenOwnerLookupFails(t *testing.T) {
	Configure(filepath.Join(t.TempDir(), "state.json"), 8088, 0)
	monitor := NewPortMonitor("/proc", time.Second)
	monitor.snapshot = PortSnapshot{UpdatedAt: time.Now(), Ports: []Port{
		{Port: 1332, Protocol: "tcp", Listening: true},
		{Port: 1332, Protocol: "udp", Listening: true},
		{Port: 9000, Protocol: "tcp", Listening: true, Loopback: true},
		{Port: 9001, Protocol: "tcp", Listening: false},
	}}
	svc := &FirewallService{PortMonitor: monitor}
	rules, err := svc.managedDesiredRules(true, 8088)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range rules {
		seen[firewallRuleSpec(r)] = true
	}
	if !seen["1332/tcp"] || !seen["1332/udp"] || seen["9000/tcp"] || seen["9001/tcp"] {
		t.Fatalf("incorrect listener policy: %+v", rules)
	}
	close := FirewallAdvancedRule{ID: closeRuleID(1332, "tcp"), Action: "deny", Protocol: "tcp", PortStart: 1332, PortEnd: 1332, IPVersion: "any", Priority: -1000}
	if err := saveFirewallJSON(firewallAdvancedRulesKey, []FirewallAdvancedRule{close}); err != nil {
		t.Fatal(err)
	}
	rules, err = svc.managedDesiredRules(true, 8088)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if firewallRuleSpec(r) == "1332/tcp" {
			t.Fatal("listener observation reopened explicitly closed port")
		}
	}
}

func TestPortMonitorPublishesNewTCPAndUDPListeners(t *testing.T) {
	// Socket monitoring must work independently of firewall backend detection.
	t.Setenv("PATH", t.TempDir())
	monitor := NewPortMonitor("/proc", time.Second)
	monitor.refresh(context.Background())
	ch, cancel := monitor.Subscribe()
	defer cancel()
	<-ch
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	monitor.refresh(context.Background())
	var snapshot PortSnapshot
	select {
	case snapshot = <-ch:
	case <-time.After(time.Second):
		t.Fatal("new listeners were not published")
	}
	tcpPort := tcp.Addr().(*net.TCPAddr).Port
	udpPort := udp.LocalAddr().(*net.UDPAddr).Port
	foundTCP, foundUDP := false, false
	for _, p := range snapshot.Ports {
		foundTCP = foundTCP || p.Port == tcpPort && p.Protocol == "tcp" && p.Listening
		foundUDP = foundUDP || p.Port == udpPort && p.Protocol == "udp" && p.Listening
	}
	if !foundTCP || !foundUDP {
		t.Fatalf("listener scan missing TCP=%v UDP=%v", foundTCP, foundUDP)
	}
	tcp.Close()
	udp.Close()
	monitor.refresh(context.Background())
	select {
	case snapshot = <-ch:
	case <-time.After(time.Second):
		t.Fatal("closed listeners were not published")
	}
	for _, p := range snapshot.Ports {
		if p.Listening && (p.Port == tcpPort && p.Protocol == "tcp" || p.Port == udpPort && p.Protocol == "udp") {
			t.Fatal("closed socket remained in listener view")
		}
	}
}
