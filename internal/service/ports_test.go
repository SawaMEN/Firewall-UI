package service

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestProcSocketAddresses(t *testing.T) {
	for _, test := range []struct {
		table, local, state, address string
		listening, loopback          bool
	}{
		{"tcp", "0100007F:1F98", "0A", "127.0.0.1", true, true},
		{"udp", "00000000:0035", "07", "0.0.0.0", true, false},
		{"tcp6", "00000000000000000000000001000000:01BB", "0A", "::1", true, true},
		{"tcp6", "0000000000000000FFFF00000100007F:01BB", "01", "127.0.0.1", false, true},
	} {
		t.Run(test.table+test.address, func(t *testing.T) {
			p, err := parseSocket(fmt.Sprintf("0: %s 00000000:0000 %s 00000000:00000000 00:00000000 00000000 1000 0 12345", test.local, test.state), test.table)
			if err != nil {
				t.Fatal(err)
			}
			if p.Address != test.address || p.Listening != test.listening || p.Loopback != test.loopback {
				t.Fatalf("unexpected socket: %+v", p)
			}
		})
	}
	if _, err := parseSocket("invalid", "tcp"); err == nil {
		t.Fatal("accepted invalid socket")
	}
}
func TestLivePortOwner(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	self, err := os.Readlink("/proc/self")
	if err != nil {
		t.Fatal(err)
	}
	selfPID, err := strconv.Atoi(self)
	if err != nil {
		t.Fatal(err)
	}
	ports, err := ReadPorts("/proc")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ports {
		if p.Port == listener.Addr().(*net.TCPAddr).Port && p.Protocol == "tcp" && p.Listening {
			for _, owner := range p.Processes {
				if owner.PID == selfPID {
					return
				}
			}
			t.Fatalf("listener has no current process owner: %+v", p)
		}
	}
	t.Fatal("live listener missing")
}
func TestSharedSocketOwners(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "net"), 0700)
	for _, table := range []string{"tcp", "udp"} {
		raw := "header\n"
		if table == "tcp" {
			raw += "0: 00000000:0050 00000000:0000 0A 0:0 0:0 0 0 0 42\n"
		}
		os.WriteFile(filepath.Join(root, "net", table), []byte(raw), 0600)
	}
	for _, pid := range []string{"100", "200"} {
		dir := filepath.Join(root, pid)
		os.MkdirAll(filepath.Join(dir, "fd"), 0700)
		os.WriteFile(filepath.Join(dir, "comm"), []byte("worker\n"), 0600)
		os.Symlink("socket:[42]", filepath.Join(dir, "fd", "3"))
		os.Symlink("socket:[42]", filepath.Join(dir, "fd", "4"))
	}
	ports, err := ReadPorts(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 1 || len(ports[0].Processes) != 2 {
		t.Fatalf("wrong shared owners: %+v", ports)
	}
}
func TestAutomaticRulesIgnoreLoopback(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	localPort := listener.Addr().(*net.TCPAddr).Port
	Configure(filepath.Join(t.TempDir(), "state.json"), 8088, 443)
	rules, err := (&FirewallService{}).desiredRules(true, 8088)
	if err != nil {
		t.Fatal(err)
	}
	protected := map[int]bool{}
	for _, r := range rules {
		protected[r.Port] = true
		if r.Port == localPort && r.Source == "service" {
			t.Fatal("loopback port automatically opened")
		}
	}
	if !protected[8088] || !protected[443] {
		t.Fatalf("panel ports not protected: %+v", rules)
	}
}
