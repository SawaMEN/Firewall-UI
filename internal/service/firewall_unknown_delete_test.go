package service

import (
	"strings"
	"testing"
)

func TestParseExternalUFWDestination(t *testing.T) {
	cases := []struct {
		raw  string
		from int
		to   int
		ok   bool
	}{
		{"ufw deny 1332/tcp", 1332, 1332, true},
		{"ufw allow from 192.0.2.0/24 to any port 1332 proto tcp", 1332, 1332, true},
		{"ufw allow 8000:8100/tcp in on eth0", 8000, 8100, true},
		{"ufw route deny from 192.0.2.0/24 to any port 2222 proto udp", 2222, 2222, true},
		{"ufw allow from 10.0.0.0/8", 0, 0, false},
		{"ufw deny to any", 0, 0, false},
		{"ufw allow from 10.0.0.0/8 port 1332 to any", 0, 0, false},
		{"ufw allow 8088/tcp comment 'Firewall-UI managed'", 0, 0, false},
		{"ufw allow 8088/tcp comment 'Firewall-UI access'", 0, 0, false},
		{"ufw allow 1332/tcp;rm", 0, 0, false},
		{"ufw -f delete 1332/tcp", 0, 0, false},
		{"ufw allow 1332/tcp\nufw deny 22", 0, 0, false},
	}
	for _, tc := range cases {
		start, end, args, err := parseExternalUFWDestination(tc.raw)
		if (err == nil) != tc.ok || (tc.ok && (start != tc.from || end != tc.to)) {
			t.Errorf("%q = %d..%d %v %v", tc.raw, start, end, args, err)
		}
		if tc.ok && (len(args) < 4 || args[0] != "--force" || args[1] != "delete") {
			t.Errorf("unexpected deletion arguments for %q: %v", tc.raw, args)
		}
	}
	if _, _, args, err := parseExternalUFWDestination("ufw allow from 192.0.2.0/24 to any port 1332 proto tcp comment 'External custom rule'"); err != nil ||
		strings.Join(args[len(args)-2:], "|") != "comment|External custom rule" {
		t.Fatalf("preserve external rule comment exactly: %v, %v", args, err)
	}
}

func TestExternalDeleteRejectsPanelSSHAndAmbiguousRules(t *testing.T) {
	safety := []FirewallRule{
		{Port: 22, Protocol: "tcp", Source: "ssh"},
		{Port: 8088, Protocol: "tcp", Source: "panel"},
		{Port: 443, Protocol: "tcp", Source: "session"},
	}
	for _, raw := range []string{
		"ufw allow 22/tcp in on eth0",
		"ufw deny 8088/tcp",
		"ufw route allow to any port 443 proto tcp",
		"ufw allow from 10.0.0.0/8",
		"ufw allow from 10.0.0.0/8 port 1332 to any",
	} {
		if removableExternalRule(raw, "ufw", safety) {
			t.Errorf("must not permit removal of potentially essential rule %q", raw)
		}
	}
	for _, raw := range []string{
		"ufw deny 1332/tcp",
		"ufw allow from 192.0.2.0/24 to any port 1332 proto tcp",
	} {
		if !removableExternalRule(raw, "ufw", safety) {
			t.Errorf("safe exact-port external rule unexpectedly rejected %q", raw)
		}
	}
}

func TestExternalFirewalldDeletionBounds(t *testing.T) {
	safety := []FirewallRule{{Port: 22, Protocol: "tcp", Source: "ssh"}, {Port: 8088, Protocol: "tcp", Source: "panel"}}
	rich := `rule family="ipv4" source address="10.0.0.0/8" port port="1332" protocol="tcp" accept`
	if !removableExternalRule(rich, "firewalld", safety) {
		t.Fatalf("should permit safe exact port rich rule")
	}
	if removableExternalRule(`rule port port="8000-8100" protocol="tcp" drop`, "firewalld", safety) {
		t.Fatalf("panel in range must protect rich rule")
	}
	if removableExternalRule(`rule service name="ssh" accept`, "firewalld", safety) {
		t.Fatalf("service-wide rich rule is ambiguous")
	}
	if removableExternalRule("rule\nport port=\"1332\" accept", "firewalld", safety) {
		t.Fatalf("reject multi-line rule injection")
	}
}
