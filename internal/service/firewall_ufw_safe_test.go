package service

import (
	"strings"
	"testing"
)

func TestFindUFWManagedRuleNumber(t *testing.T) {
	status := `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere                   # administrator
[ 2] 443/tcp                    ALLOW IN    Anywhere                   # Firewall-UI managed
[ 3] 443/tcp (v6)               ALLOW IN    Anywhere (v6)              # Firewall-UI managed
[ 4] Anywhere                   DENY IN     10.0.0.0/8                  # Firewall-UI advanced abc123
`
	if got := findUFWManagedRuleNumber(status, "Firewall-UI managed", "443/tcp"); got != 2 {
		t.Fatalf("managed 443 number = %d, want 2", got)
	}
	if got := findUFWManagedRuleNumber(status, "Firewall-UI managed", "22/tcp"); got != 0 {
		t.Fatalf("administrator rule matched as owned: %d", got)
	}
	if got := findUFWManagedRuleNumber(status, "Firewall-UI advanced abc123", ""); got != 4 {
		t.Fatalf("advanced rule number = %d, want 4", got)
	}
}

func TestParseUFWIncomingPolicy(t *testing.T) {
	cases := []struct {
		name, output, want string
	}{
		{"deny", "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n", "deny"},
		{"allow", "Status: active\nDefault: allow (incoming), deny (outgoing), disabled (routed)\n", "allow"},
		{"reject", "Default: reject (incoming), allow (outgoing)\n", "reject"},
		{"inactive", "Status: inactive\n", ""},
		{"missing", "Default: deny (outgoing), allow (routed)\n", ""},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := parseUFWIncomingPolicy(test.output); got != test.want {
				t.Fatalf("parseUFWIncomingPolicy(%q) = %q; want %q", test.output, got, test.want)
			}
		})
	}
}

func TestFindUFWPortDecisionWithoutComments(t *testing.T) {
	status := `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 1332/tcp                   DENY IN     Anywhere
[ 3] 1332/tcp                   ALLOW IN    Anywhere
[ 4] 1332/tcp (v6)              DENY IN     Anywhere (v6)
`
	if position, action := findUFWPortDecision(status, "1332/tcp"); position != 2 || action != "DENY" {
		t.Fatalf("port DENY with omitted comment = %d %s", position, action)
	}
	if position, action := findUFWPortDecision(status, "22/tcp"); position != 1 || action != "ALLOW" {
		t.Fatalf("allow port = %d %s", position, action)
	}
	status = strings.Replace(status, "[ 2] 1332/tcp                   DENY", "[ 2] 1332/tcp                   ALLOW", 1)
	if position, action := findUFWPortDecision(status, "1332/tcp"); position != 2 || action != "ALLOW" {
		t.Fatalf("earlier ALLOW must prevent a misleading DENY success: %d %s", position, action)
	}
}

func TestFindUFWPortDecisionIPv6Only(t *testing.T) {
	status := "Status: active\n[ 1] 1332/tcp (v6) DENY IN Anywhere (v6)\n"
	if pos, action := findUFWPortDecision(status, "1332/tcp"); pos != 1 || action != "DENY" {
		t.Fatalf("IPv6-only DENY = %d %s", pos, action)
	}
}

func TestUFWAdvancedOwnershipFromShowAdded(t *testing.T) {
	added := `Added user rules (see 'ufw status' for running firewall):
ufw deny to any port 1332 proto tcp comment 'Firewall-UI advanced close-port-1332-tcp'
ufw allow 22/tcp comment 'administrator'
`
	if !hasUFWAdvancedRule(added, "Firewall-UI advanced close-port-1332-tcp") {
		t.Fatal("missing advanced rule in normalized UFW show added")
	}
	if hasUFWAdvancedRule(added, "Firewall-UI advanced other") {
		t.Fatal("matched unrelated rule")
	}
}
