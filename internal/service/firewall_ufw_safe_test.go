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

func TestUFWPortDecisionSeparatesIPv4AndIPv6(t *testing.T) {
	status := `Status: active
[ 1] 1332/udp DENY IN Anywhere
[ 2] 22/tcp (v6) ALLOW IN Anywhere (v6)
[ 3] 1332/udp (v6) ALLOW IN Anywhere (v6)
[ 4] 1332/udp (v6) DENY IN Anywhere (v6)
`
	if pos, action := findUFWPortDecisionFamily(status, "1332/udp", false); pos != 1 || action != "DENY" {
		t.Fatalf("IPv4 first match = %d %s", pos, action)
	}
	if pos, action := findUFWPortDecisionFamily(status, "1332/udp", true); pos != 3 || action != "ALLOW" {
		t.Fatalf("IPv6 ALLOW must not be hidden by IPv4 DENY: %d %s", pos, action)
	}
}

func TestUFWDecisionDoesNotIgnoreEarlierPortRangeAllow(t *testing.T) {
	status := "Status: active\n[ 1] 1300:1400/udp ALLOW IN Anywhere\n[ 2] 1332/udp DENY IN Anywhere\n"
	if position, action := findUFWPortDecisionFamily(status, "1332/udp", false); position != 1 || action != "ALLOW" {
		t.Fatalf("port range ALLOW shadows specific DENY: got %d %s", position, action)
	}
}

func TestUFWDecisionDoesNotIgnoreGlobalAllowOrScopedRules(t *testing.T) {
	cases := []struct {
		name, status, action string
		position             int
	}{
		{"global allow", "Status: active\n[ 1] Anywhere ALLOW IN Anywhere\n[ 2] 1332/udp DENY IN Anywhere\n", "ALLOW", 1},
		{"scoped deny", "Status: active\n[ 1] 1332/udp DENY IN 10.0.0.0/8\n[ 2] 1332/udp ALLOW IN Anywhere\n", "ALLOW", 2},
		{"scoped allow", "Status: active\n[ 1] 1332/udp ALLOW IN 10.0.0.0/8\n[ 2] 1332/udp DENY IN Anywhere\n", "ALLOW", 1},
		{"unrelated protocol", "Status: active\n[ 1] 1300:1400/tcp ALLOW IN Anywhere\n[ 2] 1332/udp DENY IN Anywhere\n", "DENY", 2},
		{"unrelated range", "Status: active\n[ 1] 1400:1500/udp ALLOW IN Anywhere\n[ 2] 1332/udp DENY IN Anywhere\n", "DENY", 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pos, action := findUFWPortDecisionFamily(c.status, "1332/udp", false)
			if pos != c.position || action != c.action {
				t.Fatalf("decision = %d %s; expected %d %s", pos, action, c.position, c.action)
			}
		})
	}
}

func TestNftInputClosedPortMatchesKernelNormalizedRules(t *testing.T) {
	tcp := FirewallAdvancedRule{
		ID: closeRuleID(1332, "tcp"), Action: "deny", Protocol: "tcp",
		PortStart: 1332, PortEnd: 1332, IPVersion: "any", Priority: -1000,
	}
	udp := tcp
	udp.ID = closeRuleID(1332, "udp")
	udp.Protocol = "udp"
	const header = "table inet firewall_ui_containers {\n chain input {\n type filter hook input priority mangle; policy accept;\n"
	const end = " }\n}\n"
	cases := []struct {
		name string
		rule FirewallAdvancedRule
		listing string
		want bool
	}{
		{"normalized tcp", tcp, header + `tcp dport 1332 counter packets 0 bytes 0 drop comment "fwui-closed-input:close-port-1332-tcp"` + "\n" + end, true},
		{"normalized udp", udp, header + `udp dport 1332 counter packets 4 bytes 200 drop comment "fwui-closed-input:close-port-1332-udp"` + "\n" + end, true},
		{"original tcp", tcp, header + `meta l4proto tcp th dport 1332 counter packets 0 bytes 0 drop comment "fwui-closed-input:close-port-1332-tcp"` + "\n" + end, true},
		{"wrong protocol", tcp, header + `udp dport 1332 counter drop comment "fwui-closed-input:close-port-1332-tcp"` + "\n" + end, false},
		{"wrong port", tcp, header + `tcp dport 13321 counter drop comment "fwui-closed-input:close-port-1332-tcp"` + "\n" + end, false},
		{"wrong ownership", tcp, header + `tcp dport 1332 counter drop comment "another-rule"` + "\n" + end, false},
		{"missing verdict", tcp, header + `tcp dport 1332 counter accept comment "fwui-closed-input:close-port-1332-tcp"` + "\n" + end, false},
		{"unhooked chain", tcp, `table inet firewall_ui_containers { chain input { tcp dport 1332 drop comment "fwui-closed-input:close-port-1332-tcp" } }`, false},
		{"protocol only in comment", tcp, header + `th dport 1332 drop comment "fwui-closed-input:close-port-1332-tcp meta l4proto tcp"` + "\n" + end, false},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := nftInputHasCloseDrop(test.listing, test.rule); got != test.want {
				t.Fatalf("nftInputHasCloseDrop() = %v, want %v for %q", got, test.want, test.listing)
			}
		})
	}
}
