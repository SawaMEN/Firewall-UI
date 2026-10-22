package service

import "testing"

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
