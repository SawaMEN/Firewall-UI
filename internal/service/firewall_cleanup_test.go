package service

import (
	"reflect"
	"testing"
)

func TestOwnedUFWDeleteArgs(t *testing.T) {
	tests := []struct {
		line string
		want []string
	}{
		{"ufw allow 8443/tcp comment 'Firewall-UI access'", []string{"--force", "delete", "allow", "8443/tcp", "comment", "Firewall-UI access"}},
		{`ufw deny from 10.0.0.0/8 to any port 443 proto tcp comment 'Firewall-UI advanced abc123'`, []string{"--force", "delete", "deny", "from", "10.0.0.0/8", "to", "any", "port", "443", "proto", "tcp", "comment", "Firewall-UI advanced abc123"}},
		{`ufw allow 22/tcp comment 'Administrator SSH'`, nil},
		{`ufw allow 443/tcp comment 'Firewall-UI managed backup'`, nil},
		{`ufw allow 22/tcp`, nil},
		{`ufw allow --reset comment 'Firewall-UI access'`, nil},
		{"ufw allow 22/tcp comment 'Firewall-UI access'; ufw reset", nil},
	}
	for _, test := range tests {
		if got := ownedUFWDeleteArgs(test.line); !reflect.DeepEqual(got, test.want) {
			t.Errorf("%q: got %v, want %v", test.line, got, test.want)
		}
	}
}
