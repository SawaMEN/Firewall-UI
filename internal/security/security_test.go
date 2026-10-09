package security

import (
	"testing"
)

func TestIPAllowed(t *testing.T) {
	allowed := []string{"127.0.0.1", "10.0.0.0/8", "2001:db8::/32"}
	tests := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:1234", true},
		{"10.2.3.4:443", true},
		{"192.0.2.2:443", false},
		{"[2001:db8::10]:443", true},
	}
	for _, test := range tests {
		if got := IPAllowed(test.addr, allowed); got != test.want {
			t.Fatalf("IPAllowed(%q) = %v, want %v", test.addr, got, test.want)
		}
	}
}
