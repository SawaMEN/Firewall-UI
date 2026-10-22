package service

import "testing"

func TestUnknownUFWRuleClassification(t *testing.T) {
	cases := []struct {
		line string
		unknown bool
		canClose bool
		port int
	}{
		{"ufw allow 1332/tcp", false, false, 0},
		{"ufw allow to any port 1332 proto udp", false, false, 0},
		{"ufw allow from 192.0.2.0/24 to any port 1332 proto tcp", true, true, 1332},
		{"ufw allow 1332/tcp in on eth0", true, true, 1332},
		{"ufw allow to any port 8000:8100 proto tcp", true, false, 0},
		{"ufw deny 1332/tcp", true, false, 0},
		{"ufw route allow 1332/tcp", true, false, 0},
		{"ufw allow from 10.0.0.0/8", true, false, 0},
		{"ufw allow 22", true, false, 0},
		{"Random output", false, false, 0},
	}
	for _, tc := range cases {
		item, ok := unknownUFWRule(tc.line)
		if ok != tc.unknown || (ok && (item.CanClose != tc.canClose || item.Port != tc.port)) {
			t.Errorf("%q => %+v, %v", tc.line, item, ok)
		}
	}
}
