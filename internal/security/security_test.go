package security

import (
	"testing"
	"time"
)

func TestTOTPValidation(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	key, err := base32NoPaddingDecode(secret)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	code := totpCode(key, now.Unix()/30)
	if !ValidateTOTP(secret, code, now) {
		t.Fatal("valid TOTP rejected")
	}
	if ValidateTOTP(secret, "000000", now) && code != "000000" {
		t.Fatal("invalid TOTP accepted")
	}
}

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

func base32NoPaddingDecode(value string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(value)
}
