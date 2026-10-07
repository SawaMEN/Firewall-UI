package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const step = 30 * time.Second

func GenerateTOTPSecret() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

func ProvisioningURI(secret, account, issuer string) string {
	label := url.PathEscape(strings.TrimSpace(issuer) + ":" + strings.TrimSpace(account))
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return "otpauth://totp/" + label + "?" + q.Encode()
}

func ValidateTOTP(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return false
		}
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil || len(key) == 0 {
		return false
	}
	counter := now.Unix() / int64(step/time.Second)
	for delta := int64(-1); delta <= 1; delta++ {
		if totpCode(key, counter+delta) == code {
			return true
		}
	}
	return false
}

func totpCode(key []byte, counter int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000)
}

func ValidateCIDRs(values []string) error {
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			return errors.New("allowed CIDR cannot be empty")
		}
		if net.ParseIP(value) != nil {
			continue
		}
		if _, _, err := net.ParseCIDR(value); err != nil {
			return fmt.Errorf("invalid allowed CIDR or IP %q", value)
		}
	}
	return nil
}

func IPAllowed(remoteAddr string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return false
	}
	for _, raw := range allowed {
		value := strings.TrimSpace(raw)
		if candidate := net.ParseIP(value); candidate != nil {
			if candidate.Equal(ip) {
				return true
			}
			continue
		}
		_, network, err := net.ParseCIDR(value)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func NormalizeCIDRs(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if ip := net.ParseIP(value); ip != nil {
			value = ip.String()
		} else if _, network, err := net.ParseCIDR(value); err == nil {
			value = network.String()
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func ParseRollbackSeconds(raw string, fallback int) int {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value < 15 || value > 300 {
		return fallback
	}
	return value
}
