package security

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

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
	if len(values) == 0 {
		return nil
	}
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
	if len(out) == 0 {
		return nil
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
