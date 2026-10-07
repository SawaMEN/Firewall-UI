package service

import (
	"strings"
	"testing"
)

func TestValidateAdvancedRule(t *testing.T) {
	rule := FirewallAdvancedRule{
		Action:     "deny",
		Protocol:   "tcp",
		PortStart:  1000,
		PortEnd:    2000,
		SourceCIDR: "10.0.0.4/8",
		Interface:  "eth0",
		IPVersion:  "any",
		Priority:   10,
	}
	if err := validateAdvancedRule(&rule); err != nil {
		t.Fatal(err)
	}
	if rule.SourceCIDR != "10.0.0.0/8" || rule.IPVersion != "ipv4" {
		t.Fatalf("rule was not normalized: %#v", rule)
	}
	expr := advancedNFTExpression(rule)
	for _, part := range []string{"iifname", "10.0.0.0/8", "tcp", "1000-2000", "drop"} {
		if !strings.Contains(expr, part) {
			t.Fatalf("nft expression %q is missing %q", expr, part)
		}
	}
}

func TestAdvancedRuleRejectsUnsafeValues(t *testing.T) {
	tests := []FirewallAdvancedRule{
		{Action: "reject", Protocol: "tcp"},
		{Action: "allow", Protocol: "icmp", Priority: 1},
		{Action: "allow", Protocol: "any", PortStart: 443},
		{Action: "allow", Protocol: "tcp", PortStart: 9000, PortEnd: 8000},
		{Action: "allow", Protocol: "tcp", Interface: "eth0;rm"},
		{Action: "allow", Protocol: "tcp", SourceCIDR: "not-a-cidr"},
	}
	for _, rule := range tests {
		copy := rule
		if err := validateAdvancedRule(&copy); err == nil {
			t.Fatalf("accepted invalid rule: %#v", rule)
		}
	}
}

func TestSafetyRuleDetection(t *testing.T) {
	for _, source := range []string{"panel", "session", "ssh"} {
		if !isFirewallSafetyRule(FirewallRule{Source: source}) {
			t.Fatalf("%s should be a safety source", source)
		}
	}
	if isFirewallSafetyRule(FirewallRule{Source: "service"}) {
		t.Fatal("service rule must not bypass advanced deny rules")
	}
}
