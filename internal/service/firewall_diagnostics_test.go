package service

import (
	"strings"
	"testing"
)

func TestContainerForwardRulesMatchOriginalDNATPort(t *testing.T) {
	ports := []ContainerPort{
		{Protocol: "tcp", HostIP: "0.0.0.0", HostPort: 8080, Public: true},
		{Protocol: "tcp", HostIP: "127.0.0.1", HostPort: 9090, Public: false},
	}
	script := buildContainerForwardRules(ports, nil, nil)
	if !strings.Contains(script, "hook forward priority -50") {
		t.Fatal("missing FORWARD hook")
	}
	if !strings.Contains(script, "ct status dnat ct original proto-dst 8080") {
		t.Fatal("not filtering original published port")
	}
	if !strings.Contains(script, "fwui-container-block:tcp/8080") {
		t.Fatal("missing drop rule")
	}
	if strings.Contains(script, "9090") {
		t.Fatal("loopback port must not be blocked")
	}
	if strings.Contains(script, "flush ruleset") {
		t.Fatal("must not flush administrator policy")
	}
}

func TestContainerManualException(t *testing.T) {
	ports := []ContainerPort{{Protocol: "udp", HostPort: 51820, Public: true}}
	script := buildContainerForwardRules(ports, []FirewallManualRule{{Port: 51820, Protocol: "udp"}}, nil)
	if !strings.Contains(script, "counter accept comment \"fwui-container-allow:udp/51820") {
		t.Fatal("manual exception missing")
	}
	if !strings.Contains(script, "counter drop comment \"fwui-container-block:udp/51820") {
		t.Fatal("default deny missing")
	}
}

func TestAdvancedRuleOverlaps(t *testing.T) {
	a := FirewallAdvancedRule{ID: "a", Action: "allow", Protocol: "tcp", PortStart: 80, PortEnd: 100, SourceCIDR: "10.0.0.0/8", IPVersion: "ipv4"}
	b := FirewallAdvancedRule{ID: "b", Action: "deny", Protocol: "tcp", PortStart: 90, PortEnd: 90, SourceCIDR: "10.2.0.0/16", IPVersion: "ipv4"}
	if !advancedOverlap(a, b) {
		t.Fatal("CIDR/port overlap not detected")
	}
	b.SourceCIDR = "192.168.1.0/24"
	if advancedOverlap(a, b) {
		t.Fatal("disjoint CIDRs flagged")
	}
	b.SourceCIDR = "10.2.0.0/16"
	b.Protocol = "udp"
	if advancedOverlap(a, b) {
		t.Fatal("different protocols flagged")
	}
}

func TestAdvancedOverlapHonorsCIDRAddressFamily(t *testing.T) {
	v4 := FirewallAdvancedRule{ID: "v4", Action: "allow", Protocol: "tcp", PortStart: 443, SourceCIDR: "192.0.2.0/24", IPVersion: "any"}
	v6 := FirewallAdvancedRule{ID: "v6", Action: "deny", Protocol: "tcp", PortStart: 443, IPVersion: "ipv6"}
	if advancedOverlap(v4, v6) {
		t.Fatal("IPv4 CIDR cannot overlap an IPv6-only rule")
	}
	if len(AnalyzeFirewallRules("nftables", nil, []FirewallAdvancedRule{v4, v6}).Conflicts) != 0 {
		t.Fatal("conflict analysis reported a cross-family false positive")
	}
	v6.IPVersion = "ipv4"
	if !advancedOverlap(v4, v6) {
		t.Fatal("matching IPv4 rules should overlap")
	}
	v4.SourceCIDR = "2001:db8::/32"
	if advancedOverlap(v4, v6) {
		t.Fatal("IPv6 CIDR cannot overlap an IPv4-only rule")
	}
}

func TestFirewalldZoneParser(t *testing.T) {
	zones := parseFirewalldActiveZones("public\n  interfaces: eth0 eth1\n  sources: 10.0.0.0/8\nhome\n  interfaces: wg0\n")
	if len(zones["public"]) != 2 || zones["public"][0] != "eth0" || zones["home"][0] != "wg0" {
		t.Fatalf("wrong active zone interfaces: %#v", zones)
	}
}

func TestNFTCounterParser(t *testing.T) {
	payload := []byte(`{"nftables":[{"rule":{"comment":"fwui-managed:443/tcp","expr":[{"counter":{"packets":12,"bytes":1024}},{"accept":null}]}},{"rule":{"comment":"user-owned","expr":[{"counter":{"packets":5,"bytes":300}}]}}]}`)
	result, err := parseNFTTraffic(payload, "firewall_ui")
	if err != nil || len(result) != 1 || result[0].Packets != 12 || result[0].Bytes != 1024 {
		t.Fatalf("counters not parsed: %#v %v", result, err)
	}
}

func TestNFTRulesetDigestIgnoresLiveCountersAndHandles(t *testing.T) {
	before := []byte(`{"nftables":[{"metainfo":{"version":"1.0"}},{"rule":{"handle":10,"expr":[{"counter":{"packets":2,"bytes":50}},{"accept":null}],"comment":"fwui-managed:443/tcp"}}]}`)
	after := []byte(`{"nftables":[{"metainfo":{"version":"1.0"}},{"rule":{"handle":55,"expr":[{"counter":{"packets":100,"bytes":10000}},{"accept":null}],"comment":"fwui-managed:443/tcp"}}]}`)
	first, err := normalizedNFTRulesetFingerprint(before)
	if err != nil {
		t.Fatal(err)
	}
	second, err := normalizedNFTRulesetFingerprint(after)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("volatile counters or nft handles triggered policy replacement")
	}
}
