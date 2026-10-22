package service

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Kernel JSON deliberately differs from the submitted nft command: the
// transport-header match has been decoded to a named TCP/UDP payload.
func closedPortNFTFixture(protocol string, port int) string {
	return fmt.Sprintf(`{"nftables":[
 {"chain":{"family":"inet","table":"firewall_ui_containers","name":"input","type":"filter","hook":"input","prio":-50}},
 {"rule":{"family":"inet","table":"firewall_ui_containers","chain":"input","comment":"fwui-closed-input:close-port-%[2]d-%[1]s","expr":[
 {"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"%[1]s"}},
 {"match":{"op":"==","left":{"payload":{"protocol":"%[1]s","field":"dport"}},"right":%[2]d}},
 {"counter":{"packets":12,"bytes":2048}},{"drop":null}]}},
 {"chain":{"family":"inet","table":"firewall_ui_containers","name":"forward","type":"filter","hook":"forward","prio":-50}},
 {"rule":{"family":"inet","table":"firewall_ui_containers","chain":"forward","comment":"fwui-closed-port:close-port-%[2]d-%[1]s","expr":[
 {"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"%[1]s"}},
 {"match":{"op":"in","left":{"ct":{"key":"status"}},"right":"dnat"}},
 {"match":{"op":"==","left":{"ct":{"key":"proto-dst","dir":"original"}},"right":%[2]d}},
 {"counter":{"packets":3,"bytes":128}},{"drop":null}]}}
 ]}`, protocol, port)
}

func TestVerifyNFTClosedPortKernelJSON(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		rule := FirewallAdvancedRule{ID: closeRuleID(1332, protocol), Action: "deny", Protocol: protocol, PortStart: 1332, PortEnd: 1332, IPVersion: "any", Priority: -1000}
		valid := closedPortNFTFixture(protocol, 1332)
		numeric := "6"
		if protocol == "udp" {
			numeric = "17"
		}
		implicit := strings.Replace(valid, `{"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"`+protocol+`"}},`, "", 1)
		generic := strings.Replace(valid, `"protocol":"`+protocol+`","field":"dport"`, `"base":"th","offset":16,"len":16`, 1)
		tests := []struct {
			name, raw string
			ok        bool
		}{
			{"normalized", valid, true},
			{"implicit protocol after nft decoding", implicit, true},
			{"numeric protocol", strings.ReplaceAll(valid, `"right":"`+protocol+`"`, `"right":`+numeric), true},
			{"named transport header", strings.Replace(valid, `"protocol":"`+protocol+`","field":"dport"`, `"protocol":"th","field":"dport"`, 1), true}, {"raw transport header", generic, true},
			{"port prefix", strings.ReplaceAll(valid, `"right":1332`, `"right":13320`), false},
			{"wrong protocol", strings.ReplaceAll(valid, `"right":"`+protocol+`"`, `"right":"icmp"`), false},
			{"wrong input hook", strings.Replace(valid, `"hook":"input"`, `"hook":"output"`, 1), false},
			{"missing forward hook", strings.Replace(valid, `"hook":"forward"`, `"hook":"output"`, 1), false},
			{"wrong priority", strings.Replace(valid, `"prio":-50`, `"prio":0`, 1), false},
			{"wrong dnat port", strings.Replace(valid, `"dir":"original"`, `"dir":"reply"`, 1), false},
			{"missing dnat", strings.Replace(valid, `"right":"dnat"`, `"right":"snat"`, 1), false},
			{"accept", strings.Replace(valid, `"drop":null`, `"accept":null`, 1), false},
			{"comment alone", strings.Replace(valid, `"field":"dport"`, `"field":"sport"`, 1), false},
			{"source restriction", strings.Replace(valid, `{"drop":null}`, `{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"192.0.2.1"}},{"drop":null}`, 1), false},
			{"empty", `{"nftables":[]}`, false}, {"malformed", `not json`, false},
		}
		// A matching DROP after an ACCEPT in the same base chain is ineffective.
		var doc map[string][]map[string]any
		if err := json.Unmarshal([]byte(valid), &doc); err != nil {
			t.Fatal(err)
		}
		bypass := map[string]any{"rule": map[string]any{"family": "inet", "table": containerNFTTable, "chain": "input", "expr": []any{map[string]any{"accept": nil}}}}
		doc["nftables"] = append([]map[string]any{bypass}, doc["nftables"]...)
		raw, _ := json.Marshal(doc)
		tests = append(tests, struct {
			name, raw string
			ok        bool
		}{"earlier accept", string(raw), false})
		for _, tt := range tests {
			t.Run(protocol+"/"+tt.name, func(t *testing.T) {
				err := verifyNFTClosedPortJSON([]byte(tt.raw), rule)
				if (err == nil) != tt.ok {
					t.Fatalf("verification error = %v, want success %v", err, tt.ok)
				}
			})
		}
	}
}
