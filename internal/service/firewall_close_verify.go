package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/SawaMEN/Firewall-UI/internal/hostexec"
)

// Read the kernel's JSON representation: nft's human-readable printer can
// rewrite "meta l4proto tcp th dport" as "tcp dport". Comparing command text
// with that output rejects valid rules (and substring matching accepts wrong ports).
func verifyNFTPortClose(ctx context.Context, rule FirewallAdvancedRule) error {
	if !isClosePortRule(rule) {
		return errors.New("not an explicit closed-port rule")
	}
	nft, err := hostexec.LookPath("nft")
	if err != nil {
		return fmt.Errorf("nftables unavailable: %w", err)
	}
	raw, err := runFirewallCommand(ctx, nft, "-j", "list", "table", "inet", containerNFTTable)
	if err != nil {
		return fmt.Errorf("read kernel closed-port rules: %w", err)
	}
	return verifyNFTClosedPortJSON([]byte(raw), rule)
}

type closeNFTChain struct {
	Family   string `json:"family"`
	Table    string `json:"table"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Hook     string `json:"hook"`
	Priority int    `json:"prio"`
}

type closeNFTRule struct {
	Family  string                       `json:"family"`
	Table   string                       `json:"table"`
	Chain   string                       `json:"chain"`
	Comment string                       `json:"comment"`
	Expr    []map[string]json.RawMessage `json:"expr"`
}

func verifyNFTClosedPortJSON(raw []byte, rule FirewallAdvancedRule) error {
	doc, err := decodeNFTPolicy(raw)
	if err != nil {
		return fmt.Errorf("decode kernel closed-port rules: %w", err)
	}
	if nftTableInactive(doc, containerNFTTable) {
		return errors.New("nftables closed-port table is dormant or has unsupported flags; active hooks cannot be verified")
	}
	for _, hook := range []string{"input", "forward"} {
		attached, blocked, bypass := false, false, false
		marker := "fwui-closed-input:" + rule.ID
		if hook == "forward" {
			marker = "fwui-closed-port:" + rule.ID
		}
		for _, item := range doc.Nftables {
			if c := item.Chain; c != nil && c.Family == "inet" && c.Table == containerNFTTable && c.Name == hook && c.Type == "filter" && c.Hook == hook && c.Priority == -50 {
				attached = true
			}
			if r := item.Rule; r != nil && r.Family == "inet" && r.Table == containerNFTTable && r.Chain == hook && !blocked {
				if !bypass && r.Comment == marker && nftCloseExpressionsMatch(r.Expr, rule, hook) {
					blocked = true
				}
				// An earlier verdict can bypass the close in this base chain.
				for _, statement := range r.Expr {
					for key := range statement {
						if key != "match" && key != "counter" && key != "drop" {
							bypass = true
						}
					}
				}
			}
		}
		if !attached || !blocked {
			return fmt.Errorf("nftables %s drop for %d/%s not present in live kernel rules", hook, rule.PortStart, rule.Protocol)
		}
	}
	return nil
}

// Only accept the unconditional rules emitted by buildContainerForwardRules.
// An extra source/interface condition must not be mistaken for a global close.
func nftCloseExpressionsMatch(expr []map[string]json.RawMessage, rule FirewallAdvancedRule, hook string) bool {
	protocol, port, dnat, drop := false, false, false, false
	for _, statement := range expr {
		if len(statement) != 1 || drop {
			return false
		}
		for key, raw := range statement {
			switch key {
			case "counter":
			case "drop":
				drop = string(raw) == "null"
			case "match":
				var match struct {
					Op    string                    `json:"op"`
					Left  map[string]map[string]any `json:"left"`
					Right any                       `json:"right"`
				}
				if json.Unmarshal(raw, &match) != nil {
					return false
				}
				if len(match.Left) != 1 {
					return false
				}
				if meta := match.Left["meta"]; meta != nil && len(meta) == 1 && meta["key"] == "l4proto" && match.Op == "==" && (match.Right == rule.Protocol || match.Right == float64(map[string]int{"tcp": 6, "udp": 17}[rule.Protocol])) {
					protocol = true
				} else if payload := match.Left["payload"]; hook == "input" && payload != nil && match.Op == "==" && match.Right == float64(rule.PortStart) {
					if len(payload) == 2 && (payload["protocol"] == rule.Protocol || payload["protocol"] == "th") && payload["field"] == "dport" {
						port = true
						if payload["protocol"] == rule.Protocol {
							protocol = true
						}
					} else if len(payload) == 3 && payload["base"] == "th" && payload["offset"] == float64(16) && payload["len"] == float64(16) {
						port = true
					} else {
						return false
					}
				} else if ct := match.Left["ct"]; hook == "forward" && ct != nil {
					if len(ct) == 2 && ct["key"] == "proto-dst" && ct["dir"] == "original" && match.Op == "==" && match.Right == float64(rule.PortStart) {
						port = true
					} else if len(ct) == 1 && ct["key"] == "status" && match.Op == "in" && match.Right == "dnat" {
						dnat = true
					} else {
						return false
					}
				} else {
					return false
				}
			default:
				return false
			}
		}
	}
	return protocol && port && drop && (hook == "input" || dnat)
}
