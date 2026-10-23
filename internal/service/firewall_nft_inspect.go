package service

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

// Keep kernel evidence separate from the saved policy and table-name probes.
// A present but detached/empty table is not an active input firewall.
type nftPolicySnapshot struct {
	Nftables []struct {
		Table *struct {
			Family string        `json:"family"`
			Name   string        `json:"name"`
			Flags  nftTableFlags `json:"flags"`
		} `json:"table"`
		Chain *struct {
			Family   string `json:"family"`
			Table    string `json:"table"`
			Name     string `json:"name"`
			Type     string `json:"type"`
			Hook     string `json:"hook"`
			Priority int    `json:"prio"`
			Policy   string `json:"policy"`
		} `json:"chain"`
		Rule *closeNFTRule `json:"rule"`
	} `json:"nftables"`
}

func decodeNFTPolicy(raw []byte) (nftPolicySnapshot, error) {
	var doc nftPolicySnapshot
	if err := json.Unmarshal(raw, &doc); err != nil {
		return doc, err
	}
	if doc.Nftables == nil {
		return doc, errors.New("nftables JSON is missing its ruleset array")
	}
	return doc, nil
}

func nativeNFTState(raw []byte) (bool, map[string]bool, error) {
	doc, err := decodeNFTPolicy(raw)
	if err != nil {
		return false, nil, err
	}
	active := false
	allows := map[string]bool{}
	if nftTableInactive(doc, managedNftTable) {
		return false, allows, nil
	}
	for _, item := range doc.Nftables {
		if c := item.Chain; c != nil && c.Family == "inet" && c.Table == managedNftTable && c.Name == managedNftChain && c.Type == "filter" && c.Hook == "input" && c.Priority == 100 && c.Policy == "drop" {
			active = true
		}
		r := item.Rule
		if r == nil || r.Family != "inet" || r.Table != managedNftTable || r.Chain != managedNftChain {
			continue
		}
		spec, ok := strings.CutPrefix(r.Comment, "fwui-managed:")
		canonical, valid := canonicalFirewallSpec(spec)
		if !ok || !valid || spec != canonical {
			continue
		}
		pieces := strings.SplitN(spec, "/", 2)
		rule := FirewallRule{Protocol: pieces[1]}
		if strings.Contains(pieces[0], "-") {
			rule.PortRange = pieces[0]
		} else {
			rule.Port, _ = strconv.Atoi(pieces[0])
		}
		if nftAllowExpressionsMatch(r.Expr, rule) {
			allows[spec] = true
		}
	}
	return active, allows, nil
}

// Reuse the strict exact-port INPUT matcher after translating only a terminal
// ACCEPT verdict and an exact expected interval. Extra source/interface tests,
// wrong protocols/ports and an ownership comment without a rule never qualify.
func nftAllowExpressionsMatch(expr []map[string]json.RawMessage, rule FirewallRule) bool {
	translated := make([]map[string]json.RawMessage, 0, len(expr))
	start, end := firewallRuleStart(rule), firewallRuleEnd(rule)
	accepted := false
	for _, statement := range expr {
		if raw, ok := statement["accept"]; ok {
			if len(statement) != 1 || string(raw) != "null" {
				return false
			}
			translated = append(translated, map[string]json.RawMessage{"drop": json.RawMessage("null")})
			accepted = true
			continue
		}
		if raw, ok := statement["match"]; ok && start != end {
			var match map[string]json.RawMessage
			if json.Unmarshal(raw, &match) != nil {
				return false
			}
			var interval struct {
				Range []int `json:"range"`
			}
			if json.Unmarshal(match["right"], &interval) == nil && len(interval.Range) > 0 {
				if len(interval.Range) != 2 || interval.Range[0] != start || interval.Range[1] != end {
					return false
				}
				match["right"], _ = json.Marshal(start)
				updated, _ := json.Marshal(match)
				translated = append(translated, map[string]json.RawMessage{"match": updated})
				continue
			}
			// A single port must not be mistaken for an entire expected range.
			var left map[string]json.RawMessage
			if json.Unmarshal(match["left"], &left) == nil && left["payload"] != nil {
				return false
			}
		}
		translated = append(translated, statement)
	}
	return accepted && nftCloseExpressionsMatch(translated, FirewallAdvancedRule{Protocol: rule.Protocol, PortStart: start}, "input")
}

func nftTableInactive(doc nftPolicySnapshot, table string) bool {
	for _, item := range doc.Nftables {
		if entry := item.Table; entry != nil && entry.Family == "inet" && entry.Name == table {
			for _, flag := range entry.Flags {
				// Some older nft JSON printers put the table name in flags
				// instead of "dormant". Unknown flags cannot establish that
				// the base hooks are active; never silently trust them.
				if flag != "owner" && flag != "persist" {
					return true
				}
			}
		}
	}
	return false
}

// nft versions serialize table flags as a string or a string array.
// Interpret both without losing dormant-table enforcement checks.
type nftTableFlags []string

func (flags *nftTableFlags) UnmarshalJSON(raw []byte) error {
	var list []string
	if len(raw) > 0 && raw[0] == '[' {
		if err := json.Unmarshal(raw, &list); err != nil {
			return err
		}
	} else {
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			return err
		}
		list = strings.FieldsFunc(text, func(r rune) bool { return r == ',' || r == ' ' })
	}
	*flags = list
	return nil
}
