package service

import (
	"encoding/json"
	"errors"
	"fmt"
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

// This is the minimum attachment proof for auxiliary policy. Individual
// close-port DROP expressions are verified separately before caching a write.
func verifyNFTContainerHooks(raw []byte) error {
	doc, err := decodeNFTPolicy(raw)
	if err != nil {
		return fmt.Errorf("decode container nftables policy: %w", err)
	}
	if nftTableInactive(doc, containerNFTTable) {
		return errors.New("Container FORWARD hook is missing or changed")
	}
	for _, item := range doc.Nftables {
		if c := item.Chain; c != nil && c.Family == "inet" && c.Table == containerNFTTable && c.Name == "forward" && c.Type == "filter" && c.Hook == "forward" && c.Priority == -50 && c.Policy == "accept" {
			return nil
		}
	}
	return errors.New("Container FORWARD hook is missing or changed")
}

// Prediction needs an unchanged snapshot of a policy we successfully applied.
// Saved intent alone cannot establish the order or presence of advanced rules.
func verifyNFTSnapshotFingerprint(raw []byte, expected [32]byte) error {
	if expected == ([32]byte{}) {
		return errors.New("nftables policy has not been verified since startup")
	}
	observed, err := normalizedNFTRulesetFingerprint(raw)
	if err != nil {
		return err
	}
	if observed != expected {
		return errors.New("nftables policy changed since the last verified application")
	}
	return nil
}

// Confirm the generated marked rules were installed in the requested order
// with the requested terminal verdict. Exact closed-port predicates have an
// additional semantic check; subsequent drift compares the entire snapshot.
func verifyNFTMarkedRules(raw []byte, script, table, prefix string) error {
	doc, err := decodeNFTPolicy(raw)
	if err != nil {
		return err
	}
	type markedRule struct{ comment, verdict string }
	expected := map[string][]markedRule{}
	chain := ""
	for _, line := range strings.Split(script, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "chain" {
			chain = fields[1]
		}
		before, comment, ok := strings.Cut(line, " comment \"")
		if !ok {
			continue
		}
		comment = strings.TrimSuffix(comment, "\"")
		if !strings.HasPrefix(comment, prefix) {
			continue
		}
		words := strings.Fields(before)
		if chain == "" || len(words) == 0 {
			return errors.New("invalid generated nftables rule")
		}
		expected[chain] = append(expected[chain], markedRule{comment, words[len(words)-1]})
	}
	actual := map[string][]markedRule{}
	for _, item := range doc.Nftables {
		r := item.Rule
		if r == nil || r.Family != "inet" || r.Table != table || !strings.HasPrefix(r.Comment, prefix) {
			continue
		}
		verdict := ""
		if len(r.Expr) > 0 {
			last := r.Expr[len(r.Expr)-1]
			if len(last) == 1 {
				for key, value := range last {
					if (key == "accept" || key == "drop") && string(value) == "null" {
						verdict = key
					}
				}
			}
		}
		actual[r.Chain] = append(actual[r.Chain], markedRule{r.Comment, verdict})
	}
	for chain, want := range expected {
		got := actual[chain]
		if len(got) != len(want) {
			return fmt.Errorf("nftables marked policy is incomplete in %s/%s", table, chain)
		}
		for i := range want {
			if got[i] != want[i] {
				return fmt.Errorf("nftables marked policy order or verdict changed in %s/%s", table, chain)
			}
		}
		delete(actual, chain)
	}
	if len(actual) > 0 {
		return fmt.Errorf("unexpected marked nftables rules in %s", table)
	}
	return nil
}

// A newly supplied request port is not evidence that the previous FORWARD
// transaction contained its protective exception.
func nftForwardSafetyAllow(raw []byte, rule FirewallRule) bool {
	doc, err := decodeNFTPolicy(raw)
	if err != nil || nftTableInactive(doc, containerNFTTable) {
		return false
	}
	for _, item := range doc.Nftables {
		r := item.Rule
		if r == nil || r.Family != "inet" || r.Table != containerNFTTable || r.Chain != "forward" || r.Comment != "fwui-container-safety:"+firewallRuleSpec(rule) {
			continue
		}
		translated := make([]map[string]json.RawMessage, 0, len(r.Expr))
		accepted := false
		for _, statement := range r.Expr {
			if value, ok := statement["accept"]; ok && len(statement) == 1 && string(value) == "null" {
				translated = append(translated, map[string]json.RawMessage{"drop": json.RawMessage("null")})
				accepted = true
			} else {
				translated = append(translated, statement)
			}
		}
		if accepted && nftCloseExpressionsMatch(translated, FirewallAdvancedRule{Protocol: rule.Protocol, PortStart: rule.Port}, "forward") {
			return true
		}
	}
	return false
}
