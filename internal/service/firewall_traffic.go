package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/SawaMEN/Firewall-UI/internal/hostexec"
)

type TrafficCounter struct {
	Rule    string `json:"rule"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
	Table   string `json:"table"`
}
type FirewallTraffic struct {
	Supported bool             `json:"supported"`
	Counters  []TrafficCounter `json:"counters"`
	Note      string           `json:"note"`
}

func parseNFTTraffic(data []byte, table string) ([]TrafficCounter, error) {
	doc, err := decodeNFTPolicy(data)
	if err != nil {
		return nil, err
	}
	out := []TrafficCounter{}
	for _, item := range doc.Nftables {
		rule := item.Rule
		if rule == nil {
			continue
		}
		counter := TrafficCounter{Table: table, Rule: rule.Comment}
		found := false
		for _, expr := range rule.Expr {
			if value := expr["comment"]; len(value) > 0 && rule.Comment == "" {
				_ = json.Unmarshal(value, &counter.Rule)
			}
			if value := expr["counter"]; len(value) > 0 {
				var numbers struct {
					Packets uint64 `json:"packets"`
					Bytes   uint64 `json:"bytes"`
				}
				if json.Unmarshal(value, &numbers) == nil {
					counter.Packets = numbers.Packets
					counter.Bytes = numbers.Bytes
					found = true
				}
			}
		}
		if found && strings.HasPrefix(counter.Rule, "fwui-") {
			out = append(out, counter)
		}
	}
	return out, nil
}

func (s *FirewallService) TrafficCounters(ctx context.Context) (FirewallTraffic, error) {
	firewallMu.Lock()
	defer firewallMu.Unlock()
	result := FirewallTraffic{Counters: []TrafficCounter{}, Note: "Counters are kernel totals since the last rule installation; replacing nftables rules resets them. External firewall rules are not counted."}
	nft, err := hostexec.LookPath("nft")
	if err == nil {
		for _, table := range []string{managedNftTable, containerNFTTable} {
			exists, checkErr := containerTableExistsFor(ctx, nft, table)
			if checkErr != nil {
				return result, checkErr
			}
			if !exists {
				continue
			}
			raw, err := runFirewallCommand(ctx, nft, "-j", "list", "table", "inet", table)
			if err != nil {
				return result, err
			}
			counters, err := parseNFTTraffic([]byte(raw), table)
			if err != nil {
				return result, err
			}
			result.Counters = append(result.Counters, counters...)
			result.Supported = true
		}
	}
	if !result.Supported {
		// Older native iptables deployments expose packet/byte counts via
		// -L, though arbitrary administrator/UFW rules are not mapped to IDs.
		iptables, err := hostexec.LookPath("iptables")
		if err == nil {
			raw, runErr := runFirewallCommand(ctx, iptables, "-w", "-n", "-v", "-x", "--line-numbers", "-L", managedIPTablesChain)
			if runErr == nil {
				result.Supported = true
				for _, line := range strings.Split(raw, "\n") {
					fields := strings.Fields(line)
					if len(fields) < 4 {
						continue
					}
					index, e1 := strconv.Atoi(fields[0])
					packets, e2 := strconv.ParseUint(fields[1], 10, 64)
					bytes, e3 := strconv.ParseUint(fields[2], 10, 64)
					if e1 != nil || e2 != nil || e3 != nil {
						continue
					}
					result.Counters = append(result.Counters, TrafficCounter{Rule: fmt.Sprintf("iptables rule #%d (%s)", index, fields[3]), Packets: packets, Bytes: bytes, Table: managedIPTablesChain})
				}
			}
		}
	}
	if !result.Supported {
		result.Note = "Per-rule counters are not available for the current backend. No traffic statistics are invented."
	}
	return result, nil
}

func containerTableExistsFor(ctx context.Context, nft, table string) (bool, error) {
	tables, err := runFirewallCommand(ctx, nft, "list", "tables")
	if err != nil {
		return false, err
	}
	return firewallOutputHasFields(tables, "table", "inet", table), nil
}
