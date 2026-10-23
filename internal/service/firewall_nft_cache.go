package service

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

var managedNFTDesiredHash [32]byte
var managedNFTObservedHash [32]byte

// Ignore volatile nft counters and kernel-assigned handles while comparing
// the owned table. This preserves packet counters across no-op auto-sync ticks
// but still detects out-of-band changes and repairs the policy.
func normalizedNFTRulesetFingerprint(raw []byte) ([32]byte, error) {
	var document any
	if err := json.Unmarshal(raw, &document); err != nil {
		return [32]byte{}, err
	}
	object, ok := document.(map[string]any)
	if !ok {
		return [32]byte{}, fmt.Errorf("invalid nftables JSON document")
	}
	if _, ok := object["nftables"].([]any); !ok {
		return [32]byte{}, fmt.Errorf("nftables JSON is missing its ruleset array")
	}
	var scrub func(any)
	scrub = func(value any) {
		switch typed := value.(type) {
		case map[string]any:
			delete(typed, "handle")
			delete(typed, "metainfo")
			if counter, ok := typed["counter"].(map[string]any); ok {
				delete(counter, "packets")
				delete(counter, "bytes")
			}
			for _, child := range typed {
				scrub(child)
			}
		case []any:
			for _, child := range typed {
				scrub(child)
			}
		}
	}
	scrub(document)
	canonical, err := json.Marshal(document)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(canonical), nil
}

func currentManagedNFTFingerprint(ctx context.Context, binary string) ([32]byte, error) {
	raw, err := runFirewallCommand(ctx, binary, "-j", "list", "table", "inet", managedNftTable)
	if err != nil {
		return [32]byte{}, err
	}
	return normalizedNFTRulesetFingerprint([]byte(raw))
}
