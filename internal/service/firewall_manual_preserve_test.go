package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestReopenPreservesManualTCPUDPMetadata(t *testing.T) {
	for _, label := range []string{"Мой TCP + UDP сервис", ""} {
		t.Run(label, func(t *testing.T) {
			root := t.TempDir()
			state := filepath.Join(root, "state.json")
			Configure(state, 8088, 0)
			if err := os.WriteFile(filepath.Join(root, "ufw"), []byte("#!/bin/sh\ncase \"$*\" in\n status*) echo 'Status: inactive';;\nesac\n"), 0755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", root)
			if err := (&SettingService{}).setBool(firewallAutoSyncKey, false); err != nil {
				t.Fatal(err)
			}
			svc := &FirewallService{}
			ctx := context.Background()
			if _, err := svc.AddManagedManualRuleSafe(ctx, 1332, "both", label, 8088); err != nil {
				t.Fatal(err)
			}
			for _, proto := range []string{"tcp", "udp", "both", "tcp"} {
				if _, err := svc.EnsureManagedManualRuleSafe(ctx, 1332, proto, "Открыт вручную", 8088); err != nil {
					t.Fatal(err)
				}
				// Reload settings to catch persistence errors, not just response rendering.
				Configure(state, 8088, 0)
				rules, err := loadManualFirewallRules()
				if err != nil {
					t.Fatal(err)
				}
				labels, err := loadFirewallManualLabels()
				if err != nil {
					t.Fatal(err)
				}
				if len(rules) != 2 {
					t.Fatalf("manual protocol pair changed: %+v", rules)
				}
				for _, rule := range rules {
					if labels[firewallRuleKey(rule.Port, rule.Protocol)] != label {
						t.Fatalf("reopen %s changed %s label: %+v", proto, rule.Protocol, labels)
					}
				}
			}
			// An explicit edit must still update the requested protocol only.
			if _, err := svc.AddManagedManualRuleSafe(ctx, 1332, "tcp", "Изменено", 8088); err != nil {
				t.Fatal(err)
			}
			labels, err := loadFirewallManualLabels()
			if err != nil {
				t.Fatal(err)
			}
			if labels["1332/tcp"] != "Изменено" || labels["1332/udp"] != label {
				t.Fatalf("explicit edit changed peer: %+v", labels)
			}
		})
	}
}

func TestEnsureManualPairAddsOnlyMissingProtocol(t *testing.T) {
	root := t.TempDir()
	Configure(filepath.Join(root, "state.json"), 8088, 0)
	if err := os.WriteFile(filepath.Join(root, "ufw"), []byte("#!/bin/sh\ncase \"$*\" in\n status*) echo 'Status: inactive';;\nesac\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root)
	svc := &FirewallService{}
	if _, err := svc.AddManagedManualRuleSafe(context.Background(), 1332, "udp", "UDP custom", 8088); err != nil {
		t.Fatal(err)
	}
	status, err := svc.EnsureManagedManualRuleSafe(context.Background(), 1332, "both", "Открыт вручную", 8088)
	if err != nil {
		t.Fatal(err)
	}
	if len(status.ManualRules) != 2 {
		t.Fatalf("missing manual pair: %+v", status.ManualRules)
	}
	labels, err := loadFirewallManualLabels()
	if err != nil {
		t.Fatal(err)
	}
	if labels["1332/udp"] != "UDP custom" || labels["1332/tcp"] != "Открыт вручную" {
		t.Fatalf("existing peer overwritten: %+v", labels)
	}
}
