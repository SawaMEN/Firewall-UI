package service

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/SawaMEN/Firewall-UI/internal/hostexec"
)

const (
	containerProtectionKey = "firewallContainerProtection"
	containerNFTTable      = "firewall_ui_containers"
)

type ContainerProtectionStatus struct {
	Enabled   bool            `json:"enabled"`
	Supported bool            `json:"supported"`
	Active    bool            `json:"active"`
	Ports     []ContainerPort `json:"ports"`
	Message   string          `json:"message,omitempty"`
}

var containerPolicyHash [32]byte
var containerPolicyLastCheck time.Time

func containerProtectionEnabled() (bool, error) {
	raw, err := firewallSetting(containerProtectionKey, "false")
	if err != nil {
		return false, err
	}
	return strconv.ParseBool(strings.TrimSpace(raw))
}

func (s *FirewallService) ContainerProtectionStatus(ctx context.Context) (ContainerProtectionStatus, error) {
	firewallMu.Lock()
	defer firewallMu.Unlock()
	enabled, err := containerProtectionEnabled()
	if err != nil {
		return ContainerProtectionStatus{}, err
	}
	status := ContainerProtectionStatus{Enabled: enabled, Ports: []ContainerPort{}}
	if s.PortMonitor != nil {
		status.Ports = s.PortMonitor.Snapshot().Containers
	} else {
		status.Ports = ReadContainerPorts(ctx)
	}
	path, err := hostexec.LookPath("nft")
	if err != nil {
		status.Message = "nftables is required for forwarded container traffic protection"
		return status, nil
	}
	status.Supported = true
	status.Active, err = containerTableExists(ctx, path)
	return status, err
}

// SetContainerProtection never changes a host policy unless the nftables
// transaction can be applied. In particular, it does not guess that an INPUT
// rule will protect Docker's DNAT traffic, which traverses FORWARD instead.
func (s *FirewallService) SetContainerProtection(ctx context.Context, enabled bool) error {
	firewallMu.Lock()
	defer firewallMu.Unlock()
	previous, err := containerProtectionEnabled()
	if err != nil {
		return err
	}
	if err := (&SettingService{}).setBool(containerProtectionKey, enabled); err != nil {
		return err
	}
	containerPolicyHash = [32]byte{}
	if err := s.syncContainerProtectionLocked(ctx); err != nil {
		restoreErr := (&SettingService{}).setBool(containerProtectionKey, previous)
		containerPolicyHash = [32]byte{}
		recovery, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		return errors.Join(err, restoreErr, s.syncContainerProtectionLocked(recovery))
	}
	return nil
}

func (s *FirewallService) SyncContainerProtection(ctx context.Context) error {
	firewallMu.Lock()
	defer firewallMu.Unlock()
	return s.syncContainerProtectionLocked(ctx)
}

func containerTableExists(ctx context.Context, nft string) (bool, error) {
	tables, err := runFirewallCommand(ctx, nft, "list", "tables")
	if err != nil {
		return false, err
	}
	return firewallOutputHasFields(tables, "table", "inet", containerNFTTable), nil
}

// Always keep a dedicated, non-destructive FORWARD hook. No Docker chains,
// host FORWARD policy or administrator-owned nftables objects are modified.
func (s *FirewallService) syncContainerProtectionLocked(ctx context.Context) error {
	enabled, err := containerProtectionEnabled()
	if err != nil {
		return err
	}
	// A manually closed port must block forwarded DNAT traffic even when
	// the optional "protect all container ports" feature is disabled.
	advanced, err := loadAdvancedFirewallRules()
	if err != nil {
		return err
	}
	hasClosedPorts := false
	for _, rule := range advanced {
		if isClosePortRule(rule) {
			hasClosedPorts = true
			break
		}
	}
	managed, configured, err := firewallManagedEnabledPreference()
	if err != nil {
		return err
	}
	backend, detectErr := detectManagedFirewallBackend(ctx)
	if detectErr != nil {
		return detectErr
	}
	if !isManagedNativeFirewall(backend.name) || !configured || managed {
		managed, err = backend.enabled(ctx)
		if err != nil {
			return err
		}
	}
	needForwardHook := managed && (enabled || hasClosedPorts)
	nft, err := hostexec.LookPath("nft")
	if err != nil {
		if !needForwardHook {
			return nil
		}
		return errors.New("nftables is required to close Docker/Podman published ports (install nftables on the host)")
	}
	exists, err := containerTableExists(ctx, nft)
	if err != nil {
		return err
	}
	if !needForwardHook {
		containerPolicyHash = [32]byte{}
		if exists {
			_, err = runFirewallCommand(ctx, nft, "delete", "table", "inet", containerNFTTable)
		}
		return err
	}
	var ports []ContainerPort
	var manual []FirewallManualRule
	if enabled {
		if s.PortMonitor != nil {
			ports = s.PortMonitor.Snapshot().Containers
		}
		if ports == nil {
			ports = ReadContainerPorts(ctx)
		}
		manual, err = loadManualFirewallRules()
		if err != nil {
			return err
		}
	}
	script := buildContainerForwardRules(ports, manual, advanced)
	fingerprint := sha256.Sum256([]byte(script))
	if exists && fingerprint == containerPolicyHash && time.Since(containerPolicyLastCheck) < time.Minute {
		return nil
	}
	// The hash describes our last script, not the live kernel ruleset.
	// Previously, once a matching hash was cached, an externally removed or
	// modified FORWARD rule was never restored because this branch refreshed
	// the timestamp without checking nftables. Reapply the owned table after
	// the verification interval to repair drift, without touching other
	// nftables tables. (Reapplying resets counters for this one table.)
	var batch strings.Builder
	if exists {
		batch.WriteString("delete table inet " + containerNFTTable + "\n")
	}
	batch.WriteString(script)
	cmd := firewallCommand(ctx, nft, "-f", "-")
	cmd.Stdin = strings.NewReader(batch.String())
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("apply container FORWARD protection: %w: %s", err, strings.TrimSpace(string(output)))
	}
	containerPolicyHash = fingerprint
	containerPolicyLastCheck = time.Now()
	return nil
}

// The original destination port is checked because the packet has already
// undergone DNAT by the time it reaches FORWARD. A bound HostIP is matched too;
// binding to 0.0.0.0 or :: intentionally covers all local destinations.
func containerMatch(port ContainerPort) string {
	match := "meta l4proto " + port.Protocol + " ct status dnat ct original proto-dst " + strconv.Itoa(port.HostPort)
	ip := net.ParseIP(port.HostIP)
	if ip != nil && !ip.IsUnspecified() {
		if ip.To4() != nil {
			match += " ct original ip daddr " + ip.String()
		} else {
			match += " ct original ip6 daddr " + ip.String()
		}
	}
	return match
}

func buildContainerForwardRules(ports []ContainerPort, manual []FirewallManualRule, advanced []FirewallAdvancedRule) string {
	// Stable ordering avoids resetting kernel counters on every socket scan.
	unique := map[string]ContainerPort{}
	for _, p := range ports {
		if !p.Public || p.HostPort < 1 || p.HostPort > 65535 || (p.Protocol != "tcp" && p.Protocol != "udp") {
			continue
		}
		key := fmt.Sprintf("%s/%d/%s", p.Protocol, p.HostPort, p.HostIP)
		unique[key] = p
	}
	keys := make([]string, 0, len(unique))
	for key := range unique {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	sortAdvancedRules(advanced)
	var b strings.Builder
	b.WriteString("table inet " + containerNFTTable + " {\n")
	// UFW INPUT rules can remain shadowed by an administrator's ALLOW or by
	// another UFW rule that the panel does not own. A separate nftables
	// INPUT base chain at priority -50 enforces explicit closes directly in
	// the kernel. It runs before the normal UFW filter chains and does not
	// modify any administrator-owned UFW configuration.
	closed := false
	for _, rule := range advanced {
		if isClosePortRule(rule) {
			closed = true
			break
		}
	}
	if closed {
		b.WriteString(" chain input { type filter hook input priority -50; policy accept;\n")
		for _, rule := range advanced {
			if !isClosePortRule(rule) {
				continue
			}
			b.WriteString("  meta l4proto " + rule.Protocol + " th dport " +
				strconv.Itoa(rule.PortStart) + " counter drop comment \"fwui-closed-input:" + rule.ID + "\"\n")
		}
		b.WriteString(" }\n")
	}
	b.WriteString(" chain forward { type filter hook forward priority -50; policy accept;\n")
	// A close-port action must win even for established connections and
	// must not depend on a potentially stale published-container snapshot.
	for _, rule := range advanced {
		if !isClosePortRule(rule) {
			continue
		}
		b.WriteString("  meta l4proto " + rule.Protocol + " ct status dnat ct original proto-dst " +
			strconv.Itoa(rule.PortStart) + " counter drop comment \"fwui-closed-port:" + rule.ID + "\"\n")
	}
	b.WriteString("  ct state established,related accept\n")
	for _, key := range keys {
		port := unique[key]
		match := containerMatch(port)
		// Advanced exceptions retain source/interface restrictions. A broad
		// manual allow is an explicit administrator decision. The final drop
		// protects all other attempts, including forwarded Docker traffic.
		for _, rule := range advanced {
			// Explicit close rules were already installed ahead of conntrack.
			if isClosePortRule(rule) {
				continue
			}
			if rule.Protocol != "any" && rule.Protocol != port.Protocol {
				continue
			}
			if rule.PortStart != 0 && (port.HostPort < rule.PortStart || port.HostPort > max(rule.PortStart, rule.PortEnd)) {
				continue
			}
			condition := match
			if rule.IPVersion == "ipv4" {
				condition += " meta nfproto ipv4"
			}
			if rule.IPVersion == "ipv6" {
				condition += " meta nfproto ipv6"
			}
			if rule.SourceCIDR != "" {
				ip := rule.SourceCIDR
				if strings.Contains(ip, ":") {
					condition += " ip6 saddr " + ip
				} else {
					condition += " ip saddr " + ip
				}
			}
			if rule.Interface != "" {
				condition += " iifname \"" + rule.Interface + "\""
			}
			action := "accept"
			if rule.Action == "deny" {
				action = "drop"
			}
			b.WriteString("  " + condition + " counter " + action + " comment \"fwui-container-rule:" + rule.ID + "\"\n")
		}
		allowed := false
		for _, rule := range manual {
			if rule.Port == port.HostPort && rule.Protocol == port.Protocol {
				allowed = true
				break
			}
		}
		if allowed {
			b.WriteString("  " + match + " counter accept comment \"fwui-container-allow:" + key + "\"\n")
		}
		b.WriteString("  " + match + " counter drop comment \"fwui-container-block:" + key + "\"\n")
	}
	b.WriteString(" }\n}\n")
	return b.String()
}
