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
    containerNFTTable = "firewall_ui_containers"
)

type ContainerProtectionStatus struct {
    Enabled bool `json:"enabled"`
    Supported bool `json:"supported"`
    Active bool `json:"active"`
    Ports []ContainerPort `json:"ports"`
    Message string `json:"message,omitempty"`
}

var containerPolicyHash [32]byte
var containerPolicyLastCheck time.Time

func containerProtectionEnabled() (bool, error) {
    raw, err := firewallSetting(containerProtectionKey, "false")
    if err != nil { return false, err }
    return strconv.ParseBool(strings.TrimSpace(raw))
}

func (s *FirewallService) ContainerProtectionStatus(ctx context.Context) (ContainerProtectionStatus, error) {
    firewallMu.Lock()
    defer firewallMu.Unlock()
    enabled, err := containerProtectionEnabled()
    if err != nil { return ContainerProtectionStatus{}, err }
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
    if err != nil { return err }
    if err := (&SettingService{}).setBool(containerProtectionKey, enabled); err != nil { return err }
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
    if err != nil { return false, err }
    return firewallOutputHasFields(tables, "table", "inet", containerNFTTable), nil
}

// Always keep a dedicated, non-destructive FORWARD hook. No Docker chains,
// host FORWARD policy or administrator-owned nftables objects are modified.
func (s *FirewallService) syncContainerProtectionLocked(ctx context.Context) error {
    enabled, err := containerProtectionEnabled()
    if err != nil { return err }
    managed, _, err := firewallManagedEnabledPreference()
    if err != nil { return err }
    if managed {
        backend, detectErr := detectManagedFirewallBackend(ctx)
        if detectErr != nil { return detectErr }
        managed, err = backend.enabled(ctx)
        if err != nil { return err }
    }
    nft, err := hostexec.LookPath("nft")
    if err != nil {
        if !enabled || !managed { return nil }
        return errors.New("nftables is required for Docker/Podman published-port protection")
    }
    exists, err := containerTableExists(ctx, nft)
    if err != nil { return err }
    if !enabled || !managed {
        containerPolicyHash = [32]byte{}
        if exists {
            _, err = runFirewallCommand(ctx, nft, "delete", "table", "inet", containerNFTTable)
        }
        return err
    }
    var ports []ContainerPort
    if s.PortMonitor != nil { ports = s.PortMonitor.Snapshot().Containers }
    if ports == nil { ports = ReadContainerPorts(ctx) }
    manual, err := loadManualFirewallRules()
    if err != nil { return err }
    advanced, err := loadAdvancedFirewallRules()
    if err != nil { return err }
    script := buildContainerForwardRules(ports, manual, advanced)
    fingerprint := sha256.Sum256([]byte(script))
    if exists && fingerprint == containerPolicyHash && time.Since(containerPolicyLastCheck) < time.Minute {
        return nil
    }
    if exists && fingerprint == containerPolicyHash {
        containerPolicyLastCheck = time.Now()
        return nil
    }
    var batch strings.Builder
    if exists { batch.WriteString("delete table inet " + containerNFTTable + "\n") }
    batch.WriteString(script)
    cmd := firewallCommand(ctx, nft, "-f", "-")
    cmd.Stdin = strings.NewReader(batch.String())
    output, err := cmd.CombinedOutput()
    if err != nil { return fmt.Errorf("apply container FORWARD protection: %w: %s", err, strings.TrimSpace(string(output))) }
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
        if ip.To4() != nil { match += " ct original ip daddr " + ip.String() } else {
            match += " ct original ip6 daddr " + ip.String()
        }
    }
    return match
}

func buildContainerForwardRules(ports []ContainerPort, manual []FirewallManualRule, advanced []FirewallAdvancedRule) string {
    // Stable ordering avoids resetting kernel counters on every socket scan.
    unique := map[string]ContainerPort{}
    for _, p := range ports {
        if !p.Public || p.HostPort < 1 || p.HostPort > 65535 || (p.Protocol != "tcp" && p.Protocol != "udp") { continue }
        key := fmt.Sprintf("%s/%d/%s", p.Protocol, p.HostPort, p.HostIP)
        unique[key] = p
    }
    keys := make([]string, 0, len(unique))
    for key := range unique { keys = append(keys, key) }
    sort.Strings(keys)
    sortAdvancedRules(advanced)
    var b strings.Builder
    b.WriteString("table inet " + containerNFTTable + " {\n")
    b.WriteString(" chain forward { type filter hook forward priority -50; policy accept;\n")
    b.WriteString("  ct state established,related accept\n")
    for _, key := range keys {
        port := unique[key]
        match := containerMatch(port)
        // Advanced exceptions retain source/interface restrictions. A broad
        // manual allow is an explicit administrator decision. The final drop
        // protects all other attempts, including forwarded Docker traffic.
        for _, rule := range advanced {
            if rule.Protocol != "any" && rule.Protocol != port.Protocol { continue }
            if rule.PortStart != 0 && (port.HostPort < rule.PortStart || port.HostPort > max(rule.PortStart, rule.PortEnd)) { continue }
            condition := match
            if rule.IPVersion == "ipv4" { condition += " meta nfproto ipv4" }
            if rule.IPVersion == "ipv6" { condition += " meta nfproto ipv6" }
            if rule.SourceCIDR != "" {
                ip := rule.SourceCIDR
                if strings.Contains(ip, ":") { condition += " ip6 saddr " + ip } else { condition += " ip saddr " + ip }
            }
            if rule.Interface != "" { condition += " iifname \"" + rule.Interface + "\"" }
            action := "accept"
            if rule.Action == "deny" { action = "drop" }
            b.WriteString("  " + condition + " counter " + action + " comment \"fwui-container-rule:" + rule.ID + "\"\n")
        }
        allowed := false
        for _, rule := range manual {
            if rule.Port == port.HostPort && rule.Protocol == port.Protocol { allowed = true; break }
        }
        if allowed { b.WriteString("  " + match + " counter accept comment \"fwui-container-allow:" + key + "\"\n") }
        b.WriteString("  " + match + " counter drop comment \"fwui-container-block:" + key + "\"\n")
    }
    b.WriteString(" }\n}\n")
    return b.String()
}
