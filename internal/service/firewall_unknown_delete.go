package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// parseExternalUFWDestination extracts a *destination* port interval from
// one saved UFW command. If the destination is ambiguous we refuse removal:
// a broad rule may be the only protection for SSH or the management panel.
func parseExternalUFWDestination(line string) (int, int, []string, error) {
	if len(line) > 2048 || strings.ContainsAny(line, "\x00\r\n") {
		return 0, 0, nil, fmt.Errorf("%w: invalid UFW rule text", ErrInvalidFirewallChange)
	}
	line = strings.TrimSpace(line)
	before, comment, hasComment := strings.Cut(line, " comment ")
	fields := strings.Fields(before)
	if len(fields) < 3 || fields[0] != "ufw" {
		return 0, 0, nil, fmt.Errorf("%w: invalid UFW rule", ErrInvalidFirewallChange)
	}
	verb := 1
	if fields[verb] == "route" {
		verb++
	}
	if verb >= len(fields) {
		return 0, 0, nil, fmt.Errorf("%w: incomplete UFW rule", ErrInvalidFirewallChange)
	}
	switch fields[verb] {
	case "allow", "deny", "reject", "limit":
	default:
		return 0, 0, nil, fmt.Errorf("%w: unsupported UFW rule operation", ErrInvalidFirewallChange)
	}
	for _, field := range fields[1:] {
		if len(field) > 256 || strings.HasPrefix(field, "-") || strings.ContainsAny(field, "\x00\r\n;'\"\\$`") {
			return 0, 0, nil, fmt.Errorf("%w: unsupported UFW rule argument", ErrInvalidFirewallChange)
		}
	}
	if hasComment {
		if len(comment) < 2 || (comment[0] != '\'' && comment[0] != '"') || comment[len(comment)-1] != comment[0] {
			return 0, 0, nil, fmt.Errorf("%w: ambiguous UFW rule comment", ErrInvalidFirewallChange)
		}
		comment = comment[1 : len(comment)-1]
		if strings.ContainsAny(comment, "\x00\r\n") {
			return 0, 0, nil, fmt.Errorf("%w: invalid UFW comment", ErrInvalidFirewallChange)
		}
	}
	if strings.Contains(line, "Firewall-UI ") || strings.Contains(comment, "Firewall-UI") {
		return 0, 0, nil, fmt.Errorf("%w: panel-managed rules cannot be removed as external", ErrInvalidFirewallChange)
	}
	var target string
	// UFW may use 'ufw deny 1234/tcp' or 'ufw deny to any port 1234 proto tcp'.
	if verb+1 < len(fields) {
		target = fields[verb+1]
	}
	if target == "to" || target == "from" || target == "in" || target == "out" || target == "on" {
		target = ""
	}
	afterTo := false
	for i := verb + 1; i < len(fields); i++ {
		switch fields[i] {
		case "to":
			afterTo = true
		case "port":
			if afterTo && i+1 < len(fields) {
				target = fields[i+1]
			}
		}
	}
	if target == "" {
		return 0, 0, nil, fmt.Errorf("%w: destination port is unknown", ErrInvalidFirewallChange)
	}
	number := strings.SplitN(target, "/", 2)[0]
	number = strings.ReplaceAll(number, ":", "-")
	pieces := strings.Split(number, "-")
	if len(pieces) < 1 || len(pieces) > 2 {
		return 0, 0, nil, fmt.Errorf("%w: ambiguous port range", ErrInvalidFirewallChange)
	}
	start, err := strconv.Atoi(pieces[0])
	if err != nil || start < 1 || start > 65535 {
		return 0, 0, nil, fmt.Errorf("%w: invalid destination port", ErrInvalidFirewallChange)
	}
	end := start
	if len(pieces) == 2 {
		end, err = strconv.Atoi(pieces[1])
		if err != nil || end < start || end > 65535 {
			return 0, 0, nil, fmt.Errorf("%w: invalid destination port range", ErrInvalidFirewallChange)
		}
	}
	args := append([]string{"--force", "delete"}, fields[1:]...)
	if hasComment {
		args = append(args, "comment", comment)
	}
	return start, end, args, nil
}

// Only exact rich-rule destination ports are supported for deletion. Service,
// protocol-wide and other broad rich rules are deliberately read-only.
func parseExternalRichDestination(raw string) (int, int, error) {
	if !strings.HasPrefix(raw, "rule ") || len(raw) > 2048 ||
		strings.ContainsAny(raw, "\x00\r\n") || strings.Contains(raw, "Firewall-UI") {
		return 0, 0, fmt.Errorf("%w: unsupported rich rule", ErrInvalidFirewallChange)
	}
	needle := `port port="`
	idx := strings.Index(raw, needle)
	if idx < 0 {
		return 0, 0, fmt.Errorf("%w: rich rule has no explicit destination port", ErrInvalidFirewallChange)
	}
	number := raw[idx+len(needle):]
	endQuote := strings.IndexByte(number, '"')
	if endQuote < 0 {
		return 0, 0, fmt.Errorf("%w: invalid rich-rule port", ErrInvalidFirewallChange)
	}
	pieces := strings.Split(number[:endQuote], "-")
	if len(pieces) < 1 || len(pieces) > 2 {
		return 0, 0, fmt.Errorf("%w: invalid rich-rule port range", ErrInvalidFirewallChange)
	}
	start, err := strconv.Atoi(pieces[0])
	if err != nil || start < 1 || start > 65535 {
		return 0, 0, fmt.Errorf("%w: invalid rich-rule port", ErrInvalidFirewallChange)
	}
	end := start
	if len(pieces) == 2 {
		end, err = strconv.Atoi(pieces[1])
		if err != nil || end < start || end > 65535 {
			return 0, 0, fmt.Errorf("%w: invalid rich-rule port range", ErrInvalidFirewallChange)
		}
	}
	return start, end, nil
}

func removableExternalRule(raw, backend string, safety []FirewallRule) bool {
	if raw == "" || len(raw) > 2048 || strings.ContainsAny(raw, "\x00\r\n") {
		return false
	}
	var start, end int
	var err error
	switch backend {
	case "ufw":
		start, end, _, err = parseExternalUFWDestination(raw)
	case "firewalld":
		start, end, err = parseExternalRichDestination(raw)
	default:
		return false
	}
	if err != nil {
		return false
	}
	for _, protected := range safety {
		if isFirewallSafetyRule(protected) && protected.Port >= start && protected.Port <= end {
			return false
		}
	}
	return true
}

// DeleteUnknownRuleSafe only deletes an exact, presently observed, external
// rule. Never infer a target from client-supplied port fields or touch the
// Firewall-UI ownership ledger. All calls are serialized with auto-sync.
func (s *FirewallService) DeleteUnknownRuleSafe(ctx context.Context, raw string, safetyPort int) error {
	firewallMu.Lock()
	defer firewallMu.Unlock()
	if raw == "" || len(raw) > 2048 || strings.ContainsAny(raw, "\x00\r\n") {
		return fmt.Errorf("%w: invalid external rule", ErrInvalidFirewallChange)
	}
	backend, err := detectManagedFirewallBackend(ctx)
	if err != nil {
		return err
	}
	safety, err := s.managedDesiredRules(false, safetyPort)
	if err != nil {
		return err
	}
	if !removableExternalRule(raw, backend.name, safety) {
		return fmt.Errorf("%w: the rule may affect SSH or panel access, or its destination is ambiguous", ErrInvalidFirewallChange)
	}
	_, unknown, err := observedHostRules(ctx, backend)
	if err != nil {
		return err
	}
	matches := 0
	for _, rule := range unknown {
		if rule.Raw == raw && rule.Reason != "truncated" {
			matches++
		}
	}
	if matches != 1 {
		return fmt.Errorf("%w: external rule changed, disappeared or is duplicated; refresh first", ErrInvalidFirewallChange)
	}
	switch backend.name {
	case "ufw":
		_, _, args, err := parseExternalUFWDestination(raw)
		if err != nil {
			return err
		}
		if _, err := runFirewallCommand(ctx, backend.binary, args...); err != nil {
			return fmt.Errorf("delete external UFW rule: %w", err)
		}
	case "firewalld":
		if _, _, err := parseExternalRichDestination(raw); err != nil {
			return err
		}
		if err := removeFirewalldRichRule(ctx, backend, raw); err != nil {
			return fmt.Errorf("delete external firewalld rule: %w", err)
		}
	default:
		return fmt.Errorf("%w: unsupported backend", ErrInvalidFirewallChange)
	}
	_, after, err := observedHostRules(ctx, backend)
	if err != nil {
		return fmt.Errorf("verify deleted external rule: %w", err)
	}
	for _, rule := range after {
		if rule.Raw == raw {
			return errors.New("external rule still present after deletion")
		}
	}
	return nil
}
