package service

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

func findUFWManagedRuleNumber(status, comment, spec string) int {
	for _, raw := range strings.Split(status, "\n") {
		line := strings.TrimSpace(raw)
		before, foundComment, hasComment := strings.Cut(line, "#")
		if !strings.HasPrefix(line, "[") || !hasComment || strings.TrimSpace(foundComment) != comment {
			continue
		}
		line = strings.TrimSpace(before)
		closeBracket := strings.Index(line, "]")
		if closeBracket < 0 {
			continue
		}
		numberText := strings.TrimSpace(strings.TrimPrefix(line[:closeBracket], "["))
		number, err := strconv.Atoi(numberText)
		if err != nil || number < 1 {
			continue
		}
		if spec == "" {
			return number
		}
		fields := strings.Fields(strings.TrimSpace(line[closeBracket+1:]))
		if len(fields) > 0 && strings.EqualFold(fields[0], spec) {
			return number
		}
	}
	return 0
}

func deleteUFWManagedRules(ctx context.Context, binary, comment, spec string) error {
	for attempts := 0; attempts < 128; attempts++ {
		status, err := runFirewallCommand(ctx, binary, "status", "numbered")
		if err != nil {
			return err
		}
		if strings.Contains(status, "Status: inactive") {
			added, err := runFirewallCommand(ctx, binary, "show", "added")
			if err != nil {
				return err
			}
			for _, line := range strings.Split(added, "\n") {
				args := ownedUFWDeleteArgs(line)
				if len(args) < 6 || args[len(args)-1] != comment {
					continue
				}
				if spec != "" && args[3] != spec {
					continue
				}
				if _, err := runFirewallCommand(ctx, binary, args...); err != nil {
					return err
				}
			}
			return nil
		}
		number := findUFWManagedRuleNumber(status, comment, spec)
		if number == 0 {
			return nil
		}
		if _, err := runFirewallCommand(ctx, binary, "--force", "delete", strconv.Itoa(number)); err != nil {
			return fmt.Errorf("delete UFW rule %d: %w", number, err)
		}
	}
	return fmt.Errorf("too many matching UFW rules for comment %q", comment)
}
