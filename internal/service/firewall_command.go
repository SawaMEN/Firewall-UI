package service

import (
	"context"
	"os"
	"os/exec"
)

func firewallCommand(ctx context.Context, binary string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	return cmd
}
