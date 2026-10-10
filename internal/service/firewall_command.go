package service

import (
	"context"
	"os"
	"os/exec"

	"github.com/SawaMEN/Firewall-UI/internal/hostexec"
)

func firewallCommand(ctx context.Context, binary string, args ...string) *exec.Cmd {
	cmd := hostexec.CommandContext(ctx, binary, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	return cmd
}
