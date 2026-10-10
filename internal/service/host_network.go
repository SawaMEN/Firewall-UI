package service

import (
	"context"
	"os"
	"os/exec"
)

// Proxy-mode containers keep their HTTP listener in the Docker network. Only
// firewall commands enter the host network namespace; PID 1 is the host init
// process because the Compose service uses pid: host.
func hostNetworkNamespace() bool {
	return os.Getenv("FIREWALL_UI_CONTAINER") == "1" && os.Getenv("FIREWALL_UI_HOST_NETNS") == "1"
}

func firewallCommand(ctx context.Context, binary string, args ...string) *exec.Cmd {
	if hostNetworkNamespace() {
		args = append([]string{"--net=/proc/1/ns/net", "--", binary}, args...)
		binary = "nsenter"
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	return cmd
}

// CheckHostNetworkNamespace fails before HTTP starts if namespace access is
// unavailable. Never silently fall back to the container's firewall.
func CheckHostNetworkNamespace(ctx context.Context) error {
	if !hostNetworkNamespace() {
		return nil
	}
	_, err := runFirewallCommand(ctx, "true")
	return err
}
