// Package hostexec runs firewall tools in the host mount namespace when the
// privileged Compose deployment shares the host PID and network namespaces.
package hostexec

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

func Enabled() bool {
	return os.Getenv("FIREWALL_UI_CONTAINER") == "1" && os.Getenv("FIREWALL_UI_HOST_FIREWALL") == "1"
}

func CommandContext(ctx context.Context, binary string, args ...string) *exec.Cmd {
	if Enabled() {
		args = append([]string{"--target", "1", "--mount", "--root", "--wd", "--", "/usr/bin/env", "LC_ALL=C", "LANG=C", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", binary}, args...)
		binary = "nsenter"
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	return cmd
}

func LookPath(binary string) (string, error) {
	if !Enabled() {
		return exec.LookPath(binary)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := CommandContext(ctx, "/bin/sh", "-c", `command -v "$1"`, "sh", binary).Output()
	path := strings.TrimSpace(string(out))
	if err != nil || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\r\n") {
		return "", fmt.Errorf("host executable %q not found", binary)
	}
	return path, nil
}
