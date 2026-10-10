package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/SawaMEN/Firewall-UI/internal/hostexec"
)

// DockerManager delegates image replacement to the host oneshot service. It
// never installs a binary into the container or exposes a Docker socket.
type DockerManager struct {
	dir         string
	mu          sync.Mutex
	requestedAt int64
}

type dockerProgress struct {
	Phase     string `json:"phase"`
	UpdatedAt int64  `json:"updatedAt"`
	Error     string `json:"error"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
}

func NewDockerManager(dir string) *DockerManager {
	if !hostexec.Enabled() || !filepath.IsAbs(dir) || filepath.Clean(dir) == "/" {
		return nil
	}
	return &DockerManager{dir: filepath.Join("/proc/1/root", filepath.Clean(dir))}
}

func (m *DockerManager) ReadStatus(status *Status) {
	if raw, err := os.ReadFile(filepath.Join(m.dir, "auto-update")); err == nil {
		status.Automatic = strings.TrimSpace(string(raw)) == "1"
	}
	file, err := os.Open(filepath.Join(m.dir, "update-status.json"))
	if err != nil {
		return
	}
	defer file.Close()
	var progress dockerProgress
	if err := json.NewDecoder(io.LimitReader(file, 8192)).Decode(&progress); err != nil {
		return
	}
	m.mu.Lock()
	requestedAt := m.requestedAt
	m.mu.Unlock()
	if progress.UpdatedAt < requestedAt || time.Now().Unix()-progress.UpdatedAt > 900 || progress.UpdatedAt > time.Now().Unix()+60 {
		return
	}
	switch progress.Phase {
	case "checking", "downloading", "installing", "restarting":
		status.Applying = true
		status.Phase = progress.Phase
		if progress.Version != "" && progress.Commit != "" {
			status.LatestVersion = progress.Version
			status.LatestCommit = progress.Commit
			status.Available = progress.Commit != status.CurrentCommit
		}
	case "failed":
		status.UpdateError = progress.Error
	}
}

func (m *DockerManager) Start(ctx context.Context) error {
	binary, err := hostexec.LookPath("systemctl")
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.requestedAt = time.Now().Unix()
	m.mu.Unlock()
	out, err := hostexec.CommandContext(ctx, binary, "start", "--no-block", "firewall-ui-docker-update.service").CombinedOutput()
	if err != nil {
		return fmt.Errorf("start Docker update: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
