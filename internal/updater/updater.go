package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/SawaMEN/Firewall-UI/internal/appconfig"
	"github.com/SawaMEN/Firewall-UI/internal/buildinfo"
)

const (
	stableManifestURL = "https://github.com/SawaMEN/Firewall-UI/releases/latest/download/update.json"
	devManifestURL    = "https://github.com/SawaMEN/Firewall-UI/releases/download/dev/update.json"
	maxManifestSize   = 1 << 20
	maxBinarySize     = 128 << 20
)

var releaseAssetPath = regexp.MustCompile(`^/SawaMEN/Firewall-UI/releases/download/[A-Za-z0-9._-]+/firewall-ui-linux-` + runtime.GOARCH + `$`)

type Asset struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	Version   string           `json:"version"`
	Channel   string           `json:"channel"`
	Commit    string           `json:"commit"`
	BuildTime string           `json:"buildTime"`
	Assets    map[string]Asset `json:"assets"`
}

type Status struct {
	CurrentVersion  string `json:"currentVersion"`
	CurrentChannel  string `json:"currentChannel"`
	CurrentCommit   string `json:"currentCommit"`
	SelectedChannel string `json:"selectedChannel"`
	LatestVersion   string `json:"latestVersion"`
	LatestCommit    string `json:"latestCommit"`
	Available       bool   `json:"available"`
	Restarting      bool   `json:"restarting,omitempty"`
}

type Manager struct {
	client   *http.Client
	restart  func()
	mu       sync.Mutex
	applying bool
	trigger  chan struct{}
}

func New(restart func()) *Manager {
	return &Manager{
		client:  &http.Client{Timeout: 30 * time.Second},
		restart: restart,
		trigger: make(chan struct{}, 1),
	}
}

func (m *Manager) Trigger() {
	select {
	case m.trigger <- struct{}{}:
	default:
	}
}

func normalizeChannel(channel string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(channel)) {
	case "stable":
		return "stable", nil
	case "dev":
		return "dev", nil
	default:
		return "", fmt.Errorf("unsupported update channel %q", channel)
	}
}

func manifestURL(channel string) (string, error) {
	switch channel {
	case "stable":
		return stableManifestURL, nil
	case "dev":
		return devManifestURL, nil
	default:
		return "", fmt.Errorf("unsupported update channel %q", channel)
	}
}

func (m *Manager) fetchManifest(ctx context.Context, channel string) (Manifest, error) {
	channel, err := normalizeChannel(channel)
	if err != nil {
		return Manifest{}, err
	}
	endpoint, err := manifestURL(channel)
	if err != nil {
		return Manifest{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Manifest{}, err
	}
	req.Header.Set("User-Agent", "Firewall-UI updater")
	req.Header.Set("Accept", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return Manifest{}, fmt.Errorf("fetch update manifest: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return Manifest{}, fmt.Errorf("fetch update manifest: HTTP %s", resp.Status)
	}
	var manifest Manifest
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestSize+1))
	if err != nil {
		return Manifest{}, fmt.Errorf("read update manifest: %w", err)
	}
	if len(raw) > maxManifestSize {
		return Manifest{}, errors.New("update manifest is too large")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode update manifest: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Manifest{}, errors.New("update manifest must contain one JSON object")
	}
	if strings.TrimSpace(manifest.Version) == "" || strings.TrimSpace(manifest.Commit) == "" {
		return Manifest{}, errors.New("update manifest is incomplete")
	}
	if manifest.Channel != channel {
		return Manifest{}, fmt.Errorf("update manifest channel %q does not match %q", manifest.Channel, channel)
	}
	asset, ok := manifest.Assets[runtime.GOARCH]
	if !ok {
		return Manifest{}, fmt.Errorf("no update asset for architecture %s", runtime.GOARCH)
	}
	if err := validateAsset(asset); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func validateAsset(asset Asset) error {
	parsed, err := url.Parse(strings.TrimSpace(asset.URL))
	if err != nil || parsed.Scheme != "https" || parsed.Host != "github.com" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" || !releaseAssetPath.MatchString(parsed.Path) {
		return errors.New("update asset must be a Firewall-UI release for this architecture")
	}
	checksum := strings.ToLower(strings.TrimSpace(asset.SHA256))
	if len(checksum) != sha256.Size*2 {
		return errors.New("invalid update asset SHA-256")
	}
	if _, err := hex.DecodeString(checksum); err != nil {
		return errors.New("invalid update asset SHA-256")
	}
	return nil
}

func (m *Manager) Check(ctx context.Context, channel string) (Status, error) {
	channel, err := normalizeChannel(channel)
	if err != nil {
		return Status{}, err
	}
	manifest, err := m.fetchManifest(ctx, channel)
	if err != nil {
		return Status{}, err
	}
	return statusFor(channel, manifest), nil
}

func statusFor(channel string, manifest Manifest) Status {
	current := buildinfo.Current()
	available := false
	switch channel {
	case "dev":
		available = current.Channel != "dev" || strings.TrimSpace(current.Commit) != strings.TrimSpace(manifest.Commit)
	case "stable":
		available = current.Channel != "stable" || stableVersionNewer(current.Version, manifest.Version)
	}
	return Status{
		CurrentVersion:  current.Version,
		CurrentChannel:  current.Channel,
		CurrentCommit:   current.Commit,
		SelectedChannel: channel,
		LatestVersion:   manifest.Version,
		LatestCommit:    manifest.Commit,
		Available:       available,
	}
}

func stableVersionNewer(current, latest string) bool {
	if strings.TrimSpace(current) == strings.TrimSpace(latest) {
		return false
	}
	currentParts, currentOK := numericVersion(current)
	latestParts, latestOK := numericVersion(latest)
	if !currentOK || !latestOK {
		return true
	}
	size := len(currentParts)
	if len(latestParts) > size {
		size = len(latestParts)
	}
	for len(currentParts) < size {
		currentParts = append(currentParts, 0)
	}
	for len(latestParts) < size {
		latestParts = append(latestParts, 0)
	}
	for i := 0; i < size; i++ {
		if latestParts[i] > currentParts[i] {
			return true
		}
		if latestParts[i] < currentParts[i] {
			return false
		}
	}
	return false
}

func numericVersion(value string) ([]int, bool) {
	value = strings.TrimPrefix(strings.TrimSpace(value), "v")
	if value == "" {
		return nil, false
	}
	parts := strings.Split(value, ".")
	out := make([]int, 0, len(parts))
	for _, part := range parts {
		if part == "" {
			return nil, false
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

func (m *Manager) Apply(ctx context.Context, channel string) (Status, error) {
	channel, err := normalizeChannel(channel)
	if err != nil {
		return Status{}, err
	}

	m.mu.Lock()
	if m.applying {
		m.mu.Unlock()
		return Status{}, errors.New("an update is already in progress")
	}
	m.applying = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.applying = false
		m.mu.Unlock()
	}()

	manifest, err := m.fetchManifest(ctx, channel)
	if err != nil {
		return Status{}, err
	}
	status := statusFor(channel, manifest)
	if !status.Available {
		return status, nil
	}
	if runtime.GOOS != "linux" {
		return Status{}, errors.New("self-update is supported on Linux only")
	}
	if os.Geteuid() != 0 {
		return Status{}, errors.New("self-update requires root privileges")
	}
	asset := manifest.Assets[runtime.GOARCH]
	if err := m.downloadAndReplace(ctx, asset); err != nil {
		return Status{}, err
	}

	status.CurrentVersion = manifest.Version
	status.CurrentChannel = manifest.Channel
	status.CurrentCommit = manifest.Commit
	status.Available = false
	status.Restarting = m.restart != nil
	if m.restart != nil {
		go func() {
			time.Sleep(600 * time.Millisecond)
			m.restart()
		}()
	}
	return status, nil
}

func (m *Manager) downloadAndReplace(ctx context.Context, asset Asset) error {
	if err := validateAsset(asset); err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate executable: %w", err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}
	dir := filepath.Dir(executable)
	tmp, err := os.CreateTemp(dir, ".firewall-ui-update-*")
	if err != nil {
		return fmt.Errorf("create update file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.URL, nil)
	if err != nil {
		_ = tmp.Close()
		return err
	}
	req.Header.Set("User-Agent", "Firewall-UI updater")
	resp, err := m.client.Do(req)
	if err != nil {
		_ = tmp.Close()
		return fmt.Errorf("download update: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = tmp.Close()
		return fmt.Errorf("download update: HTTP %s", resp.Status)
	}

	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(tmp, hash), io.LimitReader(resp.Body, maxBinarySize+1))
	if err != nil {
		_ = tmp.Close()
		return fmt.Errorf("download update: %w", err)
	}
	if written > maxBinarySize {
		_ = tmp.Close()
		return errors.New("downloaded update is too large")
	}
	got := hex.EncodeToString(hash.Sum(nil))
	want := strings.ToLower(strings.TrimSpace(asset.SHA256))
	if got != want {
		_ = tmp.Close()
		return fmt.Errorf("update checksum mismatch: got %s", got)
	}
	if err := tmp.Chmod(0755); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("set update permissions: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync update file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close update file: %w", err)
	}
	previous := executable + ".previous"
	_ = os.Remove(previous)
	if err := os.Rename(executable, previous); err != nil {
		return fmt.Errorf("backup current executable: %w", err)
	}
	if err := os.Rename(tmpName, executable); err != nil {
		_ = os.Rename(previous, executable)
		return fmt.Errorf("replace executable: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func (m *Manager) Run(ctx context.Context, configPath string) {
	initial := time.NewTimer(15 * time.Second)
	defer initial.Stop()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-initial.C:
		case <-ticker.C:
		case <-m.trigger:
		}

		cfg, err := appconfig.Load(configPath)
		if err != nil || cfg.UpdateChannel != "dev" {
			continue
		}
		updateCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		status, err := m.Check(updateCtx, "dev")
		if err == nil && status.Available {
			_, _ = m.Apply(updateCtx, "dev")
		}
		cancel()
	}
}
