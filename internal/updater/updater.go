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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	repositoryURL = "https://github.com/SawaMEN/Firewall-UI"
	maxMetadata   = 1 << 20
	maxBinary     = 128 << 20
)

var (
	Version      = "dev"
	Commit       = "unknown"
	BuildChannel = "dev"

	client   = &http.Client{Timeout: 5 * time.Minute}
	updateMu sync.Mutex
)

type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Channel string `json:"channel"`
}

type Manifest struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Channel string `json:"channel"`
}

func Current() Info {
	return Info{
		Version: strings.TrimSpace(Version),
		Commit:  strings.TrimSpace(Commit),
		Channel: strings.TrimSpace(BuildChannel),
	}
}

func releaseBase(channel string) (string, error) {
	switch channel {
	case "stable":
		return repositoryURL + "/releases/latest/download", nil
	case "dev":
		return repositoryURL + "/releases/download/dev", nil
	default:
		return "", fmt.Errorf("unsupported update channel %q", channel)
	}
}

func Remote(ctx context.Context, channel string) (Manifest, error) {
	base, err := releaseBase(channel)
	if err != nil {
		return Manifest{}, err
	}
	raw, err := fetchBytes(ctx, base+"/version.json", maxMetadata)
	if err != nil {
		return Manifest{}, err
	}
	var manifest Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode update manifest: %w", err)
	}
	manifest.Version = strings.TrimSpace(manifest.Version)
	manifest.Commit = strings.TrimSpace(manifest.Commit)
	manifest.Channel = strings.TrimSpace(manifest.Channel)
	if manifest.Version == "" || manifest.Commit == "" {
		return Manifest{}, errors.New("update manifest is incomplete")
	}
	if manifest.Channel != channel {
		return Manifest{}, fmt.Errorf("update manifest channel is %q, want %q", manifest.Channel, channel)
	}
	return manifest, nil
}

func Available(remote Manifest) bool {
	current := Current()
	return current.Version != remote.Version || current.Commit != remote.Commit || current.Channel != remote.Channel
}

func Apply(ctx context.Context, channel string) (bool, Manifest, error) {
	updateMu.Lock()
	defer updateMu.Unlock()

	remote, err := Remote(ctx, channel)
	if err != nil {
		return false, Manifest{}, err
	}
	if !Available(remote) {
		return false, remote, nil
	}
	if runtime.GOOS != "linux" {
		return false, remote, errors.New("self-update is supported only on Linux")
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return false, remote, fmt.Errorf("unsupported update architecture %s", runtime.GOARCH)
	}

	base, err := releaseBase(channel)
	if err != nil {
		return false, remote, err
	}
	asset := "firewall-ui-linux-" + runtime.GOARCH
	checksums, err := fetchBytes(ctx, base+"/checksums.txt", maxMetadata)
	if err != nil {
		return false, remote, err
	}
	expected, err := checksumFor(checksums, asset)
	if err != nil {
		return false, remote, err
	}

	executable, err := os.Executable()
	if err != nil {
		return false, remote, fmt.Errorf("resolve executable: %w", err)
	}
	if resolved, resolveErr := filepath.EvalSymlinks(executable); resolveErr == nil {
		executable = resolved
	}
	if err := replaceExecutable(ctx, executable, base+"/"+asset, expected, remote); err != nil {
		return false, remote, err
	}
	return true, remote, nil
}

func StartDevAutoUpdate(ctx context.Context, interval time.Duration, restart func()) {
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	go func() {
		timer := time.NewTimer(30 * time.Second)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}

			checkCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
			updated, _, _ := Apply(checkCtx, "dev")
			cancel()
			if updated {
				if restart != nil {
					restart()
				}
				return
			}
			timer.Reset(interval)
		}
	}()
}

func replaceExecutable(ctx context.Context, executable, binaryURL, expectedChecksum string, remote Manifest) error {
	dir := filepath.Dir(executable)
	temp, err := os.CreateTemp(dir, ".firewall-ui-update-*")
	if err != nil {
		return fmt.Errorf("create update file: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, binaryURL, nil)
	if err != nil {
		temp.Close()
		return err
	}
	request.Header.Set("User-Agent", "Firewall-UI/"+Current().Version)
	response, err := client.Do(request)
	if err != nil {
		temp.Close()
		return fmt.Errorf("download update: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		temp.Close()
		return fmt.Errorf("download update: HTTP %s", response.Status)
	}

	hash := sha256.New()
	limited := io.LimitReader(response.Body, maxBinary+1)
	written, err := io.Copy(io.MultiWriter(temp, hash), limited)
	if err != nil {
		temp.Close()
		return fmt.Errorf("write update: %w", err)
	}
	if written > maxBinary {
		temp.Close()
		return errors.New("downloaded update is too large")
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if !strings.EqualFold(actual, expectedChecksum) {
		temp.Close()
		return errors.New("downloaded update checksum mismatch")
	}
	if err := temp.Chmod(0755); err != nil {
		temp.Close()
		return fmt.Errorf("chmod update: %w", err)
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return fmt.Errorf("sync update: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close update: %w", err)
	}

	output, err := exec.CommandContext(ctx, tempName, "-version-json").Output()
	if err != nil {
		return fmt.Errorf("validate update executable: %w", err)
	}
	var built Info
	if err := json.Unmarshal(output, &built); err != nil {
		return fmt.Errorf("validate update metadata: %w", err)
	}
	if built.Version != remote.Version || built.Commit != remote.Commit || built.Channel != remote.Channel {
		return fmt.Errorf(
			"update metadata mismatch: got %s/%s/%s",
			built.Version,
			built.Commit,
			built.Channel,
		)
	}

	if err := os.Rename(tempName, executable); err != nil {
		return fmt.Errorf("replace executable: %w", err)
	}
	if dirHandle, openErr := os.Open(dir); openErr == nil {
		_ = dirHandle.Sync()
		_ = dirHandle.Close()
	}
	return nil
}

func fetchBytes(ctx context.Context, url string, limit int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "Firewall-UI/"+Current().Version)
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", filepath.Base(url), err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %s", filepath.Base(url), response.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("download %s is too large", filepath.Base(url))
	}
	return raw, nil
}

func checksumFor(raw []byte, asset string) (string, error) {
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimPrefix(fields[len(fields)-1], "*")
		if name != asset {
			continue
		}
		sum := strings.ToLower(fields[0])
		if len(sum) != sha256.Size*2 {
			return "", fmt.Errorf("invalid checksum for %s", asset)
		}
		if _, err := hex.DecodeString(sum); err != nil {
			return "", fmt.Errorf("invalid checksum for %s", asset)
		}
		return sum, nil
	}
	return "", fmt.Errorf("checksum for %s not found", asset)
}
