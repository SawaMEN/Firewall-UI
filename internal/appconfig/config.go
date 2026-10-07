package appconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	ListenHost    string `json:"listenHost"`
	ListenPort    int    `json:"listenPort"`
	ExternalPort  int    `json:"externalPort"`
	SecureCookies bool   `json:"secureCookies"`
	TLSCert       string `json:"tlsCert,omitempty"`
	TLSKey        string `json:"tlsKey,omitempty"`
	StatePath     string `json:"statePath"`
	UpdateChannel string `json:"updateChannel"`
}

func Default() Config {
	return Config{
		ListenHost:    "127.0.0.1",
		ListenPort:    8088,
		StatePath:     "/var/lib/firewall-ui/state.json",
		UpdateChannel: "stable",
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if strings.TrimSpace(cfg.UpdateChannel) == "" {
		cfg.UpdateChannel = "stable"
	}
	if err := Validate(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func Save(path string, cfg Config) error {
	if err := Validate(cfg); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	f, err := os.CreateTemp(dir, ".config-*")
	if err != nil {
		return fmt.Errorf("create temporary config: %w", err)
	}
	name := f.Name()
	defer os.Remove(name)
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return fmt.Errorf("set config permissions: %w", err)
	}
	if _, err := f.Write(append(raw, '\n')); err != nil {
		f.Close()
		return fmt.Errorf("write config: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("sync config: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close config: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}
	return os.Chmod(path, 0600)
}

func Validate(cfg Config) error {
	host := strings.TrimSpace(cfg.ListenHost)
	if host == "" {
		return errors.New("listen host is required")
	}
	if host != "localhost" && net.ParseIP(host) == nil {
		return fmt.Errorf("invalid listen host %q", host)
	}
	if cfg.ListenPort < 1 || cfg.ListenPort > 65535 {
		return fmt.Errorf("invalid listen port %d", cfg.ListenPort)
	}
	if cfg.ExternalPort < 0 || cfg.ExternalPort > 65535 {
		return fmt.Errorf("invalid external port %d", cfg.ExternalPort)
	}
	if (strings.TrimSpace(cfg.TLSCert) == "") != (strings.TrimSpace(cfg.TLSKey) == "") {
		return errors.New("both TLS certificate and key are required")
	}
	if strings.TrimSpace(cfg.StatePath) == "" || !filepath.IsAbs(cfg.StatePath) {
		return errors.New("statePath must be an absolute path")
	}
	if cfg.UpdateChannel != "stable" && cfg.UpdateChannel != "dev" {
		return fmt.Errorf("invalid update channel %q", cfg.UpdateChannel)
	}
	return nil
}

func (cfg Config) Address() string {
	return net.JoinHostPort(strings.TrimSpace(cfg.ListenHost), fmt.Sprintf("%d", cfg.ListenPort))
}
