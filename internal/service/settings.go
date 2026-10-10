package service

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

// Configure must run before serving requests or starting the synchronization worker.
var statePath string
var listenPort int
var externalPort int
var settingsMu sync.Mutex

func Configure(path string, port, external int) {
	statePath, listenPort, externalPort = path, port, external
}

type SettingService struct{}
type setting struct{ Value string }

func readSettings() (map[string]string, error) {
	values := map[string]string{}
	raw, err := os.ReadFile(statePath)
	if os.IsNotExist(err) {
		return values, nil
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(raw, &values); err != nil {
		return nil, fmt.Errorf("read settings: %w", err)
	}
	if values == nil {
		return nil, fmt.Errorf("settings must be a JSON object, not null")
	}
	return values, nil
}
func (*SettingService) getSetting(key string) (setting, error) {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	values, err := readSettings()
	if err != nil {
		return setting{}, err
	}
	value, ok := values[key]
	if !ok {
		return setting{}, os.ErrNotExist
	}
	return setting{value}, nil
}
func (*SettingService) setString(key, value string) error {
	settingsMu.Lock()
	defer settingsMu.Unlock()
	values, err := readSettings()
	if err != nil {
		return err
	}
	values[key] = value
	raw, err := json.MarshalIndent(values, "", "  ")
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(statePath), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(statePath), ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), statePath)
}
func (s *SettingService) setBool(k string, v bool) error {
	return s.setString(k, strconv.FormatBool(v))
}
func (s *SettingService) setInt(k string, v int) error { return s.setString(k, strconv.Itoa(v)) }
func (*SettingService) GetPort() (int, error)          { return listenPort, nil }
