package server

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/SawaMEN/Firewall-UI/internal/appconfig"
	"github.com/SawaMEN/Firewall-UI/internal/security"
)

func TestConcurrentSettingsAndTOTPKeepBothChanges(t *testing.T) {
	for i := 0; i < 20; i++ {
		s := New("admin", "test-password", 8088, fstest.MapFS{})
		s.ConfigPath = filepath.Join(t.TempDir(), "config.json")
		start := make(chan struct{})
		results := make(chan *httptest.ResponseRecorder, 2)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			w := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "/api/settings", bytes.NewBufferString(`{"listenHost":"0.0.0.0","listenPort":8088,"updateChannel":"dev"}`))
			r.RemoteAddr = "127.0.0.1:12345"
			s.settings(w, r)
			results <- w
		}()
		go func() {
			defer wg.Done()
			<-start
			w := httptest.NewRecorder()
			s.setupTOTP(w, httptest.NewRequest("POST", "/api/security/totp/setup", nil))
			results <- w
		}()
		close(start)
		wg.Wait()
		close(results)
		for w := range results {
			var result struct {
				Success bool `json:"success"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || !result.Success {
				t.Fatalf("request failed: %s", w.Body)
			}
		}
		saved, err := appconfig.Load(s.ConfigPath)
		if err != nil {
			t.Fatal(err)
		}
		if saved.ListenHost != "0.0.0.0" || saved.UpdateChannel != "dev" || saved.TOTPSecret == "" {
			t.Fatal("concurrent operations lost settings or the TOTP secret")
		}
		if !reflect.DeepEqual(saved, s.RuntimeConfig) {
			t.Fatal("disk and runtime configurations differ")
		}
	}
}

func TestRuntimeRollbackPreservesTwoFactorSettings(t *testing.T) {
	s := New("admin", "test-password", 8088, fstest.MapFS{})
	s.ConfigPath = filepath.Join(t.TempDir(), "config.json")
	old := s.RuntimeConfig
	s.RuntimeConfig.ExternalPort = 443
	expected := runtimeBackupFromConfig(s.RuntimeConfig)
	secret, err := security.GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	s.RuntimeConfig.TOTPEnabled = true
	s.RuntimeConfig.TOTPSecret = secret
	if err := s.restoreRuntimeAfterRollback(old, expected); err != nil {
		t.Fatal(err)
	}
	saved, err := appconfig.Load(s.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if saved.ExternalPort != old.ExternalPort || !saved.TOTPEnabled || saved.TOTPSecret != secret {
		t.Fatal("rollback failed to restore runtime settings or overwrote 2FA")
	}
	if !reflect.DeepEqual(saved, s.RuntimeConfig) {
		t.Fatal("runtime and disk differ after rollback")
	}
}

func TestRuntimeRollbackDoesNotOverwriteLaterEdits(t *testing.T) {
	s := New("admin", "test-password", 8088, fstest.MapFS{})
	s.ConfigPath = filepath.Join(t.TempDir(), "config.json")
	old := s.RuntimeConfig
	s.RuntimeConfig.ExternalPort = 443
	expected := runtimeBackupFromConfig(s.RuntimeConfig)
	s.RuntimeConfig.UpdateChannel = "dev"
	current := s.RuntimeConfig
	if err := appconfig.Save(s.ConfigPath, current); err != nil {
		t.Fatal(err)
	}
	if err := s.restoreRuntimeAfterRollback(old, expected); err == nil {
		t.Fatal("newer settings were overwritten")
	}
	saved, err := appconfig.Load(s.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(saved, current) || !reflect.DeepEqual(s.RuntimeConfig, current) {
		t.Fatal("newer configuration changed")
	}
}

func TestRuntimeRollbackWriteFailureKeepsMemory(t *testing.T) {
	s := New("admin", "test-password", 8088, fstest.MapFS{})
	s.ConfigPath = t.TempDir() // A directory cannot be replaced by the config file.
	old := s.RuntimeConfig
	s.RuntimeConfig.ExternalPort = 443
	current := s.RuntimeConfig
	if err := s.restoreRuntimeAfterRollback(old, runtimeBackupFromConfig(current)); err == nil {
		t.Fatal("accepted a failed save")
	}
	if !reflect.DeepEqual(s.RuntimeConfig, current) {
		t.Fatal("failed disk write changed runtime state")
	}
	entries, err := os.ReadDir(s.ConfigPath)
	if err != nil || len(entries) != 0 {
		t.Fatal("temporary config was not cleaned up")
	}
}

func TestBackupDecoderRejectsTrailingJSON(t *testing.T) {
	for _, payload := range []string{`{"version":1} {"version":2}`, `{"version":1} garbage`} {
		var backup fullBackup
		r := httptest.NewRequest("POST", "/api/backup/restore", bytes.NewBufferString(payload))
		if err := decodeJSONLimit(httptest.NewRecorder(), r, &backup, 4096); err == nil {
			t.Fatal("accepted trailing JSON/data")
		}
	}
	var backup fullBackup
	r := httptest.NewRequest("POST", "/api/backup/restore", bytes.NewBufferString(`{"version":1}`))
	if err := decodeJSONLimit(httptest.NewRecorder(), r, &backup, 4096); err != nil {
		t.Fatal(err)
	}
}
