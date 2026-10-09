package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func (s *Server) username() string { s.mu.Lock(); defer s.mu.Unlock(); return s.Username }

func (s *Server) credentials(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		reply(w, http.StatusMethodNotAllowed, nil, fmt.Errorf("method not allowed"))
		return
	}
	var req struct {
		Username        string `json:"username"`
		Password        string `json:"password"`
		CurrentPassword string `json:"currentPassword"`
	}
	if err := decode(w, r, &req); err != nil {
		reply(w, 400, nil, err)
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" || strings.ContainsAny(req.Username+req.Password, "\r\n\x00") {
		reply(w, 400, nil, fmt.Errorf("Логин и пароль должны быть непустыми, без переводов строки"))
		return
	}
	s.configMu.Lock()
	defer s.configMu.Unlock()
	s.mu.Lock()
	got, want := sha256.Sum256([]byte(req.CurrentPassword)), sha256.Sum256([]byte(s.Password))
	valid := subtle.ConstantTimeCompare(got[:], want[:]) == 1
	s.mu.Unlock()
	if !valid {
		reply(w, 403, nil, fmt.Errorf("Неверный текущий пароль"))
		return
	}
	// systemd reads this file on every service start. Atomic replacement prevents
	// a partial credential file from locking out the administrator after restart.
	envPath := filepath.Join(filepath.Dir(s.ConfigPath), "environment")
	if s.ConfigPath == "" {
		reply(w, 500, nil, fmt.Errorf("Configuration path is not set"))
		return
	}
	escape := func(v string) string { return strings.NewReplacer("\\", "\\\\", "\"", "\\\"").Replace(v) }
	raw := fmt.Sprintf("FIREWALL_UI_USERNAME=\"%s\"\nFIREWALL_UI_PASSWORD=\"%s\"\n", escape(req.Username), escape(req.Password))
	if err := writeCredentialFile(envPath, []byte(raw)); err != nil {
		reply(w, 500, nil, err)
		return
	}
	s.mu.Lock()
	s.Username, s.Password = req.Username, req.Password
	s.sessions = map[string]session{}
	s.attempts = map[string]attempt{}
	s.mu.Unlock()
	s.audit(r, "credentials.change", true, "", nil)
	reply(w, 200, map[string]bool{"loginRequired": true}, nil)
}

func writeCredentialFile(path string, raw []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".credentials-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
