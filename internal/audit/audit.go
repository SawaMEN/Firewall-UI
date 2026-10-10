package audit

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/SawaMEN/Firewall-UI/internal/jsonlog"
)

type Entry struct {
	Time     time.Time      `json:"time"`
	User     string         `json:"user,omitempty"`
	RemoteIP string         `json:"remoteIp,omitempty"`
	Action   string         `json:"action"`
	Success  bool           `json:"success"`
	Message  string         `json:"message,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type Logger struct {
	path string
	mu   sync.Mutex
}

func New(path string) *Logger {
	return &Logger{path: path}
}

func (l *Logger) Append(entry Entry) error {
	if l == nil || l.path == "" {
		return nil
	}
	entry.Time = time.Now().UTC()
	raw, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if len(raw) > 1048576 {
		return errors.New("audit record is too large")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(l.path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(raw, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

func (l *Logger) Recent(limit int) ([]Entry, error) {
	if l == nil || l.path == "" {
		return []Entry{}, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return jsonlog.Recent[Entry](l.path, limit, 1048576)
}
