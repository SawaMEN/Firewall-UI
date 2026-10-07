package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Entry struct {
	Time      time.Time      `json:"time"`
	User      string         `json:"user,omitempty"`
	RemoteIP  string         `json:"remoteIp,omitempty"`
	Action    string         `json:"action"`
	Success   bool           `json:"success"`
	Message   string         `json:"message,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
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
	f, err := os.Open(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return []Entry{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries := make([]Entry, 0, limit)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		var entry Entry
		if json.Unmarshal(scanner.Bytes(), &entry) == nil {
			entries = append(entries, entry)
			if len(entries) > limit {
				copy(entries, entries[len(entries)-limit:])
				entries = entries[:limit]
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
	return entries, nil
}
