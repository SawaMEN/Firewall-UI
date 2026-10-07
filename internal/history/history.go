package history

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/SawaMEN/Firewall-UI/internal/service"
)

type Snapshot struct {
	ID        string                 `json:"id"`
	CreatedAt time.Time              `json:"createdAt"`
	Reason    string                 `json:"reason"`
	Backup    service.FirewallBackup `json:"backup"`
}

type Store struct {
	path string
	mu   sync.Mutex
}

func New(path string) *Store {
	return &Store{path: path}
}

func (s *Store) Add(snapshot Snapshot) error {
	if s == nil || s.path == "" {
		return nil
	}
	snapshot.CreatedAt = time.Now().UTC()
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(raw, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

func (s *Store) Recent(limit int) ([]Snapshot, error) {
	if s == nil || s.path == "" {
		return []Snapshot{}, nil
	}
	if limit <= 0 || limit > 100 {
		limit = 30
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return []Snapshot{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	items := make([]Snapshot, 0, limit)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		var snapshot Snapshot
		if json.Unmarshal(scanner.Bytes(), &snapshot) != nil {
			continue
		}
		items = append(items, snapshot)
		if len(items) > limit {
			items = append([]Snapshot(nil), items[len(items)-limit:]...)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	for i, j := 0, len(items)-1; i < j; i, j = i+1, j-1 {
		items[i], items[j] = items[j], items[i]
	}
	return items, nil
}

func (s *Store) Get(id string) (Snapshot, bool, error) {
	items, err := s.Recent(100)
	if err != nil {
		return Snapshot{}, false, err
	}
	for _, item := range items {
		if item.ID == id {
			return item, true, nil
		}
	}
	return Snapshot{}, false, nil
}
