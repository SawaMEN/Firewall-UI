package rollback

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/SawaMEN/Firewall-UI/internal/service"
)

type Pending struct {
	Token    string    `json:"token"`
	Deadline time.Time `json:"deadline"`
}

type entry struct {
	timer    *time.Timer
	rollback func(service.FirewallBackup)
	backup   service.FirewallBackup
}

type Manager struct {
	mu      sync.Mutex
	entries map[string]*entry
	running bool
}

func NewManager() *Manager {
	return &Manager{entries: map[string]*entry{}}
}

func (m *Manager) Begin(backup service.FirewallBackup, ttl time.Duration, rollback func(service.FirewallBackup)) (Pending, error) {
	if ttl <= 0 {
		return Pending{}, errors.New("rollback timeout must be positive")
	}
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return Pending{}, err
	}
	token := hex.EncodeToString(raw)
	deadline := time.Now().Add(ttl)
	item := &entry{backup: backup, rollback: rollback}

	m.mu.Lock()
	if len(m.entries) != 0 || m.running {
		m.mu.Unlock()
		return Pending{}, errors.New("a rollback transaction is already pending")
	}
	item.timer = time.AfterFunc(ttl, func() {
		m.mu.Lock()
		current, ok := m.entries[token]
		if ok {
			delete(m.entries, token)
			m.running = true
		}
		m.mu.Unlock()
		if ok {
			defer func() {
				m.mu.Lock()
				m.running = false
				m.mu.Unlock()
			}()
		}
		if ok && current.rollback != nil {
			current.rollback(current.backup)
		}
	})
	m.entries[token] = item
	m.mu.Unlock()
	return Pending{Token: token, Deadline: deadline.UTC()}, nil
}

func (m *Manager) HasPending() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries) != 0 || m.running
}

func (m *Manager) Confirm(token string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	item, ok := m.entries[token]
	if !ok {
		return false
	}
	delete(m.entries, token)
	if item.timer != nil {
		item.timer.Stop()
	}
	return true
}
