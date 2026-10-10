package service

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"sync"
	"time"
)

type PortSnapshot struct {
	Ports      []Port          `json:"ports"`
	Containers []ContainerPort `json:"containers"`
	UpdatedAt  time.Time       `json:"updatedAt"`
}

type PortMonitor struct {
	root     string
	interval time.Duration

	mu                 sync.RWMutex
	snapshot           PortSnapshot
	fingerprint        [32]byte
	subscribers        map[chan PortSnapshot]struct{}
	startOnce          sync.Once
	stopped            bool
	containerScanAfter time.Time
	cachedContainers   []ContainerPort
}

func NewPortMonitor(root string, interval time.Duration) *PortMonitor {
	if interval < time.Second {
		interval = time.Second
	}
	return &PortMonitor{
		root:        root,
		interval:    interval,
		subscribers: map[chan PortSnapshot]struct{}{},
	}
}

func (m *PortMonitor) Start(ctx context.Context) {
	m.startOnce.Do(func() {
		m.refresh(ctx)
		go func() {
			ticker := time.NewTicker(m.interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					m.closeSubscribers()
					return
				case <-ticker.C:
					m.refresh(ctx)
				}
			}
		}()
	})
}

func (m *PortMonitor) Snapshot() PortSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return clonePortSnapshot(m.snapshot)
}

func (m *PortMonitor) Subscribe() (<-chan PortSnapshot, func()) {
	ch := make(chan PortSnapshot, 1)
	m.mu.Lock()
	if m.stopped {
		close(ch)
		m.mu.Unlock()
		return ch, func() {}
	}
	m.subscribers[ch] = struct{}{}
	current := clonePortSnapshot(m.snapshot)
	if !current.UpdatedAt.IsZero() {
		ch <- current
	}
	m.mu.Unlock()
	cancel := func() {
		m.mu.Lock()
		if _, ok := m.subscribers[ch]; ok {
			delete(m.subscribers, ch)
			close(ch)
		}
		m.mu.Unlock()
	}
	return ch, cancel
}

func (m *PortMonitor) refresh(ctx context.Context) {
	ports, err := ReadPorts(m.root)
	if err != nil {
		return
	}
	now := time.Now()
	if !now.Before(m.containerScanAfter) {
		m.cachedContainers = ReadContainerPorts(ctx)
		// Container CLI calls are more expensive than reading socket tables.
		m.containerScanAfter = now.Add(max(30*time.Second, m.interval))
	}
	containers := m.cachedContainers
	next := PortSnapshot{Ports: ports, Containers: containers, UpdatedAt: time.Now().UTC()}
	hashPayload, _ := json.Marshal(struct {
		Ports      []Port
		Containers []ContainerPort
	}{ports, containers})
	fingerprint := sha256.Sum256(hashPayload)

	m.publish(next, fingerprint)
}

func (m *PortMonitor) publish(next PortSnapshot, fingerprint [32]byte) {
	m.mu.Lock()
	changed := fingerprint != m.fingerprint
	m.snapshot = next
	m.fingerprint = fingerprint
	if changed {
		for ch := range m.subscribers {
			// Keep the newest sample even when a client is slower than the scan.
			// All sends and closes share this lock.
			select {
			case <-ch:
			default:
			}
			select {
			case ch <- clonePortSnapshot(next):
			default:
			}
		}
	}
	m.mu.Unlock()
}

func (m *PortMonitor) closeSubscribers() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopped = true
	for ch := range m.subscribers {
		close(ch)
		delete(m.subscribers, ch)
	}
}

func clonePortSnapshot(in PortSnapshot) PortSnapshot {
	out := in
	out.Ports = append([]Port{}, in.Ports...)
	for i := range out.Ports {
		out.Ports[i].Processes = append([]Process{}, in.Ports[i].Processes...)
	}
	out.Containers = append([]ContainerPort{}, in.Containers...)
	return out
}
