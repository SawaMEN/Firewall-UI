package service

import (
	"bytes"
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func TestPortSnapshotArraysAndIsolation(t *testing.T) {
	snapshot := PortSnapshot{Ports: []Port{{Port: 80}}}
	clone := clonePortSnapshot(snapshot)
	raw, err := json.Marshal(clone)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(`"processes":null`)) || bytes.Contains(raw, []byte(`"containers":null`)) {
		t.Fatalf("snapshot has null arrays: %s", raw)
	}
	clone.Ports[0].Port = 443
	if snapshot.Ports[0].Port != 80 {
		t.Fatal("snapshot aliases original ports")
	}
	empty := clonePortSnapshot(PortSnapshot{})
	raw, _ = json.Marshal(empty)
	if !bytes.Contains(raw, []byte(`"ports":[]`)) {
		t.Fatalf("empty ports not serialized as an array: %s", raw)
	}
	snapshot.Ports[0].Processes = []Process{{PID: 123, Name: "worker"}}
	clone = clonePortSnapshot(snapshot)
	clone.Ports[0].Processes[0].Name = "changed"
	if snapshot.Ports[0].Processes[0].Name != "worker" {
		t.Fatal("snapshot aliases process list")
	}
}

func TestPortMonitorKeepsLatestSample(t *testing.T) {
	m := NewPortMonitor("/proc", time.Second)
	m.snapshot = PortSnapshot{Ports: []Port{{Port: 80}}, UpdatedAt: time.Now()}
	ch, cancel := m.Subscribe()
	defer cancel()
	m.publish(PortSnapshot{Ports: []Port{{Port: 443}}, UpdatedAt: time.Now()}, [32]byte{1})
	if sample := <-ch; len(sample.Ports) != 1 || sample.Ports[0].Port != 443 {
		t.Fatalf("slow subscriber received stale sample: %+v", sample)
	}
}

func TestPortMonitorConcurrentSubscriptionAndClose(t *testing.T) {
	for i := 0; i < 100; i++ {
		m := NewPortMonitor("/proc", time.Second)
		m.snapshot = PortSnapshot{UpdatedAt: time.Now()}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, cancel := m.Subscribe()
			cancel()
		}()
		go func() {
			defer wg.Done()
			m.publish(PortSnapshot{UpdatedAt: time.Now()}, [32]byte{1})
			m.closeSubscribers()
		}()
		wg.Wait()
	}
}
