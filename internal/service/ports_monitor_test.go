package service

import (
	"bytes"
	"encoding/json"
	"testing"
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
