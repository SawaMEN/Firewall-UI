package updater

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDockerProgressAndOldFailures(t *testing.T) {
	dir := t.TempDir()
	m := &DockerManager{dir: dir}
	if err := os.WriteFile(filepath.Join(dir, "auto-update"), []byte("1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	write := func(phase, detail string, updatedAt int64) {
		progress := dockerProgress{Phase: phase, Error: detail, UpdatedAt: updatedAt, Version: "9.0.0", Commit: "new"}
		raw, err := json.Marshal(progress)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "update-status.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().Unix()
	write("downloading", "", now)
	status := Status{CurrentCommit: "old"}
	m.ReadStatus(&status)
	if !status.Automatic || !status.Applying || !status.Available || status.Phase != "downloading" || status.LatestCommit != "new" {
		t.Fatalf("lost Docker progress: %+v", status)
	}
	write("failed", "checksum failed", now-10)
	m.requestedAt = now
	status = Status{}
	m.ReadStatus(&status)
	if status.UpdateError != "" {
		t.Fatal("a previous attempt's error leaked into the new attempt")
	}
	write("failed", "checksum failed", now)
	m.ReadStatus(&status)
	if status.UpdateError != "checksum failed" {
		t.Fatal("lost update failure")
	}
	write("downloading", "", now-901)
	m.requestedAt = 0
	status = Status{}
	m.ReadStatus(&status)
	if status.Applying {
		t.Fatal("stale update still marked busy")
	}
}
