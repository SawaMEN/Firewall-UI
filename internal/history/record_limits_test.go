package history

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRejectOversizedRecordWithoutCreatingFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent", "log.jsonl")
	store := New(path)
	if err := store.Add(Snapshot{Reason: strings.Repeat("x", 4194304)}); err == nil {
		t.Fatal("accepted a record that the reader cannot decode")
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Fatal("rejected record created files or an empty directory")
	}
	if err := store.Add(Snapshot{Reason: "valid"}); err != nil {
		t.Fatal(err)
	}
	items, err := store.Recent(2)
	if err != nil || len(items) != 1 || items[0].Reason != "valid" {
		t.Fatalf("valid record after rejected append: %+v, %v", items, err)
	}
}
