package jsonlog

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRecentRecoversAfterMalformedAndOversizedRecords(t *testing.T) {
	type record struct {
		ID int `json:"id"`
	}
	path := filepath.Join(t.TempDir(), "log.jsonl")
	raw := "{\"id\":1}\nnull\ninvalid\n" + strings.Repeat("x", 200000) + "\n{\"id\":2}\n{\"id\":3}\n{\"id\":4}"
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	items, err := Recent[record](path, 2, 100)
	if err != nil || !reflect.DeepEqual(items, []record{{4}, {3}}) {
		t.Fatalf("recent records were lost or reordered: %+v, %v", items, err)
	}
	items, err = Recent[record](path, 10, 100)
	if err != nil || !reflect.DeepEqual(items, []record{{4}, {3}, {2}, {1}}) {
		t.Fatalf("malformed records became entries: %+v, %v", items, err)
	}
}

func TestRecentMissingFileAndLimits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")
	items, err := Recent[int](path, 2, 100)
	if err != nil || len(items) != 0 {
		t.Fatalf("missing log: %+v, %v", items, err)
	}
	if _, err := Recent[int](path, 0, 100); err == nil {
		t.Fatal("accepted zero capacity")
	}
	if _, err := Recent[int](path, 2, 0); err == nil {
		t.Fatal("accepted zero record size")
	}
}
