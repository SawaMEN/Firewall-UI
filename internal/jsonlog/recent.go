// Package jsonlog reads bounded recent records from append-only JSON logs.
package jsonlog

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

func Recent[T any](path string, limit, maxLine int) ([]T, error) {
	if limit <= 0 || maxLine <= 0 {
		return nil, fmt.Errorf("log limits must be positive")
	}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return []T{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	// Start at the tail and stop once enough valid records have been found.
	// Reading the entire history made every refresh grow with the log's lifetime.
	position := info.Size()
	buffer := make([]byte, min(maxLine, 64*1024))
	items := make([]T, 0, limit)
	var line []byte
	oversized := false
	consume := func() {
		if !oversized && len(line) > 0 {
			for i, j := 0, len(line)-1; i < j; i, j = i+1, j-1 {
				line[i], line[j] = line[j], line[i]
			}
			var item *T
			if json.Unmarshal(line, &item) == nil && item != nil {
				items = append(items, *item)
			}
		}
		line = line[:0]
		oversized = false
	}
	for position > 0 && len(items) < limit {
		size := min(int64(len(buffer)), position)
		position -= size
		part := buffer[:int(size)]
		n, err := file.ReadAt(part, position)
		if err != nil || n != len(part) {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			return nil, err
		}
		for i := len(part) - 1; i >= 0; i-- {
			if part[i] == '\n' {
				consume()
				if len(items) == limit {
					return items, nil
				}
			} else if !oversized {
				if len(line) == maxLine {
					oversized = true
					line = line[:0]
				} else {
					line = append(line, part[i])
				}
			}
		}
	}
	if len(items) < limit {
		consume()
	}
	return items, nil
}
