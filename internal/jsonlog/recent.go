// Package jsonlog reads bounded recent records from append-only JSON logs.
package jsonlog

import (
	"bufio"
	"bytes"
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
	reader := bufio.NewReaderSize(file, min(maxLine, 64*1024))
	ring := make([]T, limit)
	next, count := 0, 0
	var line []byte
	oversized := false
	for {
		part, err := reader.ReadSlice('\n')
		part = bytes.TrimSuffix(part, []byte{'\n'})
		if !oversized {
			if len(line)+len(part) > maxLine {
				oversized = true
				line = line[:0]
			} else {
				line = append(line, part...)
			}
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil && err != io.EOF {
			return nil, err
		}
		if !oversized && len(line) > 0 {
			var item *T
			if json.Unmarshal(line, &item) == nil && item != nil {
				ring[next] = *item
				next = (next + 1) % limit
				count = min(count+1, limit)
			}
		}
		line = line[:0]
		oversized = false
		if err == io.EOF {
			break
		}
	}
	items := make([]T, 0, count)
	for i := 0; i < count; i++ {
		items = append(items, ring[(next-1-i+limit)%limit])
	}
	return items, nil
}
