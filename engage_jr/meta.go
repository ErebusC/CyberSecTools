package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const metaFileName = ".engage.json"

// EngagementMeta is written into each engagement directory at creation time
// and updated with host count after host file processing completes.
type EngagementMeta struct {
	Name      string    `json:"name"`
	Mode      string    `json:"mode"`
	CreatedAt time.Time `json:"created_at"`
	HostCount int       `json:"host_count,omitempty"`
}

// writeMeta writes an EngagementMeta file into dir. If the file already
// exists it is left untouched so the original creation date is preserved.
func writeMeta(dir string, meta EngagementMeta) error {
	path := filepath.Join(dir, metaFileName)
	if _, err := os.Stat(path); err == nil {
		return nil // already exists — preserve original
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling metadata: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("writing metadata: %w", err)
	}
	return nil
}

// updateMetaHostCount reads the existing .engage.json in dir, sets HostCount,
// and writes it back. Called after host file processing to record the count.
func updateMetaHostCount(dir string, count int) error {
	path := filepath.Join(dir, metaFileName)
	meta, err := readMeta(path)
	if err != nil {
		return fmt.Errorf("reading metadata for update: %w", err)
	}
	meta.HostCount = count
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling updated metadata: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// readMeta reads an EngagementMeta from the given file path.
func readMeta(path string) (EngagementMeta, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return EngagementMeta{}, err
	}
	var meta EngagementMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return EngagementMeta{}, fmt.Errorf("parsing metadata: %w", err)
	}
	return meta, nil
}
