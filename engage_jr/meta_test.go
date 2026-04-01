package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteAndReadMeta(t *testing.T) {
	dir := t.TempDir()
	want := EngagementMeta{
		Name:      "TestClient",
		Mode:      "work",
		CreatedAt: time.Now().Truncate(time.Second),
	}

	if err := writeMeta(dir, want); err != nil {
		t.Fatalf("writeMeta failed: %v", err)
	}

	got, err := readMeta(filepath.Join(dir, metaFileName))
	if err != nil {
		t.Fatalf("readMeta failed: %v", err)
	}

	if got.Name != want.Name {
		t.Errorf("Name = %q, want %q", got.Name, want.Name)
	}
	if got.Mode != want.Mode {
		t.Errorf("Mode = %q, want %q", got.Mode, want.Mode)
	}
	if !got.CreatedAt.Equal(want.CreatedAt) {
		t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, want.CreatedAt)
	}
}

func TestWriteMetaIdempotent(t *testing.T) {
	dir := t.TempDir()
	original := EngagementMeta{
		Name:      "Original",
		Mode:      "work",
		CreatedAt: time.Now().Add(-24 * time.Hour).Truncate(time.Second),
	}
	if err := writeMeta(dir, original); err != nil {
		t.Fatalf("first writeMeta failed: %v", err)
	}

	// Second write with different data — should be a no-op.
	updated := EngagementMeta{Name: "Changed", Mode: "THM", CreatedAt: time.Now()}
	if err := writeMeta(dir, updated); err != nil {
		t.Fatalf("second writeMeta failed: %v", err)
	}

	got, err := readMeta(filepath.Join(dir, metaFileName))
	if err != nil {
		t.Fatalf("readMeta failed: %v", err)
	}
	if got.Name != original.Name {
		t.Errorf("Name = %q after second write, want original %q", got.Name, original.Name)
	}
}

func TestUpdateMetaHostCount(t *testing.T) {
	dir := t.TempDir()
	meta := EngagementMeta{
		Name:      "TestClient",
		Mode:      "work",
		CreatedAt: time.Now().Truncate(time.Second),
	}
	if err := writeMeta(dir, meta); err != nil {
		t.Fatalf("writeMeta failed: %v", err)
	}

	if err := updateMetaHostCount(dir, 42); err != nil {
		t.Fatalf("updateMetaHostCount failed: %v", err)
	}

	got, err := readMeta(filepath.Join(dir, metaFileName))
	if err != nil {
		t.Fatalf("readMeta failed: %v", err)
	}
	if got.HostCount != 42 {
		t.Errorf("HostCount = %d, want 42", got.HostCount)
	}
	// Other fields should be preserved.
	if got.Name != meta.Name {
		t.Errorf("Name = %q after update, want %q", got.Name, meta.Name)
	}
}

func TestUpdateMetaHostCountMissingFile(t *testing.T) {
	err := updateMetaHostCount(t.TempDir(), 10)
	if err == nil {
		t.Error("expected error when metadata file is missing, got nil")
	}
}

func TestReadMetaMissing(t *testing.T) {
	_, err := readMeta("/nonexistent/path/.engage.json")
	if err == nil {
		t.Error("expected error for missing metadata file, got nil")
	}
}

func TestReadMetaCorrupt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, metaFileName)
	os.WriteFile(path, []byte("not json {{"), 0644)

	_, err := readMeta(path)
	if err == nil {
		t.Error("expected error for corrupt metadata, got nil")
	}
}
