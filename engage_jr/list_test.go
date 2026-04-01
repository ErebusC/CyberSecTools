package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDirInfoFromMeta(t *testing.T) {
	base := t.TempDir()
	engDir := filepath.Join(base, "TestEng")
	if err := os.MkdirAll(engDir, 0755); err != nil {
		t.Fatal(err)
	}

	ts := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	meta := EngagementMeta{Name: "TestEng", Mode: "work", CreatedAt: ts, HostCount: 47}
	if err := writeMeta(engDir, meta); err != nil {
		t.Fatalf("writeMeta failed: %v", err)
	}

	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	got, count := dirInfo(base, entries[0])
	if !got.Equal(ts) {
		t.Errorf("createdAt = %v, want %v", got, ts)
	}
	if count != 47 {
		t.Errorf("hostCount = %d, want 47", count)
	}
}

func TestDirInfoFallbackToMtime(t *testing.T) {
	base := t.TempDir()
	engDir := filepath.Join(base, "NoMeta")
	if err := os.MkdirAll(engDir, 0755); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}

	got, count := dirInfo(base, entries[0])
	if got.IsZero() {
		t.Errorf("expected non-zero time when no metadata, got zero")
	}
	if count != 0 {
		t.Errorf("hostCount = %d, want 0 when no metadata", count)
	}
}

func TestListEngagementsEmpty(t *testing.T) {
	cfg := &Config{BaseDir: t.TempDir()}
	// Should not panic when no engagement directories exist.
	listEngagements(cfg, nil)
}

func TestListEngagementsFilterMode(t *testing.T) {
	base := t.TempDir()
	cfg := &Config{BaseDir: base}

	// Create a THM and a work engagement.
	for _, p := range []string{"THM/Lab1", "work/ClientA"} {
		if err := os.MkdirAll(filepath.Join(base, p), 0755); err != nil {
			t.Fatal(err)
		}
	}

	// Capture stdout.
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	mode := ModeTHM
	listEngagements(cfg, &mode)

	w.Close()
	os.Stdout = old
	var buf strings.Builder
	io.Copy(&buf, r)
	out := buf.String()

	if !strings.Contains(out, "Lab1") {
		t.Errorf("expected Lab1 in output, got: %s", out)
	}
	if strings.Contains(out, "ClientA") {
		t.Errorf("ClientA (work) should not appear in THM-filtered output, got: %s", out)
	}
}

func TestListEngagementsSortNewestFirst(t *testing.T) {
	base := t.TempDir()
	cfg := &Config{BaseDir: base}

	older := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name string
		ts   time.Time
	}{
		{"OlderEng", older},
		{"NewerEng", newer},
	} {
		dir := filepath.Join(base, "THM", tc.name)
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		meta := EngagementMeta{Name: tc.name, Mode: "THM", CreatedAt: tc.ts}
		if err := writeMeta(dir, meta); err != nil {
			t.Fatal(err)
		}
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	mode := ModeTHM
	listEngagements(cfg, &mode)

	w.Close()
	os.Stdout = old
	var buf strings.Builder
	io.Copy(&buf, r)
	out := buf.String()

	newerIdx := strings.Index(out, "NewerEng")
	olderIdx := strings.Index(out, "OlderEng")
	if newerIdx < 0 || olderIdx < 0 {
		t.Fatalf("expected both engagements in output, got: %s", out)
	}
	if newerIdx > olderIdx {
		t.Errorf("expected NewerEng before OlderEng in output (newest-first)")
	}
}
