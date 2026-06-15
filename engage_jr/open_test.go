package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveEngagementDirFound(t *testing.T) {
	base := t.TempDir()
	cfg := &Config{BaseDir: base}

	// Create a fake engagement directory.
	engDir := filepath.Join(base, "THM", "Relevant")
	if err := os.MkdirAll(engDir, 0755); err != nil {
		t.Fatal(err)
	}

	got, err := resolveEngagementDir(cfg, "THM", "Relevant")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != engDir {
		t.Errorf("dir = %q, want %q", got, engDir)
	}
}

func TestResolveEngagementDirNotFound(t *testing.T) {
	cfg := &Config{BaseDir: t.TempDir()}
	_, err := resolveEngagementDir(cfg, "THM", "NonExistent")
	if err == nil {
		t.Error("expected error for missing engagement, got nil")
	}
}

func TestResolveEngagementDirAllModes(t *testing.T) {
	base := t.TempDir()
	cfg := &Config{BaseDir: base}

	cases := []struct {
		subDir string
	}{
		{"work"},
		{"THM"},
		{"HTB"},
		{"exam"},
		{"swigger"},
		{"infra"},
		{"cloud"},
	}

	for _, c := range cases {
		t.Run(c.subDir, func(t *testing.T) {
			engDir := filepath.Join(base, c.subDir, "TestEng")
			if err := os.MkdirAll(engDir, 0755); err != nil {
				t.Fatal(err)
			}
			got, err := resolveEngagementDir(cfg, c.subDir, "TestEng")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != engDir {
				t.Errorf("dir = %q, want %q", got, engDir)
			}
		})
	}
}
