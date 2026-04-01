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

	got, err := resolveEngagementDir(cfg, ModeTHM, "Relevant")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != engDir {
		t.Errorf("dir = %q, want %q", got, engDir)
	}
}

func TestResolveEngagementDirNotFound(t *testing.T) {
	cfg := &Config{BaseDir: t.TempDir()}
	_, err := resolveEngagementDir(cfg, ModeTHM, "NonExistent")
	if err == nil {
		t.Error("expected error for missing engagement, got nil")
	}
}

func TestResolveEngagementDirUnknownMode(t *testing.T) {
	cfg := &Config{BaseDir: t.TempDir()}
	_, err := resolveEngagementDir(cfg, "bogus", "SomeName")
	if err == nil {
		t.Error("expected error for unknown mode, got nil")
	}
}

func TestResolveEngagementDirAllModes(t *testing.T) {
	base := t.TempDir()
	cfg := &Config{BaseDir: base}

	cases := []struct {
		mode    engagementMode
		subPath string
	}{
		{ModeWork, "work"},
		{ModeTHM, "THM"},
		{ModeHTB, "HTB"},
		{ModeExam, "exam"},
		{ModeSwigger, "swigger"},
	}

	for _, c := range cases {
		t.Run(string(c.mode), func(t *testing.T) {
			engDir := filepath.Join(base, c.subPath, "TestEng")
			if err := os.MkdirAll(engDir, 0755); err != nil {
				t.Fatal(err)
			}
			got, err := resolveEngagementDir(cfg, c.mode, "TestEng")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != engDir {
				t.Errorf("dir = %q, want %q", got, engDir)
			}
		})
	}
}
