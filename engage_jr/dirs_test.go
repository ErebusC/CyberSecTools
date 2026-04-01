package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuildDirWork(t *testing.T) {
	base := t.TempDir()
	cfg := &Config{BaseDir: base, BurpJar: "/nonexistent/burp.jar", WorkDirs: defaultWorkDirs}

	dir, err := buildDir(cfg, ModeWork, "TestClient")
	if err != nil {
		t.Fatalf("buildDir(ModeWork) failed: %v", err)
	}

	expected := filepath.Join(base, "work", "TestClient")
	if dir != expected {
		t.Errorf("dir = %q, want %q", dir, expected)
	}

	for _, sub := range defaultWorkDirs {
		path := filepath.Join(dir, sub)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected work subdir %q to exist: %v", sub, err)
		}
	}

	// Metadata file should be written.
	metaPath := filepath.Join(dir, metaFileName)
	if _, err := os.Stat(metaPath); err != nil {
		t.Errorf("expected metadata file %q to exist: %v", metaFileName, err)
	}
}

func TestBuildDirCustomWorkDirs(t *testing.T) {
	base := t.TempDir()
	custom := []string{"recon", "exploits", "loot"}
	cfg := &Config{BaseDir: base, BurpJar: "/nonexistent/burp.jar", WorkDirs: custom}

	dir, err := buildDir(cfg, ModeWork, "CustomClient")
	if err != nil {
		t.Fatalf("buildDir with custom WorkDirs failed: %v", err)
	}

	for _, sub := range custom {
		path := filepath.Join(dir, sub)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected custom subdir %q to exist: %v", sub, err)
		}
	}
	// Default dirs should NOT be created.
	for _, sub := range defaultWorkDirs {
		if contains(custom, sub) {
			continue
		}
		path := filepath.Join(dir, sub)
		if _, err := os.Stat(path); err == nil {
			t.Errorf("unexpected default subdir %q exists with custom WorkDirs", sub)
		}
	}
}

func TestBuildDirNonWorkModes(t *testing.T) {
	cases := []struct {
		mode    engagementMode
		subPath string
	}{
		{ModeTHM, "THM"},
		{ModeHTB, "HTB"},
		{ModeExam, "exam"},
		{ModeSwigger, "swigger"},
	}

	for _, c := range cases {
		t.Run(string(c.mode), func(t *testing.T) {
			base := t.TempDir()
			cfg := &Config{BaseDir: base, BurpJar: "/nonexistent/burp.jar", WorkDirs: defaultWorkDirs}

			dir, err := buildDir(cfg, c.mode, "TestLab")
			if err != nil {
				t.Fatalf("buildDir(%s) failed: %v", c.mode, err)
			}

			expected := filepath.Join(base, c.subPath, "TestLab")
			if dir != expected {
				t.Errorf("dir = %q, want %q", dir, expected)
			}
			if _, err := os.Stat(dir); err != nil {
				t.Errorf("directory %q does not exist: %v", dir, err)
			}

			// Non-work modes must not create tool subdirectories.
			for _, sub := range defaultWorkDirs {
				path := filepath.Join(dir, sub)
				if _, err := os.Stat(path); err == nil {
					t.Errorf("unexpected subdir %q created for mode %s", sub, c.mode)
				}
			}

			// Metadata file should still be written for all modes.
			metaPath := filepath.Join(dir, metaFileName)
			if _, err := os.Stat(metaPath); err != nil {
				t.Errorf("expected metadata file in non-work dir: %v", err)
			}
		})
	}
}

func TestBuildDirUnknownMode(t *testing.T) {
	cfg := &Config{BaseDir: t.TempDir(), BurpJar: "/nonexistent/burp.jar"}
	_, err := buildDir(cfg, "bogus", "TestLab")
	if err == nil {
		t.Error("expected error for unknown mode, got nil")
	}
}

func TestBuildDirIdempotent(t *testing.T) {
	base := t.TempDir()
	cfg := &Config{BaseDir: base, BurpJar: "/nonexistent/burp.jar"}

	if _, err := buildDir(cfg, ModeTHM, "Repeat"); err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	if _, err := buildDir(cfg, ModeTHM, "Repeat"); err != nil {
		t.Errorf("second call failed (not idempotent): %v", err)
	}
}

func TestBuildDirDryRun(t *testing.T) {
	dryRun = true
	defer func() { dryRun = false }()

	base := t.TempDir()
	cfg := &Config{BaseDir: base, BurpJar: "/nonexistent/burp.jar", WorkDirs: defaultWorkDirs}

	dir, err := buildDir(cfg, ModeWork, "DryClient")
	if err != nil {
		t.Fatalf("buildDir dry-run failed: %v", err)
	}

	expected := filepath.Join(base, "work", "DryClient")
	if dir != expected {
		t.Errorf("dry-run dir = %q, want %q", dir, expected)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Errorf("dry-run created directory %q — it should not exist", dir)
	}
}

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
