package main

import (
	"os"
	"path/filepath"
	"testing"
)

// loadTestTemplate is a helper that fatals on error — templates must be present.
func loadTestTemplate(t *testing.T, name string) *EngagementTemplate {
	t.Helper()
	tmpl, err := loadTemplate(name)
	if err != nil {
		t.Fatalf("loadTemplate(%q) failed: %v", name, err)
	}
	return tmpl
}

func TestBuildDirWork(t *testing.T) {
	base := t.TempDir()
	cfg := &Config{BaseDir: base, BurpJar: "/nonexistent/burp.jar"}
	tmpl := loadTestTemplate(t, "work")

	dir, err := buildDir(cfg, tmpl, "TestClient")
	if err != nil {
		t.Fatalf("buildDir(work) failed: %v", err)
	}

	expected := filepath.Join(base, "work", "TestClient")
	if dir != expected {
		t.Errorf("dir = %q, want %q", dir, expected)
	}

	for _, sub := range tmpl.Dirs {
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

func TestBuildDirInfra(t *testing.T) {
	base := t.TempDir()
	cfg := &Config{BaseDir: base, BurpJar: "/nonexistent/burp.jar"}
	tmpl := loadTestTemplate(t, "infra")

	dir, err := buildDir(cfg, tmpl, "InfraClient")
	if err != nil {
		t.Fatalf("buildDir(infra) failed: %v", err)
	}

	expected := filepath.Join(base, "infra", "InfraClient")
	if dir != expected {
		t.Errorf("dir = %q, want %q", dir, expected)
	}

	for _, sub := range tmpl.Dirs {
		path := filepath.Join(dir, sub)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected infra subdir %q to exist: %v", sub, err)
		}
	}

	// Infra has no Burp — no goroutine should have been spawned for it.
	if tmpl.Burp.Enabled {
		t.Error("infra template should not have Burp enabled")
	}
}

func TestBuildDirCloud(t *testing.T) {
	base := t.TempDir()
	cfg := &Config{BaseDir: base, BurpJar: "/nonexistent/burp.jar"}
	tmpl := loadTestTemplate(t, "cloud")

	dir, err := buildDir(cfg, tmpl, "CloudClient")
	if err != nil {
		t.Fatalf("buildDir(cloud) failed: %v", err)
	}

	expected := filepath.Join(base, "cloud", "CloudClient")
	if dir != expected {
		t.Errorf("dir = %q, want %q", dir, expected)
	}

	for _, sub := range tmpl.Dirs {
		path := filepath.Join(dir, sub)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected cloud subdir %q to exist: %v", sub, err)
		}
	}

	if !tmpl.AWS.Enabled {
		t.Error("cloud template should have AWS enabled")
	}
	if tmpl.HostFile.Enabled {
		t.Error("cloud template should not have host file enabled")
	}
}

func TestBuildDirNonWorkModes(t *testing.T) {
	cases := []struct {
		name    string
		subPath string
	}{
		{"THM", "THM"},
		{"HTB", "HTB"},
		{"swigger", "swigger"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			base := t.TempDir()
			cfg := &Config{BaseDir: base, BurpJar: "/nonexistent/burp.jar"}
			tmpl := loadTestTemplate(t, c.name)

			dir, err := buildDir(cfg, tmpl, "TestLab")
			if err != nil {
				t.Fatalf("buildDir(%s) failed: %v", c.name, err)
			}

			expected := filepath.Join(base, c.subPath, "TestLab")
			if dir != expected {
				t.Errorf("dir = %q, want %q", dir, expected)
			}
			if _, err := os.Stat(dir); err != nil {
				t.Errorf("directory %q does not exist: %v", dir, err)
			}

			// Lab modes have no tool subdirectories.
			if len(tmpl.Dirs) > 0 {
				for _, sub := range tmpl.Dirs {
					path := filepath.Join(dir, sub)
					if _, err := os.Stat(path); err != nil {
						t.Errorf("expected subdir %q to exist: %v", sub, err)
					}
				}
			}

			// Metadata file should be written for all modes.
			metaPath := filepath.Join(dir, metaFileName)
			if _, err := os.Stat(metaPath); err != nil {
				t.Errorf("expected metadata file in non-work dir: %v", err)
			}
		})
	}
}

func TestBuildDirExam(t *testing.T) {
	base := t.TempDir()
	cfg := &Config{BaseDir: base, BurpJar: "/nonexistent/burp.jar"}
	tmpl := loadTestTemplate(t, "exam")

	dir, err := buildDir(cfg, tmpl, "TestExam")
	if err != nil {
		t.Fatalf("buildDir(exam) failed: %v", err)
	}

	expected := filepath.Join(base, "exam", "TestExam")
	if dir != expected {
		t.Errorf("dir = %q, want %q", dir, expected)
	}

	// Exam creates tool subdirectories.
	for _, sub := range tmpl.Dirs {
		path := filepath.Join(dir, sub)
		if _, err := os.Stat(path); err != nil {
			t.Errorf("expected exam subdir %q to exist: %v", sub, err)
		}
	}

	// Metadata file should be written.
	metaPath := filepath.Join(dir, metaFileName)
	if _, err := os.Stat(metaPath); err != nil {
		t.Errorf("expected metadata file %q to exist: %v", metaFileName, err)
	}
}

func TestBuildDirIdempotent(t *testing.T) {
	base := t.TempDir()
	cfg := &Config{BaseDir: base, BurpJar: "/nonexistent/burp.jar"}
	tmpl := loadTestTemplate(t, "THM")

	if _, err := buildDir(cfg, tmpl, "Repeat"); err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	if _, err := buildDir(cfg, tmpl, "Repeat"); err != nil {
		t.Errorf("second call failed (not idempotent): %v", err)
	}
}

func TestBuildDirDryRun(t *testing.T) {
	dryRun = true
	defer func() { dryRun = false }()

	base := t.TempDir()
	cfg := &Config{BaseDir: base, BurpJar: "/nonexistent/burp.jar"}
	tmpl := loadTestTemplate(t, "work")

	dir, err := buildDir(cfg, tmpl, "DryClient")
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
