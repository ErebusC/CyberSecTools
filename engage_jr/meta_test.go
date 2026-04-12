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

func TestUpdateMetaContext(t *testing.T) {
	dir := t.TempDir()

	// Seed the metadata file.
	if err := writeMeta(dir, EngagementMeta{
		Name:      "acmecorp_1",
		Mode:      "work",
		CreatedAt: time.Now().Truncate(time.Second),
	}); err != nil {
		t.Fatalf("writeMeta failed: %v", err)
	}

	// Write host files as processHostFile would.
	os.WriteFile(filepath.Join(dir, "hosts"), []byte("10.0.0.1\n10.0.0.2\n"), 0644)
	os.WriteFile(filepath.Join(dir, "http_hosts"), []byte("http://example.com\n"), 0644)

	cfg := &Config{TmuxEnabled: boolPtr(true), TmuxPrefix: ""}
	stats := hostStats{Unique: 2, HTTP: 1}
	envVars := []string{"ENGAGE_NAME=acmecorp_1", "TARGET_1=10.0.0.1", "TARGET_2=10.0.0.2"}

	if err := updateMetaContext(dir, cfg, ModeWork, "acmecorp_1", stats, "lhack", envVars); err != nil {
		t.Fatalf("updateMetaContext failed: %v", err)
	}

	got, err := readMeta(filepath.Join(dir, metaFileName))
	if err != nil {
		t.Fatalf("readMeta failed: %v", err)
	}

	// Original fields preserved.
	if got.Name != "acmecorp_1" {
		t.Errorf("Name = %q, want acmecorp_1", got.Name)
	}
	// Host stats.
	if got.HostCount != 2 {
		t.Errorf("HostCount = %d, want 2", got.HostCount)
	}
	if got.HTTPCount != 1 {
		t.Errorf("HTTPCount = %d, want 1", got.HTTPCount)
	}
	// Structured target lists.
	if len(got.Targets) != 2 || got.Targets[0] != "10.0.0.1" {
		t.Errorf("Targets = %v, want [10.0.0.1 10.0.0.2]", got.Targets)
	}
	if len(got.HTTPTargets) != 1 || got.HTTPTargets[0] != "http://example.com" {
		t.Errorf("HTTPTargets = %v, want [http://example.com]", got.HTTPTargets)
	}
	// SSH host.
	if got.SSHHost != "lhack" {
		t.Errorf("SSHHost = %q, want lhack", got.SSHHost)
	}
	// Tmux session (enabled, no prefix → bare name).
	if got.TmuxSession != "acmecorp_1" {
		t.Errorf("TmuxSession = %q, want acmecorp_1", got.TmuxSession)
	}
	// Env map.
	if got.Env["ENGAGE_NAME"] != "acmecorp_1" {
		t.Errorf("Env[ENGAGE_NAME] = %q, want acmecorp_1", got.Env["ENGAGE_NAME"])
	}
	if got.Env["TARGET_1"] != "10.0.0.1" {
		t.Errorf("Env[TARGET_1] = %q, want 10.0.0.1", got.Env["TARGET_1"])
	}
}

func TestUpdateMetaContextTmuxDisabled(t *testing.T) {
	dir := t.TempDir()
	if err := writeMeta(dir, EngagementMeta{
		Name: "lab1", Mode: "HTB", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{TmuxEnabled: boolPtr(false)}
	if err := updateMetaContext(dir, cfg, ModeHTB, "lab1", hostStats{}, "", nil); err != nil {
		t.Fatalf("updateMetaContext failed: %v", err)
	}

	got, err := readMeta(filepath.Join(dir, metaFileName))
	if err != nil {
		t.Fatal(err)
	}
	if got.TmuxSession != "" {
		t.Errorf("TmuxSession = %q, want empty when tmux disabled", got.TmuxSession)
	}
}

func TestUpdateMetaContextNoHosts(t *testing.T) {
	dir := t.TempDir() // no host files written
	if err := writeMeta(dir, EngagementMeta{
		Name: "test", Mode: "THM", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{}
	if err := updateMetaContext(dir, cfg, ModeTHM, "test", hostStats{}, "", nil); err != nil {
		t.Fatalf("updateMetaContext failed: %v", err)
	}

	got, err := readMeta(filepath.Join(dir, metaFileName))
	if err != nil {
		t.Fatal(err)
	}
	// Nil slices are omitted; zero counts are omitted.
	if len(got.Targets) != 0 {
		t.Errorf("Targets = %v, want empty when no hosts file", got.Targets)
	}
	if got.HostCount != 0 {
		t.Errorf("HostCount = %d, want 0", got.HostCount)
	}
}

func TestUpdateMetaContextMissingFile(t *testing.T) {
	cfg := &Config{}
	err := updateMetaContext(t.TempDir(), cfg, ModeWork, "test", hostStats{}, "", nil)
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
