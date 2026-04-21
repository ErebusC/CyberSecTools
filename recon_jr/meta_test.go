package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFindEngagementDir(t *testing.T) {
	dir := t.TempDir()

	// Create a nested structure: dir/a/b/c
	nested := filepath.Join(dir, "a", "b", "c")
	if err := os.MkdirAll(nested, 0755); err != nil {
		t.Fatal(err)
	}

	// No .engage.json yet — should fail
	if _, err := findEngagementDir(nested); err == nil {
		t.Error("expected error when .engage.json not present")
	}

	// Place .engage.json in dir/a
	metaPath := filepath.Join(dir, "a", engageMetaFile)
	os.WriteFile(metaPath, []byte(`{"name":"test","mode":"work","created_at":"2024-01-01T00:00:00Z"}`), 0644)

	found, err := findEngagementDir(nested)
	if err != nil {
		t.Fatalf("findEngagementDir: %v", err)
	}
	expected := filepath.Join(dir, "a")
	if found != expected {
		t.Errorf("findEngagementDir: got %q, want %q", found, expected)
	}
}

func TestReadEngageMeta(t *testing.T) {
	dir := t.TempDir()
	data := `{
		"name": "ACME-2024",
		"mode": "work",
		"created_at": "2024-01-15T10:00:00Z",
		"host_count": 3,
		"targets": ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
	}`
	os.WriteFile(filepath.Join(dir, engageMetaFile), []byte(data), 0644)

	meta, err := readEngageMeta(dir)
	if err != nil {
		t.Fatalf("readEngageMeta: %v", err)
	}
	if meta.Name != "ACME-2024" {
		t.Errorf("Name: got %q", meta.Name)
	}
	if meta.Mode != "work" {
		t.Errorf("Mode: got %q", meta.Mode)
	}
	if meta.HostCount != 3 {
		t.Errorf("HostCount: got %d", meta.HostCount)
	}
	if len(meta.Targets) != 3 {
		t.Errorf("Targets: got %d items", len(meta.Targets))
	}
}

func TestReadEngageMetaMissing(t *testing.T) {
	dir := t.TempDir()
	if _, err := readEngageMeta(dir); err == nil {
		t.Error("expected error for missing .engage.json")
	}
}

func TestInitReconMeta(t *testing.T) {
	dir := t.TempDir()
	engMeta := EngagementMeta{Name: "TEST-001", Mode: "work"}

	meta := initReconMeta(dir, engMeta)
	if meta == nil {
		t.Fatal("initReconMeta returned nil")
	}
	if meta.EngagementName != "TEST-001" {
		t.Errorf("EngagementName: got %q", meta.EngagementName)
	}
	if meta.PhaseStatus == nil {
		t.Error("PhaseStatus should be initialized")
	}
}

func TestInitReconMetaResumesExisting(t *testing.T) {
	dir := t.TempDir()
	engMeta := EngagementMeta{Name: "TEST-001", Mode: "work"}

	// Write an existing .recon.json
	existing := &ReconMeta{
		EngagementName: "TEST-001",
		StartedAt:      time.Now().Add(-1 * time.Hour),
		PhaseStatus: map[string]PhaseStatus{
			"phase1": {Status: "completed"},
		},
	}
	if err := flushReconMeta(dir, existing); err != nil {
		t.Fatal(err)
	}

	meta := initReconMeta(dir, engMeta)
	if _, ok := meta.PhaseStatus["phase1"]; !ok {
		t.Error("expected to resume phase1 status from existing .recon.json")
	}
}

func TestFlushAndReadReconMeta(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().Truncate(time.Second)

	meta := &ReconMeta{
		EngagementName: "FLUSH-TEST",
		StartedAt:      now,
		PhaseStatus: map[string]PhaseStatus{
			"phase1": {Status: "completed", StartedAt: now},
		},
		ToolsRun: []string{"subfinder", "dnsx"},
	}
	if err := flushReconMeta(dir, meta); err != nil {
		t.Fatalf("flushReconMeta: %v", err)
	}

	loaded, err := readReconMeta(dir)
	if err != nil {
		t.Fatalf("readReconMeta: %v", err)
	}
	if loaded.EngagementName != "FLUSH-TEST" {
		t.Errorf("EngagementName: got %q", loaded.EngagementName)
	}
	if len(loaded.ToolsRun) != 2 {
		t.Errorf("ToolsRun: got %v", loaded.ToolsRun)
	}
	if ps, ok := loaded.PhaseStatus["phase1"]; !ok || ps.Status != "completed" {
		t.Errorf("phase1 status: got %+v", ps)
	}
}

func TestMarkPhaseHelpers(t *testing.T) {
	meta := &ReconMeta{PhaseStatus: make(map[string]PhaseStatus)}

	markPhaseStarted(meta, "phase1")
	if meta.PhaseStatus["phase1"].Status != "running" {
		t.Error("expected status=running after markPhaseStarted")
	}

	markPhaseCompleted(meta, "phase1")
	ps := meta.PhaseStatus["phase1"]
	if ps.Status != "completed" {
		t.Errorf("expected status=completed, got %q", ps.Status)
	}
	if ps.CompletedAt == nil {
		t.Error("CompletedAt should be set")
	}

	markPhaseInterrupted(meta, "phase2", "nmap")
	ps2 := meta.PhaseStatus["phase2"]
	if ps2.Status != "interrupted" {
		t.Errorf("expected status=interrupted, got %q", ps2.Status)
	}
	if ps2.InterruptedTool != "nmap" {
		t.Errorf("InterruptedTool: got %q", ps2.InterruptedTool)
	}
}

func TestRecordToolRunDedup(t *testing.T) {
	meta := &ReconMeta{}
	recordToolRun(meta, "subfinder")
	recordToolRun(meta, "subfinder")
	recordToolRun(meta, "dnsx")
	if len(meta.ToolsRun) != 2 {
		t.Errorf("expected 2 unique tools, got %d: %v", len(meta.ToolsRun), meta.ToolsRun)
	}
}
