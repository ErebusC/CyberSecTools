package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	engageMetaFile = ".engage.json"
	reconMetaFile  = ".recon.json"
)

// EngagementMeta mirrors engage_jr's .engage.json structure.
// recon_jr reads this file but never writes it.
type EngagementMeta struct {
	Name        string            `json:"name"`
	Mode        string            `json:"mode"`
	CreatedAt   time.Time         `json:"created_at"`
	HostCount   int               `json:"host_count,omitempty"`
	HTTPCount   int               `json:"http_count,omitempty"`
	Targets     []string          `json:"targets,omitempty"`
	HTTPTargets []string          `json:"http_targets,omitempty"`
	SSHHost     string            `json:"ssh_host,omitempty"`
	TmuxSession string            `json:"tmux_session,omitempty"`
	Env         map[string]string `json:"env,omitempty"`
}

// PhaseStatus records the outcome of a single recon phase.
type PhaseStatus struct {
	Status          string     `json:"status"`            // "completed", "interrupted", "skipped", "failed"
	StartedAt       time.Time  `json:"started_at"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
	InterruptedTool string     `json:"interrupted_tool,omitempty"`
}

// ReconMeta is written to .recon.json in the engagement root.
// It records what recon_jr has done and provides state for resuming interrupted runs.
type ReconMeta struct {
	EngagementName   string                 `json:"engagement_name"`
	StartedAt        time.Time              `json:"started_at"`
	CompletedAt      *time.Time             `json:"completed_at,omitempty"`
	PhaseStatus      map[string]PhaseStatus `json:"phase_status"`
	NessusSkipped    bool                   `json:"nessus_skipped,omitempty"`
	NessusSkipReason string                 `json:"nessus_skip_reason,omitempty"`
	NessusScanID     int64                  `json:"nessus_scan_id,omitempty"`
	NessusStatus     string                 `json:"nessus_status,omitempty"`
	DiscoveredHosts  int                    `json:"discovered_hosts"`
	ToolsRun         []string               `json:"tools_run"`
	ToolsSkipped     []string               `json:"tools_skipped,omitempty"`
	Findings         []Finding              `json:"findings,omitempty"`
}

// findEngagementDir walks up from startDir looking for a .engage.json file.
// Returns the directory containing .engage.json, or an error if not found.
func findEngagementDir(startDir string) (string, error) {
	dir, err := filepath.Abs(startDir)
	if err != nil {
		return "", fmt.Errorf("resolving path %s: %w", startDir, err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, engageMetaFile)); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no %s found in %s or any parent directory", engageMetaFile, startDir)
		}
		dir = parent
	}
}

// readEngageMeta reads and parses .engage.json from engDir.
func readEngageMeta(engDir string) (EngagementMeta, error) {
	path := filepath.Join(engDir, engageMetaFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return EngagementMeta{}, fmt.Errorf("reading %s: %w", path, err)
	}
	var meta EngagementMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return EngagementMeta{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	return meta, nil
}

// initReconMeta creates a new ReconMeta for engDir, loading any existing .recon.json
// so that resumed runs preserve prior phase state.
func initReconMeta(engDir string, engMeta EngagementMeta) *ReconMeta {
	if existing, err := readReconMeta(engDir); err == nil {
		return existing
	}
	return &ReconMeta{
		EngagementName: engMeta.Name,
		StartedAt:      time.Now(),
		PhaseStatus:    make(map[string]PhaseStatus),
	}
}

// readReconMeta reads .recon.json from engDir.
func readReconMeta(engDir string) (*ReconMeta, error) {
	path := filepath.Join(engDir, reconMetaFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var meta ReconMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if meta.PhaseStatus == nil {
		meta.PhaseStatus = make(map[string]PhaseStatus)
	}
	return &meta, nil
}

// flushReconMeta writes meta to .recon.json in engDir. Called after each phase
// and on interrupt to ensure accurate resume state.
func flushReconMeta(engDir string, meta *ReconMeta) error {
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling recon metadata: %w", err)
	}
	path := filepath.Join(engDir, reconMetaFile)
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// markPhaseStarted records that phase n has begun.
func markPhaseStarted(meta *ReconMeta, phaseName string) {
	meta.PhaseStatus[phaseName] = PhaseStatus{
		Status:    "running",
		StartedAt: time.Now(),
	}
}

// markPhaseCompleted records that phase n finished successfully.
func markPhaseCompleted(meta *ReconMeta, phaseName string) {
	ps := meta.PhaseStatus[phaseName]
	ps.Status = "completed"
	now := time.Now()
	ps.CompletedAt = &now
	meta.PhaseStatus[phaseName] = ps
}

// markPhaseInterrupted records that phase n was interrupted while toolName was running.
func markPhaseInterrupted(meta *ReconMeta, phaseName, toolName string) {
	ps := meta.PhaseStatus[phaseName]
	ps.Status = "interrupted"
	ps.InterruptedTool = toolName
	meta.PhaseStatus[phaseName] = ps
}

// recordToolRun appends toolName to the tools_run list (deduplicates).
func recordToolRun(meta *ReconMeta, toolName string) {
	for _, t := range meta.ToolsRun {
		if t == toolName {
			return
		}
	}
	meta.ToolsRun = append(meta.ToolsRun, toolName)
}

// recordToolSkipped appends toolName to the tools_skipped list (deduplicates).
func recordToolSkipped(meta *ReconMeta, toolName string) {
	for _, t := range meta.ToolsSkipped {
		if t == toolName {
			return
		}
	}
	meta.ToolsSkipped = append(meta.ToolsSkipped, toolName)
}
