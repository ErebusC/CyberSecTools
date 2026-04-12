package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const metaFileName = ".engage.json"

// EngagementMeta is written into each engagement directory at creation time
// and enriched after host processing and session setup complete.
//
// It serves as the primary interface for recon_jr and other tooling: structured
// fields (Targets, HTTPTargets, SSHHost, TmuxSession) allow direct iteration
// without string parsing, and the Env map provides shell-ready variables that
// can be sourced or passed to tools directly.
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

// updateMetaContext enriches .engage.json with the full engagement context after
// host processing and tmux setup complete. It is safe to call on re-open (merges,
// never resets CreatedAt). All fields are optional — zero/nil values are omitted.
//
// Populates:
//   - HostCount, HTTPCount from stats
//   - Targets from <dir>/hosts, HTTPTargets from <dir>/http_hosts
//   - SSHHost from sshHost arg
//   - TmuxSession from cfg (only when TmuxEnabled)
//   - Env from the envVars KEY=VALUE slice
func updateMetaContext(dir string, cfg *Config, mode engagementMode, name string,
	stats hostStats, sshHost string, envVars []string) error {

	path := filepath.Join(dir, metaFileName)
	meta, err := readMeta(path)
	if err != nil {
		return fmt.Errorf("reading metadata for context update: %w", err)
	}

	meta.HostCount = stats.Unique
	meta.HTTPCount = stats.HTTP
	meta.Targets = readHostsFile(filepath.Join(dir, "hosts"))
	meta.HTTPTargets = readHostsFile(filepath.Join(dir, "http_hosts"))
	meta.SSHHost = sshHost

	if cfg.TmuxEnabled {
		meta.TmuxSession = tmuxSessionName(cfg, name)
	}

	if len(envVars) > 0 {
		env := make(map[string]string, len(envVars))
		for _, pair := range envVars {
			if idx := strings.IndexByte(pair, '='); idx >= 0 {
				env[pair[:idx]] = pair[idx+1:]
			}
		}
		meta.Env = env
	}

	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling metadata: %w", err)
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
