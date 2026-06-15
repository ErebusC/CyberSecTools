package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type engagementMode string

const (
	ModeWork    engagementMode = "work"
	ModeInfra   engagementMode = "infra"
	ModeCloud   engagementMode = "cloud"
	ModeTHM     engagementMode = "THM"
	ModeHTB     engagementMode = "HTB"
	ModeExam    engagementMode = "exam"
	ModeSwigger engagementMode = "swigger"
)

// buildDir creates the engagement directory structure driven by the template.
// Returns the absolute path of the engagement directory.
func buildDir(cfg *Config, tmpl *EngagementTemplate, name string) (string, error) {
	base := filepath.Join(cfg.BaseDir, tmpl.SubDir, name)

	if dryRun {
		logInfo("[dry-run] would create: %s", base)
		for _, dir := range tmpl.Dirs {
			logInfo("[dry-run] would create: %s/%s", base, dir)
		}
		if tmpl.Burp.Enabled {
			logInfo("[dry-run] would create Burp project: %s/burp/%s.burp", base, name)
		}
		logInfo("[dry-run] would write metadata: %s/%s", base, metaFileName)
		return base, nil
	}

	if _, err := os.Stat(base); err == nil {
		logWarn("%s already exists — host files will be appended", base)
	}

	if err := os.MkdirAll(base, 0755); err != nil {
		return "", fmt.Errorf("failed to create directory %s: %w", base, err)
	}

	meta := EngagementMeta{
		Name:      name,
		Mode:      tmpl.SubDir,
		CreatedAt: time.Now(),
	}
	if err := writeMeta(base, meta); err != nil {
		logWarn("could not write engagement metadata: %v", err)
	}

	for _, dir := range tmpl.Dirs {
		path := filepath.Join(base, dir)
		if err := os.MkdirAll(path, 0755); err != nil {
			return "", fmt.Errorf("failed to create subdirectory %s: %w", path, err)
		}
	}

	if tmpl.IsolatedVault {
		obsidianDir := filepath.Join(base, "notes", ".obsidian")
		if err := os.MkdirAll(obsidianDir, 0755); err != nil {
			logWarn("could not create notes vault skeleton: %v", err)
		}
		if err := provisionEngagementNotes(base, name); err != nil {
			logWarn("could not provision engagement notes: %v", err)
		}
	}

	if tmpl.Burp.Enabled {
		go createBurpProject(cfg, base, name)
	}

	return base, nil
}
