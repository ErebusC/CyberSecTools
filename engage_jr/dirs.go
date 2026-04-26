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
	ModeTHM     engagementMode = "THM"
	ModeHTB     engagementMode = "HTB"
	ModeExam    engagementMode = "exam"
	ModeSwigger engagementMode = "swigger"
)

// modeSubDir maps each engagement mode to its subdirectory name under BaseDir.
var modeSubDir = map[engagementMode]string{
	ModeWork:    "work",
	ModeTHM:     "THM",
	ModeHTB:     "HTB",
	ModeExam:    "exam",
	ModeSwigger: "swigger",
}

// buildDir creates the engagement directory structure for the given mode and
// engagement name. Work mode additionally creates tool subdirectories, writes
// an engagement metadata file, and triggers Burp Suite project creation in a
// background goroutine. Returns the absolute path of the engagement directory.
func buildDir(cfg *Config, mode engagementMode, name string) (string, error) {
	sub, ok := modeSubDir[mode]
	if !ok {
		return "", fmt.Errorf("unknown engagement mode: %s", mode)
	}

	base := filepath.Join(cfg.BaseDir, sub, name)

	if dryRun {
		logInfo("[dry-run] would create: %s", base)
		if mode == ModeWork || mode == ModeExam {
			workDirs := cfg.WorkDirs
			if len(workDirs) == 0 {
				workDirs = defaultWorkDirs
			}
			for _, dir := range workDirs {
				logInfo("[dry-run] would create: %s/%s", base, dir)
			}
		}
		if mode == ModeWork {
			logInfo("[dry-run] would create Burp project: %s/burp/%s.burp", base, name)
			logInfo("[dry-run] would write metadata: %s/%s", base, metaFileName)
		}
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
		Mode:      string(mode),
		CreatedAt: time.Now(),
	}
	if err := writeMeta(base, meta); err != nil {
		logWarn("could not write engagement metadata: %v", err)
	}

	if mode == ModeWork || mode == ModeExam {
		workDirs := cfg.WorkDirs
		if len(workDirs) == 0 {
			workDirs = defaultWorkDirs
		}
		for _, dir := range workDirs {
			path := filepath.Join(base, dir)
			if err := os.MkdirAll(path, 0755); err != nil {
				return "", fmt.Errorf("failed to create subdirectory %s: %w", path, err)
			}
		}
	}

	if mode == ModeWork {
		// Create the notes directory with an Obsidian vault skeleton so the vault
		// is valid from the first open. The vault is named after the engagement
		// (not a generic "notes") so the obsidian://open?vault= URI is unambiguous
		// across multiple engagements.
		obsidianDir := filepath.Join(base, "notes", name, ".obsidian")
		if err := os.MkdirAll(obsidianDir, 0755); err != nil {
			logWarn("could not create notes vault skeleton: %v", err)
		}
		if err := provisionEngagementNotes(base, name); err != nil {
			logWarn("could not provision engagement notes: %v", err)
		}

		go createBurpProject(cfg, base, name)
	}

	return base, nil
}
