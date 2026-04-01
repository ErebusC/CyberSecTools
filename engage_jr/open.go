package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// resolveEngagementDir returns the absolute path of an existing engagement
// directory for the given mode and name, or an error if it does not exist.
// Separated from openEngagement so it can be tested without launching a shell.
func resolveEngagementDir(cfg *Config, mode engagementMode, name string) (string, error) {
	sub, ok := modeSubDir[mode]
	if !ok {
		return "", fmt.Errorf("unknown engagement mode: %s", mode)
	}
	dir := filepath.Join(cfg.BaseDir, sub, name)
	if _, err := os.Stat(dir); err != nil {
		return "", fmt.Errorf("engagement %q not found under %s: %w", name, filepath.Join(cfg.BaseDir, sub), err)
	}
	return dir, nil
}

// openEngagement resumes an existing engagement by changing to its directory
// and launching an interactive shell. The mode flag determines which
// subdirectory to search in under cfg.BaseDir.
func openEngagement(cfg *Config, mode engagementMode, name string) {
	dir, err := resolveEngagementDir(cfg, mode, name)
	if err != nil {
		fatal("%v", err)
	}
	logInfo("resuming: %s", dir)
	launchShell(dir)
}

// launchShell changes to dir and runs the user's interactive shell.
// Used by both new engagements and -open.
func launchShell(dir string) {
	if err := os.Chdir(dir); err != nil {
		fatal("changing to engagement directory: %v", err)
	}
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/bash"
	}
	cmd := exec.Command(shell)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "shell exited: %v\n", err)
	}
}
