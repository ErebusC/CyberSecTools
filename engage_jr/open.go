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

// openEngagement resumes an existing engagement by attaching to its tmux session
// (when tmux is enabled) or launching an interactive shell. sshHost optionally
// overrides ENGAGE_SSH_HOST in an existing session.
func openEngagement(cfg *Config, mode engagementMode, name, sshHost string) {
	dir, err := resolveEngagementDir(cfg, mode, name)
	if err != nil {
		fatal("%v", err)
	}
	logInfo("resuming: %s", dir)
	launchShell(cfg, mode, name, dir, sshHost)
}

// launchShell is the single entry point for starting a shell or tmux session
// after an engagement directory is ready. When tmux is enabled it delegates to
// launchTmux; otherwise it falls back to launchPlainShell.
func launchShell(cfg *Config, mode engagementMode, name, dir, sshHost string) {
	if cfg.tmuxEnabled() {
		launchTmux(cfg, mode, name, dir, sshHost)
		return
	}
	launchPlainShell(dir)
}

// launchPlainShell changes to dir and runs the user's interactive shell.
// Used as a fallback when tmux is disabled or unavailable.
func launchPlainShell(dir string) {
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
