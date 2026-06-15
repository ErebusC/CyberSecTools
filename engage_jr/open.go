package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// awsProfileFromMeta reads back the AWS_PROFILE value persisted in .engage.json,
// used when re-opening a cloud engagement whose tmux session was killed.
func awsProfileFromMeta(dir string) string {
	meta, err := readMeta(filepath.Join(dir, metaFileName))
	if err != nil {
		return ""
	}
	return meta.Env["AWS_PROFILE"]
}

// resolveEngagementDir returns the absolute path of an existing engagement
// directory for the given subDir and name, or an error if it does not exist.
// Separated from openEngagement so it can be tested without launching a shell.
func resolveEngagementDir(cfg *Config, subDir, name string) (string, error) {
	dir := filepath.Join(cfg.BaseDir, subDir, name)
	if _, err := os.Stat(dir); err != nil {
		return "", fmt.Errorf("engagement %q not found under %s: %w", name, filepath.Join(cfg.BaseDir, subDir), err)
	}
	return dir, nil
}

// openEngagement resumes an existing engagement by attaching to its tmux session
// (when tmux is enabled) or launching an interactive shell. sshHost optionally
// overrides ENGAGE_SSH_HOST in an existing session.
func openEngagement(cfg *Config, tmpl *EngagementTemplate, name, sshHost string) {
	dir, err := resolveEngagementDir(cfg, tmpl.SubDir, name)
	if err != nil {
		fatal("%v", err)
	}
	logInfo("resuming: %s", dir)
	// Restore the AWS profile from stored metadata so that a re-created tmux
	// session has AWS_PROFILE set even though no profiles file is re-parsed.
	awsProfile := ""
	if tmpl.AWS.Enabled {
		awsProfile = awsProfileFromMeta(dir)
	}
	launchShell(cfg, tmpl, name, dir, sshHost, awsProfile)
}

// launchShell is the single entry point for starting a shell or tmux session
// after an engagement directory is ready. When tmux is enabled it delegates to
// launchTmux; otherwise it falls back to launchPlainShell.
func launchShell(cfg *Config, tmpl *EngagementTemplate, name, dir, sshHost, awsProfile string) {
	if cfg.tmuxEnabled() {
		launchTmux(cfg, tmpl, name, dir, sshHost, awsProfile)
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
