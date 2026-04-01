package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// createBurpProject launches Burp Suite Pro headlessly to initialise a project
// file, waits for it to stabilise, then terminates the process and removes
// any temporary files it left behind. Intended to run as a goroutine.
func createBurpProject(cfg *Config, engagementDir, name string) {
	if _, err := exec.LookPath("java"); err != nil {
		logWarn("java not found in PATH — skipping Burp project creation")
		return
	}
	if _, err := os.Stat(cfg.BurpJar); err != nil {
		logWarn("Burp Suite jar not found at %s — skipping project creation", cfg.BurpJar)
		return
	}

	projectFile := filepath.Join(engagementDir, "burp", name+".burp")
	timeout := time.Duration(cfg.BurpTimeoutSecs) * time.Second

	logDebug("starting Burp Suite: project=%s timeout=%s", projectFile, timeout)

	cmd := exec.Command(
		"java",
		"-jar",
		"-Djava.awt.headless=true",
		cfg.BurpJar,
		"--project-file="+projectFile,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		logWarn("failed to start Burp Suite: %v", err)
		return
	}

	time.Sleep(timeout)

	if err := cmd.Process.Kill(); err != nil {
		logWarn("failed to stop Burp Suite: %v", err)
	}

	cleanBurpTemp()
}

func cleanBurpTemp() {
	matches, err := filepath.Glob("/tmp/burp*")
	if err != nil {
		return
	}
	for _, match := range matches {
		os.RemoveAll(match)
	}
}
