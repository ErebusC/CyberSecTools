package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func finishEngagement(cfg *Config, mode engagementMode, name string) {
	engDir, err := resolveEngagementDir(cfg, mode, name)
	if err != nil {
		fatal("%v", err)
	}

	listCmd := exec.Command("gpg", "--list-secret-keys", "--keyid-format", "LONG")
	listCmd.Stdout = os.Stdout
	listCmd.Stderr = os.Stderr
	if err := listCmd.Run(); err != nil {
		fatal("listing GPG keys: %v", err)
	}

	fmt.Print("\nEnter key ID or email to sign with: ")
	reader := bufio.NewReader(os.Stdin)
	signKey, err := reader.ReadString('\n')
	if err != nil {
		fatal("reading key input: %v", err)
	}
	signKey = strings.TrimSpace(signKey)
	if signKey == "" {
		fatal("no key provided")
	}

	outputFile := filepath.Join(filepath.Dir(engDir), fmt.Sprintf("%s_%s.tar.gpg", name, "DR"))

	logInfo("archiving %s → %s", engDir, outputFile)

	tarCmd := exec.Command("tar", "-czf", "-", "-C", filepath.Dir(engDir), name)
	gpgCmd := exec.Command(
		"gpg",
		"--sign",
		"--local-user", signKey,
		"--output", outputFile,
	)

	pipe, err := tarCmd.StdoutPipe()
	if err != nil {
		fatal("creating pipe: %v", err)
	}
	gpgCmd.Stdin = pipe
	gpgCmd.Stdout = os.Stdout
	gpgCmd.Stderr = os.Stderr

	if err := tarCmd.Start(); err != nil {
		fatal("starting tar: %v", err)
	}
	if err := gpgCmd.Start(); err != nil {
		fatal("starting gpg: %v", err)
	}
	if err := tarCmd.Wait(); err != nil {
		fatal("tar failed: %v", err)
	}
	if err := gpgCmd.Wait(); err != nil {
		fatal("gpg failed: %v", err)
	}

	logInfo("finished: %s", outputFile)
}
