package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type gpgKey struct {
	keyID string
	uid   string
}

func listGPGKeys(secret bool) ([]gpgKey, error) {
	args := []string{"--with-colons", "--keyid-format", "LONG"}
	if secret {
		args = append(args, "--list-secret-keys")
	} else {
		args = append(args, "--list-keys")
	}

	out, err := exec.Command("gpg", args...).Output()
	if err != nil {
		return nil, err
	}

	var keys []gpgKey
	var current gpgKey
	keyTag := "pub"
	if secret {
		keyTag = "sec"
	}

	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			continue
		}
		if fields[0] == keyTag {
			current = gpgKey{keyID: fields[4]}
		}
		if fields[0] == "uid" && current.keyID != "" {
			current.uid = fields[9]
			keys = append(keys, current)
			current = gpgKey{}
		}
	}
	return keys, nil
}

func promptKeySelection(reader *bufio.Reader, keys []gpgKey, prompt string) string {
	fmt.Println()
	for i, k := range keys {
		fmt.Printf("  [%d] %s (%s)\n", i+1, k.uid, k.keyID)
	}
	fmt.Printf("\n%s: ", prompt)

	input, err := reader.ReadString('\n')
	if err != nil {
		fatal("reading input: %v", err)
	}
	input = strings.TrimSpace(input)
	if input == "" {
		fatal("no key provided")
	}

	if idx, err := strconv.Atoi(input); err == nil && idx >= 1 && idx <= len(keys) {
		return keys[idx-1].keyID
	}
	return input
}

func finishEngagement(cfg *Config, tmpl *EngagementTemplate, name string) {
	engDir, err := resolveEngagementDir(cfg, tmpl.SubDir, name)
	if err != nil {
		fatal("%v", err)
	}

	// Kill the tmux session for this engagement before archiving so no zombie
	// sessions remain after the directory is encrypted and removed.
	if cfg.tmuxEnabled() {
		session := tmuxSessionName(cfg, name)
		if tmuxSessionExists(session) {
			if err := exec.Command("tmux", "kill-session", "-t", session).Run(); err != nil {
				logWarn("could not kill tmux session %q: %v", session, err)
			} else {
				logInfo("killed tmux session: %s", session)
			}
		}
	}

	reader := bufio.NewReader(os.Stdin)

	pubKeys, err := listGPGKeys(false)
	if err != nil {
		fatal("listing public keys: %v", err)
	}
	if len(pubKeys) == 0 {
		fatal("no public keys found")
	}
	recipientKey := promptKeySelection(reader, pubKeys,
		"Select the key to encrypt the file with (recipient who will decrypt it)")

	secKeys, err := listGPGKeys(true)
	if err != nil {
		fatal("listing secret keys: %v", err)
	}
	if len(secKeys) == 0 {
		fatal("no secret keys found")
	}
	signKey := promptKeySelection(reader, secKeys,
		"Select your signing key (so recipients know who encrypted it)")

	finalPath := filepath.Join(filepath.Dir(engDir), fmt.Sprintf("%s_%s.tar.gpg", name, "DR"))

	localTmp, err := os.UserCacheDir()
	if err != nil {
		localTmp = os.TempDir()
	} else {
		localTmp = filepath.Join(localTmp, "engage_jr")
		if err := os.MkdirAll(localTmp, 0700); err != nil {
			localTmp = os.TempDir()
		}
	}
	tmpFile, err := os.CreateTemp(localTmp, "engage-*.tar.gpg")
	if err != nil {
		fatal("creating temp file: %v", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	os.Remove(tmpPath)
	defer os.Remove(tmpPath)

	logInfo("encrypting %s → %s", engDir, finalPath)

	tarCmd := exec.Command(
		"tar",
		"-cf", "-",
		"-C", engDir,
		".",
	)
	gpgCmd := exec.Command(
		"gpg",
		"--encrypt",
		"--sign",
		"--trust-model", "always",
		"--local-user", signKey,
		"--recipient", recipientKey,
		"--output", tmpPath,
	)

	pipe, err := tarCmd.StdoutPipe()
	if err != nil {
		fatal("creating pipe: %v", err)
	}
	gpgCmd.Stdin = bufio.NewReaderSize(pipe, 1024*1024)
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

	logInfo("moving to %s", finalPath)
	src, err := os.Open(tmpPath)
	if err != nil {
		fatal("opening temp file: %v", err)
	}
	defer src.Close()
	dst, err := os.OpenFile(finalPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		fatal("creating output file: %v", err)
	}
	defer dst.Close()
	if _, err := io.CopyBuffer(dst, src, make([]byte, 4*1024*1024)); err != nil {
		fatal("writing output: %v", err)
	}

	logInfo("finished: %s", finalPath)

	// Promote redacted lessons to the synced vault when the template enables it.
	if tmpl.PromoteRedLessons {
		dest, err := promoteRedLessons(engDir, name, reader)
		if err != nil {
			logWarn("could not promote lessons to synced vault: %v", err)
		} else if dest != "" {
			logInfo("lessons promoted: %s", dest)
		}
	}
}
