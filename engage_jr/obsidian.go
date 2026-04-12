package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type obsidianRegistry struct {
	Vaults map[string]obsidianVault `json:"vaults"`
}

type obsidianVault struct {
	Path string `json:"path"`
	Ts   int64  `json:"ts"`
}

// ensureObsidianVault registers vaultPath in Obsidian's vault registry
// (~/.config/obsidian/obsidian.json) so that obsidian://open?path=<path>
// opens the correct vault without a manual selection step.
//
// The function is idempotent — if the path is already registered it returns
// immediately. Errors are non-fatal; callers should log and continue.
func ensureObsidianVault(vaultPath string) error {
	cfgDir, err := obsidianConfigDir()
	if err != nil {
		return err
	}
	registryPath := filepath.Join(cfgDir, "obsidian.json")

	// Read existing registry, or start with an empty one.
	reg := obsidianRegistry{Vaults: map[string]obsidianVault{}}
	if data, err := os.ReadFile(registryPath); err == nil {
		if err := json.Unmarshal(data, &reg); err != nil {
			return fmt.Errorf("parsing obsidian registry: %w", err)
		}
		if reg.Vaults == nil {
			reg.Vaults = map[string]obsidianVault{}
		}
	}

	// No-op if the path is already registered.
	for _, v := range reg.Vaults {
		if v.Path == vaultPath {
			return nil
		}
	}

	// Deterministic ID: first 8 bytes of SHA-256(path) → 16 hex chars.
	sum := sha256.Sum256([]byte(vaultPath))
	id := hex.EncodeToString(sum[:8])

	reg.Vaults[id] = obsidianVault{
		Path: vaultPath,
		Ts:   time.Now().UnixMilli(),
	}

	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling obsidian registry: %w", err)
	}

	// Atomic write: write to a temp file then rename.
	tmp := registryPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return fmt.Errorf("writing obsidian registry: %w", err)
	}
	return os.Rename(tmp, registryPath)
}

// obsidianConfigDir returns the path to Obsidian's config directory,
// creating it if necessary. Respects XDG_CONFIG_HOME when set.
func obsidianConfigDir() (string, error) {
	cfgHome := os.Getenv("XDG_CONFIG_HOME")
	if cfgHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolving home directory: %w", err)
		}
		cfgHome = filepath.Join(home, ".config")
	}
	dir := filepath.Join(cfgHome, "obsidian")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("creating obsidian config dir: %w", err)
	}
	return dir, nil
}
