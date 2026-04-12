package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// withObsidianConfigDir redirects obsidianConfigDir to a temp directory for the
// duration of the test by overriding XDG_CONFIG_HOME.
func withObsidianConfigDir(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)
	return filepath.Join(tmp, "obsidian")
}

func TestEnsureObsidianVaultCreatesRegistry(t *testing.T) {
	cfgDir := withObsidianConfigDir(t)
	vaultPath := "/home/user/notes/acmecorp"

	if err := ensureObsidianVault(vaultPath); err != nil {
		t.Fatalf("ensureObsidianVault failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(cfgDir, "obsidian.json"))
	if err != nil {
		t.Fatalf("obsidian.json not created: %v", err)
	}

	var reg obsidianRegistry
	if err := json.Unmarshal(data, &reg); err != nil {
		t.Fatalf("obsidian.json is not valid JSON: %v", err)
	}

	for _, v := range reg.Vaults {
		if v.Path == vaultPath {
			if v.Ts <= 0 {
				t.Error("vault Ts should be a positive Unix ms timestamp")
			}
			return
		}
	}
	t.Errorf("vault %q not found in registry; got: %+v", vaultPath, reg.Vaults)
}

func TestEnsureObsidianVaultIsIdempotent(t *testing.T) {
	withObsidianConfigDir(t)
	vaultPath := "/home/user/notes/lab1"

	if err := ensureObsidianVault(vaultPath); err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	if err := ensureObsidianVault(vaultPath); err != nil {
		t.Fatalf("second call failed: %v", err)
	}

	cfgDir, _ := obsidianConfigDir()
	data, _ := os.ReadFile(filepath.Join(cfgDir, "obsidian.json"))
	var reg obsidianRegistry
	json.Unmarshal(data, &reg)

	count := 0
	for _, v := range reg.Vaults {
		if v.Path == vaultPath {
			count++
		}
	}
	if count != 1 {
		t.Errorf("vault registered %d times, want exactly 1", count)
	}
}

func TestEnsureObsidianVaultAddsToExisting(t *testing.T) {
	cfgDir := withObsidianConfigDir(t)

	// Pre-populate registry with one vault.
	existing := obsidianRegistry{
		Vaults: map[string]obsidianVault{
			"aabbccdd11223344": {Path: "/home/user/Notes", Ts: 1000000},
		},
	}
	data, _ := json.MarshalIndent(existing, "", "  ")
	if err := os.MkdirAll(cfgDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "obsidian.json"), data, 0644); err != nil {
		t.Fatal(err)
	}

	newVault := "/home/user/notes/htb-lab"
	if err := ensureObsidianVault(newVault); err != nil {
		t.Fatalf("ensureObsidianVault failed: %v", err)
	}

	data, _ = os.ReadFile(filepath.Join(cfgDir, "obsidian.json"))
	var reg obsidianRegistry
	json.Unmarshal(data, &reg)

	if len(reg.Vaults) != 2 {
		t.Errorf("registry has %d vaults, want 2", len(reg.Vaults))
	}
	// Original vault must still be present.
	if _, ok := reg.Vaults["aabbccdd11223344"]; !ok {
		t.Error("existing vault was removed from registry")
	}
}

func TestEnsureObsidianVaultDeterministicID(t *testing.T) {
	withObsidianConfigDir(t)
	vaultPath := "/home/user/notes/deterministic"

	// Compute the expected ID the same way the implementation does.
	sum := sha256.Sum256([]byte(vaultPath))
	wantID := hex.EncodeToString(sum[:8])

	if err := ensureObsidianVault(vaultPath); err != nil {
		t.Fatalf("ensureObsidianVault failed: %v", err)
	}

	cfgDir, _ := obsidianConfigDir()
	data, _ := os.ReadFile(filepath.Join(cfgDir, "obsidian.json"))
	var reg obsidianRegistry
	json.Unmarshal(data, &reg)

	if _, ok := reg.Vaults[wantID]; !ok {
		t.Errorf("expected vault ID %q not found in registry; got keys: %v",
			wantID, vaultKeys(reg))
	}
}

func vaultKeys(reg obsidianRegistry) []string {
	keys := make([]string, 0, len(reg.Vaults))
	for k := range reg.Vaults {
		keys = append(keys, k)
	}
	return keys
}
