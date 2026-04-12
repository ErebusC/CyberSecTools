package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func unsetTmuxEnvs(t *testing.T) {
	t.Helper()
	for _, e := range []string{envTmux, envTmuxSessionPrefix, envObsidianBin, envObsidianVault} {
		os.Unsetenv(e)
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	os.Unsetenv(envBurpJar)
	os.Unsetenv(envBaseDir)
	os.Unsetenv(envBurpTimeout)
	unsetTmuxEnvs(t)

	cfg, err := loadConfig("/nonexistent/config.json", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.BurpJar == "" {
		t.Error("BurpJar should have a default value")
	}
	if cfg.BaseDir == "" {
		t.Error("BaseDir should have a default value")
	}
	if cfg.BurpTimeoutSecs != defaultBurpTimeoutSecs {
		t.Errorf("BurpTimeoutSecs = %d, want %d", cfg.BurpTimeoutSecs, defaultBurpTimeoutSecs)
	}
}

func TestLoadConfigEnvVars(t *testing.T) {
	unsetTmuxEnvs(t)
	os.Setenv(envBurpJar, "/env/burp.jar")
	os.Setenv(envBaseDir, "/env/base")
	os.Setenv(envBurpTimeout, "120")
	defer os.Unsetenv(envBurpJar)
	defer os.Unsetenv(envBaseDir)
	defer os.Unsetenv(envBurpTimeout)

	cfg, err := loadConfig("/nonexistent/config.json", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.BurpJar != "/env/burp.jar" {
		t.Errorf("BurpJar = %q, want /env/burp.jar", cfg.BurpJar)
	}
	if cfg.BaseDir != "/env/base" {
		t.Errorf("BaseDir = %q, want /env/base", cfg.BaseDir)
	}
	if cfg.BurpTimeoutSecs != 120 {
		t.Errorf("BurpTimeoutSecs = %d, want 120", cfg.BurpTimeoutSecs)
	}
}

func TestLoadConfigInvalidBurpTimeout(t *testing.T) {
	unsetTmuxEnvs(t)
	os.Unsetenv(envBurpJar)
	os.Unsetenv(envBaseDir)
	os.Setenv(envBurpTimeout, "notanumber")
	defer os.Unsetenv(envBurpTimeout)

	cfg, err := loadConfig("/nonexistent/config.json", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Invalid env var should fall back to default, not crash.
	if cfg.BurpTimeoutSecs != defaultBurpTimeoutSecs {
		t.Errorf("BurpTimeoutSecs = %d after invalid env, want default %d", cfg.BurpTimeoutSecs, defaultBurpTimeoutSecs)
	}
}

func TestLoadConfigCLIOverridesEnv(t *testing.T) {
	unsetTmuxEnvs(t)
	os.Setenv(envBurpJar, "/env/burp.jar")
	os.Setenv(envBaseDir, "/env/base")
	defer os.Unsetenv(envBurpJar)
	defer os.Unsetenv(envBaseDir)

	cfg, err := loadConfig("/nonexistent/config.json", "/cli/burp.jar", "/cli/base")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.BurpJar != "/cli/burp.jar" {
		t.Errorf("BurpJar = %q, want /cli/burp.jar", cfg.BurpJar)
	}
	if cfg.BaseDir != "/cli/base" {
		t.Errorf("BaseDir = %q, want /cli/base", cfg.BaseDir)
	}
}

func TestLoadConfigFile(t *testing.T) {
	unsetTmuxEnvs(t)
	os.Unsetenv(envBurpJar)
	os.Unsetenv(envBaseDir)
	os.Unsetenv(envBurpTimeout)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	data, _ := json.Marshal(Config{
		BurpJar:         "/file/burp.jar",
		BaseDir:         "/file/base",
		BurpTimeoutSecs: 90,
	})
	if err := os.WriteFile(cfgPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(cfgPath, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.BurpJar != "/file/burp.jar" {
		t.Errorf("BurpJar = %q, want /file/burp.jar", cfg.BurpJar)
	}
	if cfg.BaseDir != "/file/base" {
		t.Errorf("BaseDir = %q, want /file/base", cfg.BaseDir)
	}
	if cfg.BurpTimeoutSecs != 90 {
		t.Errorf("BurpTimeoutSecs = %d, want 90", cfg.BurpTimeoutSecs)
	}
}

func TestLoadConfigFilePrecedenceBelowEnv(t *testing.T) {
	unsetTmuxEnvs(t)
	os.Setenv(envBurpJar, "/env/burp.jar")
	defer os.Unsetenv(envBurpJar)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	data, _ := json.Marshal(Config{BurpJar: "/file/burp.jar"})
	os.WriteFile(cfgPath, data, 0644)

	cfg, err := loadConfig(cfgPath, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Env var should win over config file.
	if cfg.BurpJar != "/env/burp.jar" {
		t.Errorf("BurpJar = %q, want /env/burp.jar (env should override file)", cfg.BurpJar)
	}
}

func TestLoadConfigInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	os.WriteFile(cfgPath, []byte("not json {{{"), 0644)

	_, err := loadConfig(cfgPath, "", "")
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestLoadConfigTmuxEnabledByDefault(t *testing.T) {
	unsetTmuxEnvs(t)

	cfg, err := loadConfig("/nonexistent/config.json", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.tmuxEnabled() {
		t.Error("tmux should be enabled by default (nil TmuxEnabled → true)")
	}
	if cfg.TmuxPrefix != "" {
		t.Errorf("TmuxPrefix = %q, want empty (no prefix by default)", cfg.TmuxPrefix)
	}
}

func TestLoadConfigTmuxDisableViaEnv(t *testing.T) {
	unsetTmuxEnvs(t)
	for _, val := range []string{"0", "false", "FALSE"} {
		t.Run(val, func(t *testing.T) {
			os.Setenv(envTmux, val)
			defer os.Unsetenv(envTmux)

			cfg, err := loadConfig("/nonexistent/config.json", "", "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.tmuxEnabled() {
				t.Errorf("tmux should be disabled for ENGAGE_TMUX=%q", val)
			}
		})
	}
}

func TestLoadConfigTmuxDisableViaFile(t *testing.T) {
	unsetTmuxEnvs(t)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	disabled := false
	data, _ := json.Marshal(map[string]interface{}{"tmux_enabled": disabled})
	if err := os.WriteFile(cfgPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(cfgPath, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.tmuxEnabled() {
		t.Error("tmux should be disabled when config file sets tmux_enabled: false")
	}
}

func TestLoadConfigTmuxEnvVar(t *testing.T) {
	unsetTmuxEnvs(t)
	for _, val := range []string{"1", "true", "TRUE", "True"} {
		t.Run(val, func(t *testing.T) {
			os.Setenv(envTmux, val)
			defer os.Unsetenv(envTmux)

			cfg, err := loadConfig("/nonexistent/config.json", "", "")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !cfg.tmuxEnabled() {
				t.Errorf("tmuxEnabled() = false for ENGAGE_TMUX=%q, want true", val)
			}
		})
	}
}

func TestLoadConfigTmuxPrefixEnvVar(t *testing.T) {
	unsetTmuxEnvs(t)
	os.Setenv(envTmuxSessionPrefix, "pentest")
	defer os.Unsetenv(envTmuxSessionPrefix)

	cfg, err := loadConfig("/nonexistent/config.json", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.TmuxPrefix != "pentest" {
		t.Errorf("TmuxPrefix = %q, want pentest", cfg.TmuxPrefix)
	}
}

func TestLoadConfigObsidianDefaults(t *testing.T) {
	unsetTmuxEnvs(t)

	cfg, err := loadConfig("/nonexistent/config.json", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The GUI binary at /opt/Obsidian/obsidian is preferred when it exists;
	// otherwise the default falls back to the "obsidian" name in PATH.
	const guiBin = "/opt/Obsidian/obsidian"
	wantBin := "obsidian"
	if fi, err := os.Stat(guiBin); err == nil && fi.Mode()&0111 != 0 {
		wantBin = guiBin
	}
	if cfg.ObsidianBin != wantBin {
		t.Errorf("ObsidianBin = %q, want %q", cfg.ObsidianBin, wantBin)
	}
	if cfg.ObsidianSyncedVault != defaultObsidianVault {
		t.Errorf("ObsidianSyncedVault = %q, want %q", cfg.ObsidianSyncedVault, defaultObsidianVault)
	}
}

func TestLoadConfigObsidianEnvVars(t *testing.T) {
	unsetTmuxEnvs(t)
	os.Setenv(envObsidianBin, "/opt/Obsidian.AppImage")
	os.Setenv(envObsidianVault, "/home/user/SyncedNotes")
	defer os.Unsetenv(envObsidianBin)
	defer os.Unsetenv(envObsidianVault)

	cfg, err := loadConfig("/nonexistent/config.json", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ObsidianBin != "/opt/Obsidian.AppImage" {
		t.Errorf("ObsidianBin = %q, want /opt/Obsidian.AppImage", cfg.ObsidianBin)
	}
	if cfg.ObsidianSyncedVault != "/home/user/SyncedNotes" {
		t.Errorf("ObsidianSyncedVault = %q, want /home/user/SyncedNotes", cfg.ObsidianSyncedVault)
	}
}

func TestLoadConfigSSHHostsFromFile(t *testing.T) {
	unsetTmuxEnvs(t)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	data, _ := json.Marshal(map[string]interface{}{
		"ssh_hosts": map[string]string{"work": "lhack", "HTB": "htb-vps"},
	})
	if err := os.WriteFile(cfgPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(cfgPath, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.SSHHosts["work"] != "lhack" {
		t.Errorf("SSHHosts[work] = %q, want lhack", cfg.SSHHosts["work"])
	}
	if cfg.SSHHosts["HTB"] != "htb-vps" {
		t.Errorf("SSHHosts[HTB] = %q, want htb-vps", cfg.SSHHosts["HTB"])
	}
}

func TestLoadConfigTmuxLayoutFromFile(t *testing.T) {
	unsetTmuxEnvs(t)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	data, _ := json.Marshal(map[string]interface{}{
		"tmux_layouts": map[string]interface{}{
			"work": []map[string]interface{}{
				{"name": "shell", "focus_pane": 0,
					"panes": []map[string]interface{}{
						{},
						{"split_direction": "v", "percent": 40},
					}},
			},
		},
	})
	if err := os.WriteFile(cfgPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(cfgPath, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	layout := cfg.TmuxLayouts["work"]
	if len(layout) != 1 {
		t.Fatalf("TmuxLayouts[work] has %d windows, want 1", len(layout))
	}
	if layout[0].Name != "shell" {
		t.Errorf("TmuxLayouts[work][0].Name = %q, want shell", layout[0].Name)
	}
	if len(layout[0].Panes) != 2 {
		t.Errorf("TmuxLayouts[work][0] has %d panes, want 2", len(layout[0].Panes))
	}
}
