package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigDefaults(t *testing.T) {
	os.Unsetenv(envBurpJar)
	os.Unsetenv(envBaseDir)
	os.Unsetenv(envBurpTimeout)

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
