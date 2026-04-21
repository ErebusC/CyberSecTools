package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigDefaults(t *testing.T) {
	cfg, err := loadConfig("nonexistent_config_defaults_test.json", "", "", "", "")
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.NessusPollSecs != defaultNessusPollSecs {
		t.Errorf("NessusPollSecs: got %d, want %d", cfg.NessusPollSecs, defaultNessusPollSecs)
	}
	if cfg.NessusMaxScanMins != defaultNessusMaxScanMins {
		t.Errorf("NessusMaxScanMins: got %d, want %d", cfg.NessusMaxScanMins, defaultNessusMaxScanMins)
	}
	if cfg.ToolsTimeoutSecs != defaultToolsTimeoutSecs {
		t.Errorf("ToolsTimeoutSecs: got %d, want %d", cfg.ToolsTimeoutSecs, defaultToolsTimeoutSecs)
	}
	if cfg.ToolDelaySecs != defaultToolDelaySecs {
		t.Errorf("ToolDelaySecs: got %d, want %d", cfg.ToolDelaySecs, defaultToolDelaySecs)
	}
}

func TestLoadConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.json")

	data, _ := json.Marshal(Config{
		NessusHost:        "https://nessus.test:8834",
		NessusAccessKey:   "testkey",
		NessusSecretKey:   "testsecret",
		NessusPollSecs:    30,
		NessusMaxScanMins: 120,
		ToolDelaySecs:     10,
		SkipTools:         []string{"nikto"},
	})
	os.WriteFile(cfgFile, data, 0644)

	cfg, err := loadConfig(cfgFile, "", "", "", "")
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.NessusHost != "https://nessus.test:8834" {
		t.Errorf("NessusHost: got %q", cfg.NessusHost)
	}
	if cfg.NessusAccessKey != "testkey" {
		t.Errorf("NessusAccessKey: got %q", cfg.NessusAccessKey)
	}
	if cfg.NessusPollSecs != 30 {
		t.Errorf("NessusPollSecs: got %d", cfg.NessusPollSecs)
	}
	if len(cfg.SkipTools) != 1 || cfg.SkipTools[0] != "nikto" {
		t.Errorf("SkipTools: got %v", cfg.SkipTools)
	}
}

func TestLoadConfigEnvVars(t *testing.T) {
	t.Setenv(envNessusHost, "https://env-nessus:8834")
	t.Setenv(envNessusAccessKey, "env-access")
	t.Setenv(envNessusSecretKey, "env-secret")
	t.Setenv(envToolDelaySecs, "15")

	cfg, err := loadConfig("nonexistent_config.json", "", "", "", "")
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.NessusHost != "https://env-nessus:8834" {
		t.Errorf("NessusHost from env: got %q", cfg.NessusHost)
	}
	if cfg.ToolDelaySecs != 15 {
		t.Errorf("ToolDelaySecs from env: got %d", cfg.ToolDelaySecs)
	}
}

func TestLoadConfigCLIOverrides(t *testing.T) {
	t.Setenv(envNessusHost, "https://env-nessus:8834")

	cfg, err := loadConfig("", "https://cli-nessus:8834", "", "", "")
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	// CLI should win over env
	if cfg.NessusHost != "https://cli-nessus:8834" {
		t.Errorf("NessusHost CLI override: got %q", cfg.NessusHost)
	}
}

func TestLoadConfigPrecedence(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.json")
	data, _ := json.Marshal(Config{NessusHost: "https://file-nessus:8834"})
	os.WriteFile(cfgFile, data, 0644)

	t.Setenv(envNessusHost, "https://env-nessus:8834")

	// env wins over file
	cfg, err := loadConfig(cfgFile, "", "", "", "")
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.NessusHost != "https://env-nessus:8834" {
		t.Errorf("env should override file: got %q", cfg.NessusHost)
	}
}

func TestNessusEnabled(t *testing.T) {
	tests := []struct {
		cfg  Config
		want bool
	}{
		{Config{NessusHost: "https://nessus:8834", NessusAccessKey: "a", NessusSecretKey: "s"}, true},
		{Config{NessusHost: "", NessusAccessKey: "a", NessusSecretKey: "s"}, false},
		{Config{NessusHost: "https://nessus:8834", NessusAccessKey: "", NessusSecretKey: "s"}, false},
		{Config{}, false},
	}
	for _, tt := range tests {
		if got := tt.cfg.nessusEnabled(); got != tt.want {
			t.Errorf("nessusEnabled() = %v, want %v for %+v", got, tt.want, tt.cfg)
		}
	}
}

func TestLoadConfigProxy(t *testing.T) {
	// CLI proxy flag
	cfg, err := loadConfig("", "", "", "", "http://127.0.0.1:8080")
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.ProxyURL != "http://127.0.0.1:8080" {
		t.Errorf("ProxyURL from CLI: got %q", cfg.ProxyURL)
	}

	// Env var
	t.Setenv(envProxy, "http://10.0.0.1:8888")
	cfg, err = loadConfig("", "", "", "", "")
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.ProxyURL != "http://10.0.0.1:8888" {
		t.Errorf("ProxyURL from env: got %q", cfg.ProxyURL)
	}

	// CLI overrides env
	cfg, err = loadConfig("", "", "", "", "http://127.0.0.1:8080")
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.ProxyURL != "http://127.0.0.1:8080" {
		t.Errorf("CLI should override env proxy: got %q", cfg.ProxyURL)
	}
}

func TestExpandPath(t *testing.T) {
	home, _ := os.UserHomeDir()
	tests := []struct {
		input string
		want  string
	}{
		{"~/foo", filepath.Join(home, "foo")},
		{"/absolute/path", "/absolute/path"},
		{"relative/path", "relative/path"},
	}
	for _, tt := range tests {
		if got := expandPath(tt.input); got != tt.want {
			t.Errorf("expandPath(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
