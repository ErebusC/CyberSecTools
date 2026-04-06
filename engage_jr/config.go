package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

const (
	envBurpJar     = "ENGAGE_BURP_JAR"
	envBaseDir     = "ENGAGE_BASE_DIR"
	envBurpTimeout = "ENGAGE_BURP_TIMEOUT"

	defaultBurpTimeoutSecs = 60
)

// defaultWorkDirs is the subdirectory layout created under a work engagement
// when no custom work_dirs are specified in the config file.
var defaultWorkDirs = []string{"nmap", "burp", "nessus", "other"}

type Config struct {
	BurpJar         string   `json:"burp_jar"`
	BaseDir         string   `json:"base_dir"`
	BurpTimeoutSecs int      `json:"burp_timeout_secs"`
	WorkDirs        []string `json:"work_dirs"`
}

// loadConfig builds a Config by layering sources in ascending priority:
// defaults < config file < environment variables < CLI flags.
func loadConfig(configPath, cliBurpJar, cliBaseDir string) (*Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("could not determine home directory: %w", err)
	}

	cfg := &Config{
		BurpJar:         filepath.Join(home, "BurpSuitePro", "burpsuite_pro.jar"),
		BaseDir:         filepath.Join("/", "Share"),
		BurpTimeoutSecs: defaultBurpTimeoutSecs,
		WorkDirs:        defaultWorkDirs,
	}

	// Config file — silently skipped if absent, warned on any other read error.
	if configPath == "" {
		configPath = filepath.Join(home, ".config", "engage_jr", "config.json")
	}
	data, readErr := os.ReadFile(configPath)
	if readErr == nil {
		var fileCfg Config
		if err := json.Unmarshal(data, &fileCfg); err != nil {
			return nil, fmt.Errorf("invalid config file %s: %w", configPath, err)
		}
		if fileCfg.BurpJar != "" {
			cfg.BurpJar = fileCfg.BurpJar
		}
		if fileCfg.BaseDir != "" {
			cfg.BaseDir = fileCfg.BaseDir
		}
		if fileCfg.BurpTimeoutSecs > 0 {
			cfg.BurpTimeoutSecs = fileCfg.BurpTimeoutSecs
		}
		if len(fileCfg.WorkDirs) > 0 {
			cfg.WorkDirs = fileCfg.WorkDirs
		}
		logDebug("loaded config from %s", configPath)
	} else if !os.IsNotExist(readErr) {
		logWarn("could not read config file %s: %v", configPath, readErr)
	}

	// Environment variables.
	if v := os.Getenv(envBurpJar); v != "" {
		cfg.BurpJar = v
	}
	if v := os.Getenv(envBaseDir); v != "" {
		cfg.BaseDir = v
	}
	if v := os.Getenv(envBurpTimeout); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			logWarn("invalid %s value %q — using %ds", envBurpTimeout, v, cfg.BurpTimeoutSecs)
		} else {
			cfg.BurpTimeoutSecs = n
		}
	}

	// CLI flags — highest priority.
	if cliBurpJar != "" {
		cfg.BurpJar = cliBurpJar
	}
	if cliBaseDir != "" {
		cfg.BaseDir = cliBaseDir
	}

	return cfg, nil
}
