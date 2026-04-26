package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	envNessusHost         = "RECON_NESSUS_HOST"
	envNessusAccessKey    = "RECON_NESSUS_ACCESS_KEY"
	envNessusSecretKey    = "RECON_NESSUS_SECRET_KEY"
	envNessusTemplateUUID = "RECON_NESSUS_TEMPLATE_UUID"
	envNessusInsecureTLS  = "RECON_NESSUS_INSECURE_TLS"
	envNessusPollSecs     = "RECON_NESSUS_POLL_SECS"
	envNessusMaxScanMins  = "RECON_NESSUS_MAX_SCAN_MINUTES"
	envWordlist           = "RECON_WORDLIST"
	envVhostWordlist      = "RECON_VHOST_WORDLIST"
	envNucleiTemplates    = "RECON_NUCLEI_TEMPLATES"
	envToolsTimeoutSecs   = "RECON_TOOLS_TIMEOUT_SECS"
	envToolDelaySecs      = "RECON_TOOL_DELAY_SECS"
	envProxy              = "RECON_PROXY"
	envWPScanAPIToken     = "RECON_WPSCAN_API_TOKEN"
	envGithubOrgs         = "RECON_GITHUB_ORGS"

	burpProxyURL = "http://127.0.0.1:8080"

	defaultNessusPollSecs    = 60
	defaultNessusMaxScanMins = 240
	defaultToolsTimeoutSecs  = 300
	defaultFuzzTimeoutSecs   = 1800 // 30 min for feroxbuster, nuclei, testssl
	defaultToolDelaySecs     = 5
	defaultFeroxThreads      = 20
)

// Config holds all runtime configuration for recon_jr.
// Config precedence (highest to lowest): CLI flags > env vars > config file > defaults.
type Config struct {
	NessusHost         string   `json:"nessus_host"`
	NessusAccessKey    string   `json:"nessus_access_key"`
	NessusSecretKey    string   `json:"nessus_secret_key"`
	NessusTemplateUUID string   `json:"nessus_template_uuid"`
	NessusInsecureTLS  bool     `json:"nessus_insecure_tls"`
	NessusPollSecs     int      `json:"nessus_poll_secs"`
	NessusMaxScanMins  int      `json:"nessus_max_scan_minutes"`
	Wordlist           string   `json:"wordlist"`
	VhostWordlist      string   `json:"vhost_wordlist"`
	NucleiTemplates    string   `json:"nuclei_templates"`
	ToolsTimeoutSecs   int      `json:"tools_timeout_secs"`
	FuzzTimeoutSecs    int      `json:"fuzz_timeout_secs"` // timeout for slow tools: feroxbuster, nuclei, testssl
	FeroxThreads       int      `json:"ferox_threads"`     // feroxbuster --threads (default 20)
	ToolDelaySecs      int      `json:"tool_delay_secs"`
	SkipTools          []string `json:"skip_tools"`
	ProxyURL           string   `json:"proxy_url"`
	WPScanAPIToken     string   `json:"wpscan_api_token"`
	GithubOrgs         []string `json:"github_orgs"`
}

// nessusEnabled reports whether Nessus credentials are configured.
func (c *Config) nessusEnabled() bool {
	return c.NessusHost != "" && c.NessusAccessKey != "" && c.NessusSecretKey != ""
}

// expandPath expands a leading ~/ in path to the user's home directory.
func expandPath(path string) string {
	if !strings.HasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, path[2:])
}

// loadConfig builds a Config by layering sources in ascending priority:
// defaults < config file < environment variables < CLI flags.
//
// cliNessusHost, cliWordlist, cliNucleiTemplates are set when the corresponding
// CLI flags are provided; empty string means "not set by CLI".
func loadConfig(configPath, cliNessusHost, cliWordlist, cliNucleiTemplates, cliProxy string) (*Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("could not determine home directory: %w", err)
	}

	cfg := &Config{
		NessusPollSecs:    defaultNessusPollSecs,
		NessusMaxScanMins: defaultNessusMaxScanMins,
		ToolsTimeoutSecs:  defaultToolsTimeoutSecs,
		FuzzTimeoutSecs:   defaultFuzzTimeoutSecs,
		FeroxThreads:      defaultFeroxThreads,
		ToolDelaySecs:     defaultToolDelaySecs,
		Wordlist:          "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
		VhostWordlist:     "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
		NucleiTemplates:   filepath.Join(home, ".local", "nuclei-templates"),
	}

	// Config file — silently skipped if absent, warned on any other read error.
	if configPath == "" {
		configPath = filepath.Join(home, ".config", "recon_jr", "config.json")
	}
	data, readErr := os.ReadFile(configPath)
	if readErr == nil {
		var fileCfg Config
		if err := json.Unmarshal(data, &fileCfg); err != nil {
			return nil, fmt.Errorf("invalid config file %s: %w", configPath, err)
		}
		if fileCfg.NessusHost != "" {
			cfg.NessusHost = fileCfg.NessusHost
		}
		if fileCfg.NessusAccessKey != "" {
			cfg.NessusAccessKey = fileCfg.NessusAccessKey
		}
		if fileCfg.NessusSecretKey != "" {
			cfg.NessusSecretKey = fileCfg.NessusSecretKey
		}
		if fileCfg.NessusTemplateUUID != "" {
			cfg.NessusTemplateUUID = fileCfg.NessusTemplateUUID
		}
		if fileCfg.NessusInsecureTLS {
			cfg.NessusInsecureTLS = true
		}
		if fileCfg.NessusPollSecs > 0 {
			cfg.NessusPollSecs = fileCfg.NessusPollSecs
		}
		if fileCfg.NessusMaxScanMins > 0 {
			cfg.NessusMaxScanMins = fileCfg.NessusMaxScanMins
		}
		if fileCfg.Wordlist != "" {
			cfg.Wordlist = fileCfg.Wordlist
		}
		if fileCfg.VhostWordlist != "" {
			cfg.VhostWordlist = fileCfg.VhostWordlist
		}
		if fileCfg.NucleiTemplates != "" {
			cfg.NucleiTemplates = fileCfg.NucleiTemplates
		}
		if fileCfg.ToolsTimeoutSecs > 0 {
			cfg.ToolsTimeoutSecs = fileCfg.ToolsTimeoutSecs
		}
		if fileCfg.FuzzTimeoutSecs > 0 {
			cfg.FuzzTimeoutSecs = fileCfg.FuzzTimeoutSecs
		}
		if fileCfg.FeroxThreads > 0 {
			cfg.FeroxThreads = fileCfg.FeroxThreads
		}
		if fileCfg.ToolDelaySecs >= 0 {
			cfg.ToolDelaySecs = fileCfg.ToolDelaySecs
		}
		if len(fileCfg.SkipTools) > 0 {
			cfg.SkipTools = fileCfg.SkipTools
		}
		if fileCfg.ProxyURL != "" {
			cfg.ProxyURL = fileCfg.ProxyURL
		}
		if fileCfg.WPScanAPIToken != "" {
			cfg.WPScanAPIToken = fileCfg.WPScanAPIToken
		}
		if len(fileCfg.GithubOrgs) > 0 {
			cfg.GithubOrgs = fileCfg.GithubOrgs
		}
		logDebug("loaded config from %s", configPath)
	} else if !os.IsNotExist(readErr) {
		logWarn("could not read config file %s: %v", configPath, readErr)
	}

	// Environment variables.
	if v := os.Getenv(envNessusHost); v != "" {
		cfg.NessusHost = v
	}
	if v := os.Getenv(envNessusAccessKey); v != "" {
		cfg.NessusAccessKey = v
	}
	if v := os.Getenv(envNessusSecretKey); v != "" {
		cfg.NessusSecretKey = v
	}
	if v := os.Getenv(envNessusTemplateUUID); v != "" {
		cfg.NessusTemplateUUID = v
	}
	if v := os.Getenv(envNessusInsecureTLS); v != "" {
		v = strings.ToLower(strings.TrimSpace(v))
		cfg.NessusInsecureTLS = v == "1" || v == "true"
	}
	if v := os.Getenv(envNessusPollSecs); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.NessusPollSecs = n
		} else {
			logWarn("invalid %s value %q — using %ds", envNessusPollSecs, v, cfg.NessusPollSecs)
		}
	}
	if v := os.Getenv(envNessusMaxScanMins); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.NessusMaxScanMins = n
		} else {
			logWarn("invalid %s value %q — using %dm", envNessusMaxScanMins, v, cfg.NessusMaxScanMins)
		}
	}
	if v := os.Getenv(envWordlist); v != "" {
		cfg.Wordlist = v
	}
	if v := os.Getenv(envVhostWordlist); v != "" {
		cfg.VhostWordlist = v
	}
	if v := os.Getenv(envNucleiTemplates); v != "" {
		cfg.NucleiTemplates = v
	}
	if v := os.Getenv(envToolsTimeoutSecs); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.ToolsTimeoutSecs = n
		} else {
			logWarn("invalid %s value %q — using %ds", envToolsTimeoutSecs, v, cfg.ToolsTimeoutSecs)
		}
	}
	if v := os.Getenv(envToolDelaySecs); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			cfg.ToolDelaySecs = n
		} else {
			logWarn("invalid %s value %q — using %ds", envToolDelaySecs, v, cfg.ToolDelaySecs)
		}
	}
	if v := os.Getenv(envProxy); v != "" {
		cfg.ProxyURL = v
	}
	if v := os.Getenv(envWPScanAPIToken); v != "" {
		cfg.WPScanAPIToken = v
	}
	if v := os.Getenv(envGithubOrgs); v != "" {
		for _, org := range strings.Split(v, ",") {
			if org = strings.TrimSpace(org); org != "" {
				cfg.GithubOrgs = append(cfg.GithubOrgs, org)
			}
		}
	}

	// CLI flags — highest priority.
	if cliNessusHost != "" {
		cfg.NessusHost = cliNessusHost
	}
	if cliWordlist != "" {
		cfg.Wordlist = cliWordlist
	}
	if cliNucleiTemplates != "" {
		cfg.NucleiTemplates = cliNucleiTemplates
	}
	if cliProxy != "" {
		cfg.ProxyURL = cliProxy
	}

	// Expand ~ paths.
	cfg.Wordlist = expandPath(cfg.Wordlist)
	cfg.VhostWordlist = expandPath(cfg.VhostWordlist)
	cfg.NucleiTemplates = expandPath(cfg.NucleiTemplates)

	if cfg.ToolDelaySecs == 0 {
		logWarn("tool_delay_secs is 0 — back-to-back tool execution may trigger WAF rate limits")
	}

	return cfg, nil
}
