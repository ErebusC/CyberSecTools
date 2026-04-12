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
	envBurpJar           = "ENGAGE_BURP_JAR"
	envBaseDir           = "ENGAGE_BASE_DIR"
	envBurpTimeout       = "ENGAGE_BURP_TIMEOUT"
	envTmux              = "ENGAGE_TMUX"
	envTmuxSessionPrefix = "ENGAGE_TMUX_SESSION_PREFIX"
	envObsidianBin       = "ENGAGE_OBSIDIAN_BIN"
	envObsidianVault     = "ENGAGE_OBSIDIAN_VAULT"

	defaultBurpTimeoutSecs = 60
	defaultObsidianVault   = "~/Notes"
)

// defaultWorkDirs is the subdirectory layout created under a work engagement
// when no custom work_dirs are specified in the config file.
var defaultWorkDirs = []string{"nmap", "burp", "nessus", "other"}

// TmuxPaneConfig describes a single pane within a tmux window layout.
// The first pane in a window always exists on creation; subsequent panes are
// created by splitting the pane at SplitFrom (or the previous pane if nil).
type TmuxPaneConfig struct {
	SplitDirection string `json:"split_direction,omitempty"` // "h" (right) or "v" (below); default "v"
	SplitFrom      *int   `json:"split_from,omitempty"`      // pane index to split; nil = previous pane
	Percent        int    `json:"percent,omitempty"`         // percentage for the new pane (0 = tmux default)
	Command        string `json:"command,omitempty"`         // command typed into the pane shell after creation
}

// TmuxWindowConfig describes a tmux window and its pane layout.
// FocusPane selects which pane index is active after all panes are created.
type TmuxWindowConfig struct {
	Name      string           `json:"name"`
	Panes     []TmuxPaneConfig `json:"panes,omitempty"`
	FocusPane int              `json:"focus_pane"` // pane index to focus after layout (default 0)
}

type Config struct {
	BurpJar             string                        `json:"burp_jar"`
	BaseDir             string                        `json:"base_dir"`
	BurpTimeoutSecs     int                           `json:"burp_timeout_secs"`
	WorkDirs            []string                      `json:"work_dirs"`
	TmuxEnabled         *bool                         `json:"tmux_enabled"`          // nil = use default (true); explicit false disables tmux
	TmuxPrefix          string                        `json:"tmux_prefix"`           // prepended to session name; empty = use engagement name directly
	TmuxLayouts         map[string][]TmuxWindowConfig `json:"tmux_layouts"`          // keyed by mode string; overrides built-in defaults
	SSHHosts            map[string]string             `json:"ssh_hosts"`             // per-mode VPS/jump host alias; defers to ~/.ssh/config for key/port-forward details
	ObsidianBin         string                        `json:"obsidian_bin"`          // obsidian binary or full command
	ObsidianSyncedVault string                        `json:"obsidian_synced_vault"` // synced vault for HTB/THM/exam/swigger (default ~/Notes)
}

// tmuxEnabled reports whether tmux session management is active.
// Returns true by default (nil pointer = unset = use default).
func (c *Config) tmuxEnabled() bool {
	return c.TmuxEnabled == nil || *c.TmuxEnabled
}

// boolPtr returns a pointer to b, used for *bool config fields.
func boolPtr(b bool) *bool { return &b }

// loadConfig builds a Config by layering sources in ascending priority:
// defaults < config file < environment variables < CLI flags.
func loadConfig(configPath, cliBurpJar, cliBaseDir string) (*Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("could not determine home directory: %w", err)
	}

	cfg := &Config{
		BurpJar:             filepath.Join(home, "BurpSuitePro", "burpsuite_pro.jar"),
		BaseDir:             filepath.Join("/", "Share"),
		BurpTimeoutSecs:     defaultBurpTimeoutSecs,
		WorkDirs:            defaultWorkDirs,
		ObsidianBin:         "obsidian",
		ObsidianSyncedVault: defaultObsidianVault,
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
		if fileCfg.TmuxEnabled != nil {
			cfg.TmuxEnabled = fileCfg.TmuxEnabled
		}
		if fileCfg.TmuxPrefix != "" {
			cfg.TmuxPrefix = fileCfg.TmuxPrefix
		}
		if len(fileCfg.TmuxLayouts) > 0 {
			cfg.TmuxLayouts = fileCfg.TmuxLayouts
		}
		if len(fileCfg.SSHHosts) > 0 {
			cfg.SSHHosts = fileCfg.SSHHosts
		}
		if fileCfg.ObsidianBin != "" {
			cfg.ObsidianBin = fileCfg.ObsidianBin
		}
		if fileCfg.ObsidianSyncedVault != "" {
			cfg.ObsidianSyncedVault = fileCfg.ObsidianSyncedVault
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
	if v := os.Getenv(envTmux); v != "" {
		v = strings.ToLower(strings.TrimSpace(v))
		enabled := v == "1" || v == "true"
		cfg.TmuxEnabled = &enabled
	}
	if v := os.Getenv(envTmuxSessionPrefix); v != "" {
		cfg.TmuxPrefix = v
	}
	if v := os.Getenv(envObsidianBin); v != "" {
		cfg.ObsidianBin = v
	}
	if v := os.Getenv(envObsidianVault); v != "" {
		cfg.ObsidianSyncedVault = v
	}

	// CLI flags — highest priority.
	if cliBurpJar != "" {
		cfg.BurpJar = cliBurpJar
	}
	if cliBaseDir != "" {
		cfg.BaseDir = cliBaseDir
	}

	// If no explicit obsidian_bin was configured, prefer the GUI binary at its
	// standard Linux installation path over the "obsidian" CLI wrapper in PATH.
	// The CLI wrapper only dispatches to a running GUI instance; it cannot launch
	// Obsidian itself.
	if cfg.ObsidianBin == "obsidian" {
		const guiBin = "/opt/Obsidian/obsidian"
		if fi, err := os.Stat(guiBin); err == nil && fi.Mode()&0111 != 0 {
			cfg.ObsidianBin = guiBin
			logDebug("resolved Obsidian GUI binary: %s", guiBin)
		}
	}

	return cfg, nil
}
