package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

//go:embed templates
var embeddedTemplates embed.FS

// HostFileFeature controls whether the engagement accepts a host/scope file.
type HostFileFeature struct {
	Enabled bool `json:"enabled"`
}

// BurpFeature controls whether Burp Suite project creation is triggered.
type BurpFeature struct {
	Enabled bool `json:"enabled"`
}

// AWSFeature controls AWS-specific behaviour for cloud engagements.
type AWSFeature struct {
	Enabled       bool   `json:"enabled"`
	ProfilesFile  bool   `json:"profiles_file"`  // accept profiles.txt as second arg
	DefaultOutput string `json:"default_output"` // "json", "text", or "table"
}

// EngagementTemplate is the deserialized form of a templates/<name>.json file.
// It drives directory creation, feature flags, and tmux layout selection.
type EngagementTemplate struct {
	SubDir            string             `json:"sub_dir"`
	Dirs              []string           `json:"dirs"`
	IsolatedVault     bool               `json:"isolated_vault"`
	PromoteRedLessons bool               `json:"promote_red_lessons"`
	HostFile          HostFileFeature    `json:"host_file"`
	Burp              BurpFeature        `json:"burp"`
	AWS               AWSFeature         `json:"aws"`
	Env               map[string]string  `json:"env,omitempty"`
	TmuxLayout        []TmuxWindowConfig `json:"tmux_layout,omitempty"`
}

// loadTemplate loads a named engagement template. Lookup order (highest first):
//  1. ~/.config/engage_jr/templates/<name>.json  — user always wins
//  2. Embedded templates/<name>.json             — shipped defaults
func loadTemplate(name string) (*EngagementTemplate, error) {
	// 1. User override.
	home, err := os.UserHomeDir()
	if err == nil {
		userPath := filepath.Join(home, ".config", "engage_jr", "templates", name+".json")
		if data, err := os.ReadFile(userPath); err == nil {
			return parseTemplate(data, userPath)
		}
	}

	// 2. Embedded default.
	data, err := embeddedTemplates.ReadFile("templates/" + name + ".json")
	if err != nil {
		return nil, fmt.Errorf("template %q not found (no built-in or user override)", name)
	}
	return parseTemplate(data, "embedded:"+name)
}

func parseTemplate(data []byte, src string) (*EngagementTemplate, error) {
	var t EngagementTemplate
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("invalid template %s: %w", src, err)
	}
	return &t, nil
}
