package main

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTmuxSessionNameNoPrefix(t *testing.T) {
	cfg := &Config{TmuxPrefix: ""}
	got := tmuxSessionName(cfg, "acmecorp_inc_1_5")
	if got != "acmecorp_inc_1_5" {
		t.Errorf("tmuxSessionName = %q, want acmecorp_inc_1_5", got)
	}
}

func TestTmuxSessionNameWithPrefix(t *testing.T) {
	cfg := &Config{TmuxPrefix: "pentest"}
	got := tmuxSessionName(cfg, "acmecorp_inc_1_5")
	if got != "pentest_acmecorp_inc_1_5" {
		t.Errorf("tmuxSessionName = %q, want pentest_acmecorp_inc_1_5", got)
	}
}

func TestReadHostsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	content := "10.10.10.1\n# comment\n10.10.10.2\n\n10.10.10.3\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	lines := readHostsFile(path)
	if len(lines) != 3 {
		t.Fatalf("readHostsFile returned %d lines, want 3: %v", len(lines), lines)
	}
	if lines[0] != "10.10.10.1" || lines[2] != "10.10.10.3" {
		t.Errorf("readHostsFile = %v, unexpected content", lines)
	}
}

func TestReadHostsFileMissing(t *testing.T) {
	lines := readHostsFile("/nonexistent/path/hosts")
	if lines != nil {
		t.Errorf("expected nil for missing file, got %v", lines)
	}
}

func loadTmuxTestTemplate(t *testing.T, name string) *EngagementTemplate {
	t.Helper()
	tmpl, err := loadTemplate(name)
	if err != nil {
		t.Fatalf("loadTemplate(%q): %v", name, err)
	}
	return tmpl
}

func TestBuildTmuxEnvWorkMode(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "hosts"), []byte("10.10.10.1\n10.10.10.2\n"), 0644)
	os.WriteFile(filepath.Join(dir, "http_hosts"), []byte("http://example.com\n"), 0644)

	cfg := &Config{
		ObsidianBin:         "obsidian",
		ObsidianSyncedVault: "~/Notes",
		SSHHosts:            map[string]string{"work": "lhack"},
	}
	tmpl := loadTmuxTestTemplate(t, "work")

	env := buildTmuxEnv(cfg, tmpl, "acmecorp_1", dir, "", "")

	find := func(key string) string {
		prefix := key + "="
		for _, e := range env {
			if strings.HasPrefix(e, prefix) {
				return e[len(prefix):]
			}
		}
		return ""
	}

	if find("ENGAGE_NAME") != "acmecorp_1" {
		t.Errorf("ENGAGE_NAME = %q", find("ENGAGE_NAME"))
	}
	if find("ENGAGE_MODE") != "work" {
		t.Errorf("ENGAGE_MODE = %q", find("ENGAGE_MODE"))
	}
	if find("ENGAGE_DIR") != dir {
		t.Errorf("ENGAGE_DIR = %q", find("ENGAGE_DIR"))
	}
	if find("ENGAGE_NOTES_DIR") != filepath.Join(dir, "notes") {
		t.Errorf("ENGAGE_NOTES_DIR = %q, want <engDir>/notes", find("ENGAGE_NOTES_DIR"))
	}
	wantObsidianURL := "obsidian://open?path=" + url.QueryEscape(filepath.Join(dir, "notes", "general_notes.md"))
	if find("ENGAGE_OBSIDIAN_URL") != wantObsidianURL {
		t.Errorf("ENGAGE_OBSIDIAN_URL = %q, want %q", find("ENGAGE_OBSIDIAN_URL"), wantObsidianURL)
	}
	if find("TARGET_1") != "10.10.10.1" {
		t.Errorf("TARGET_1 = %q", find("TARGET_1"))
	}
	if find("TARGET_2") != "10.10.10.2" {
		t.Errorf("TARGET_2 = %q", find("TARGET_2"))
	}
	if find("TARGETS") != "10.10.10.1 10.10.10.2" {
		t.Errorf("TARGETS = %q", find("TARGETS"))
	}
	if find("HTTP_TARGETS") != "http://example.com" {
		t.Errorf("HTTP_TARGETS = %q", find("HTTP_TARGETS"))
	}
	// SSH host from config default (no CLI override supplied).
	if find("ENGAGE_SSH_HOST") != "lhack" {
		t.Errorf("ENGAGE_SSH_HOST = %q, want lhack", find("ENGAGE_SSH_HOST"))
	}
}

func TestBuildTmuxEnvSSHHostCLIOverride(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{
		ObsidianBin:         "obsidian",
		ObsidianSyncedVault: "~/Notes",
		SSHHosts:            map[string]string{"work": "default-vps"},
	}
	tmpl := loadTmuxTestTemplate(t, "work")

	env := buildTmuxEnv(cfg, tmpl, "test", dir, "override-vps", "")

	for _, e := range env {
		if strings.HasPrefix(e, "ENGAGE_SSH_HOST=") {
			if e != "ENGAGE_SSH_HOST=override-vps" {
				t.Errorf("ENGAGE_SSH_HOST = %q, want override-vps (CLI should win)", e)
			}
			return
		}
	}
	t.Error("ENGAGE_SSH_HOST not set")
}

func TestBuildTmuxEnvNoHosts(t *testing.T) {
	dir := t.TempDir() // no host files written
	cfg := &Config{ObsidianBin: "obsidian", ObsidianSyncedVault: "~/Notes"}
	tmpl := loadTmuxTestTemplate(t, "THM")

	env := buildTmuxEnv(cfg, tmpl, "Lab1", dir, "", "")

	// Core vars must always be present.
	required := []string{
		"ENGAGE_NAME", "ENGAGE_MODE", "ENGAGE_DIR",
		"ENGAGE_HOST_FILE", "ENGAGE_NMAP_DIR", "ENGAGE_BURP_DIR",
		"ENGAGE_NOTES_DIR", "ENGAGE_OBSIDIAN_BIN",
	}
	for _, key := range required {
		found := false
		for _, e := range env {
			if strings.HasPrefix(e, key+"=") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected env var %q to be set", key)
		}
	}

	// Target vars must not appear when hosts files are absent.
	for _, key := range []string{"TARGET_1", "TARGETS", "HTTP_TARGETS"} {
		for _, e := range env {
			if strings.HasPrefix(e, key+"=") {
				t.Errorf("unexpected env var %q when no hosts exist", key)
			}
		}
	}
}

func TestBuildTmuxEnvSyncedVaultForNonWork(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{ObsidianBin: "obsidian", ObsidianSyncedVault: "/home/user/Notes"}

	for _, name := range []string{"HTB", "THM", "exam", "swigger"} {
		t.Run(name, func(t *testing.T) {
			tmpl := loadTmuxTestTemplate(t, name)
			env := buildTmuxEnv(cfg, tmpl, "test", dir, "", "")
			for _, e := range env {
				if strings.HasPrefix(e, "ENGAGE_NOTES_DIR=") {
					got := e[len("ENGAGE_NOTES_DIR="):]
					if got != "/home/user/Notes" {
						t.Errorf("mode %s: ENGAGE_NOTES_DIR = %q, want /home/user/Notes", name, got)
					}
					return
				}
			}
			t.Errorf("mode %s: ENGAGE_NOTES_DIR not set", name)
		})
	}
}

func TestBuildTmuxEnvAWSProfile(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{ObsidianBin: "obsidian", ObsidianSyncedVault: "~/Notes"}
	tmpl := loadTmuxTestTemplate(t, "cloud")

	env := buildTmuxEnv(cfg, tmpl, "cloud-audit", dir, "", "client-a")

	find := func(key string) string {
		prefix := key + "="
		for _, e := range env {
			if strings.HasPrefix(e, prefix) {
				return e[len(prefix):]
			}
		}
		return ""
	}

	if find("AWS_PROFILE") != "client-a" {
		t.Errorf("AWS_PROFILE = %q, want client-a", find("AWS_PROFILE"))
	}
	if find("ENGAGE_AWS_PROFILE") != "client-a" {
		t.Errorf("ENGAGE_AWS_PROFILE = %q, want client-a", find("ENGAGE_AWS_PROFILE"))
	}
}

func TestDefaultLayoutsExistForAllModes(t *testing.T) {
	modes := []engagementMode{ModeWork, ModeInfra, ModeCloud, ModeHTB, ModeTHM, ModeExam, ModeSwigger}
	for _, mode := range modes {
		t.Run(string(mode), func(t *testing.T) {
			layout, ok := defaultTmuxLayouts[string(mode)]
			if !ok || len(layout) == 0 {
				t.Errorf("no default layout for mode %q", mode)
			}
		})
	}
}

func TestGetLayoutPrefersConfig(t *testing.T) {
	custom := []TmuxWindowConfig{{Name: "custom"}}
	cfg := &Config{
		TmuxLayouts: map[string][]TmuxWindowConfig{
			"work": custom,
		},
	}
	tmpl := loadTmuxTestTemplate(t, "work")
	got := getLayout(cfg, tmpl)
	if len(got) != 1 || got[0].Name != "custom" {
		t.Errorf("getLayout did not prefer config-defined layout")
	}
}

func TestGetLayoutFallsBackToDefault(t *testing.T) {
	cfg := &Config{} // no custom layouts
	tmpl := loadTmuxTestTemplate(t, "HTB")
	got := getLayout(cfg, tmpl)
	if len(got) == 0 {
		t.Error("getLayout returned empty layout for HTB with no config override")
	}
}

func TestGetLayoutPrefersTemplate(t *testing.T) {
	cfg := &Config{} // no config overrides
	// Cloud template has no tmux_layout in JSON, so it falls back to defaultTmuxLayouts.
	// Verify the fallback path works for cloud.
	tmpl := loadTmuxTestTemplate(t, "cloud")
	got := getLayout(cfg, tmpl)
	if len(got) == 0 {
		t.Error("getLayout returned empty layout for cloud")
	}
}
