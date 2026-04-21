package main

import (
	"os"
	"path/filepath"
	"testing"
)

func makeTestRunner(t *testing.T, skipTools []string) (*Runner, *ReconMeta, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := &Config{
		ToolsTimeoutSecs: 10,
		ToolDelaySecs:    0,
		SkipTools:        skipTools,
	}
	meta := &ReconMeta{PhaseStatus: make(map[string]PhaseStatus)}
	return newRunner(cfg, dir, meta), meta, dir
}

func TestRunnerShouldSkipConfig(t *testing.T) {
	r, _, _ := makeTestRunner(t, []string{"nikto", "arjun"})

	skip, reason := r.ShouldSkip("nikto", "nikto")
	if !skip {
		t.Error("nikto should be skipped (in skip_tools)")
	}
	if reason == "" {
		t.Error("reason should not be empty")
	}
}

func TestRunnerShouldSkipMissingBinary(t *testing.T) {
	r, _, _ := makeTestRunner(t, nil)

	skip, reason := r.ShouldSkip("nonexistent-tool", "nonexistent-tool-binary-xyz")
	if !skip {
		t.Error("nonexistent binary should be skipped")
	}
	if reason == "" {
		t.Error("reason should not be empty")
	}
}

func TestRunnerRunEcho(t *testing.T) {
	r, meta, dir := makeTestRunner(t, nil)

	outFile := filepath.Join(dir, "echo_output.txt")
	result := r.Run("echo-test", "echo", []string{"hello", "world"}, outFile)

	if result.Skipped {
		t.Fatalf("echo should not be skipped: %s", result.SkipReason)
	}
	if result.Err != nil {
		t.Fatalf("echo failed: %v", result.Err)
	}
	if result.ExitCode != 0 {
		t.Errorf("echo exit code: %d", result.ExitCode)
	}

	content, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("reading output file: %v", err)
	}
	if string(content) != "hello world\n" {
		t.Errorf("output file content: %q", string(content))
	}

	// Tool should be recorded
	found := false
	for _, tool := range meta.ToolsRun {
		if tool == "echo-test" {
			found = true
		}
	}
	if !found {
		t.Error("echo-test should be in ToolsRun")
	}
}

func TestRunnerRunWithOutput(t *testing.T) {
	r, _, _ := makeTestRunner(t, nil)

	stdout, result := r.RunWithOutput("echo-test", "echo", []string{"test-output"})
	if result.Skipped {
		t.Fatalf("echo skipped: %s", result.SkipReason)
	}
	if stdout != "test-output\n" {
		t.Errorf("stdout: got %q", stdout)
	}
}

func TestRunnerDryRun(t *testing.T) {
	dryRun = true
	defer func() { dryRun = false }()

	r, _, _ := makeTestRunner(t, nil)
	result := r.Run("echo-test", "echo", []string{"hello"}, "")
	if !result.Skipped {
		t.Error("dry-run should skip tool execution")
	}
	if result.SkipReason != "dry-run" {
		t.Errorf("dry-run skip reason: %q", result.SkipReason)
	}
}

func TestRunnerInterrupted(t *testing.T) {
	interrupted.Store(true)
	defer interrupted.Store(false)

	r, _, _ := makeTestRunner(t, nil)
	result := r.Run("echo-test", "echo", []string{"hello"}, "")
	if !result.Skipped {
		t.Error("interrupted should skip tool execution")
	}
	if result.SkipReason != "interrupted" {
		t.Errorf("interrupted skip reason: %q", result.SkipReason)
	}
}

func TestRunnerTimeout(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{
		ToolsTimeoutSecs: 1, // 1 second timeout
		ToolDelaySecs:    0,
	}
	meta := &ReconMeta{PhaseStatus: make(map[string]PhaseStatus)}
	r := newRunner(cfg, dir, meta)

	// sleep 5 should timeout
	result := r.Run("sleep-test", "sleep", []string{"5"}, "")
	if result.Skipped {
		t.Skip("sleep not available — skipping timeout test")
	}
	if result.Err == nil {
		t.Error("expected timeout error")
	}
}

func TestCheckDeps(t *testing.T) {
	// echo and true should always be available
	binaries := map[string]string{
		"echo": "echo",
		"true": "true",
		"nonexistent-xyz": "nonexistent-xyz",
	}
	missing := CheckDeps(binaries, nil, true, nil)
	if len(missing) != 1 {
		t.Errorf("expected 1 missing binary, got %d: %v", len(missing), missing)
	}
}

func TestCheckDepsSkipList(t *testing.T) {
	binaries := map[string]string{
		"nonexistent-xyz": "nonexistent-xyz",
	}
	// nonexistent should be skipped via skip list
	missing := CheckDeps(binaries, []string{"nonexistent-xyz"}, true, nil)
	if len(missing) != 0 {
		t.Errorf("expected 0 missing (all skipped), got %d: %v", len(missing), missing)
	}
}

func TestProxyFlagForTool(t *testing.T) {
	tests := []struct {
		tool    string
		wantLen int
		wantArg string
	}{
		{"curl", 2, "-x"},
		{"nuclei", 2, "-proxy"},
		{"feroxbuster", 2, "--proxy"},
		{"httpx", 2, "-http-proxy"},
		{"katana", 2, "-proxy"},
		{"nikto", 2, "-useproxy"},
		{"whatweb", 2, "--proxy"},
		{"subfinder", 2, "-proxy"},
		{"wpscan", 2, "--proxy"},
		{"gowitness", 2, "--proxy"},
		{"dig", 0, ""},
		{"nmap", 0, ""},
	}
	proxy := "http://127.0.0.1:8080"
	for _, tt := range tests {
		flags := proxyFlagForTool(tt.tool, proxy)
		if len(flags) != tt.wantLen {
			t.Errorf("proxyFlagForTool(%q): got %d flags, want %d", tt.tool, len(flags), tt.wantLen)
			continue
		}
		if tt.wantLen > 0 && flags[0] != tt.wantArg {
			t.Errorf("proxyFlagForTool(%q): first flag = %q, want %q", tt.tool, flags[0], tt.wantArg)
		}
		if tt.wantLen > 0 && flags[1] != proxy {
			t.Errorf("proxyFlagForTool(%q): proxy value = %q, want %q", tt.tool, flags[1], proxy)
		}
	}

	// Empty proxy URL should always return nil
	if flags := proxyFlagForTool("curl", ""); flags != nil {
		t.Errorf("empty proxy should return nil, got %v", flags)
	}
}

func TestRunnerProxyEnvInjection(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{
		ToolsTimeoutSecs: 10,
		ToolDelaySecs:    0,
		ProxyURL:         "http://127.0.0.1:9999",
	}
	meta := &ReconMeta{PhaseStatus: make(map[string]PhaseStatus)}
	r := newRunner(cfg, dir, meta)

	// Use printenv to check that HTTP_PROXY is injected into subprocess env
	stdout, result := r.RunWithOutput("env-test", "sh", []string{"-c", "echo $HTTP_PROXY"})
	if result.Skipped {
		t.Fatalf("sh skipped: %s", result.SkipReason)
	}
	if result.Err != nil {
		t.Fatalf("sh failed: %v", result.Err)
	}
	expected := "http://127.0.0.1:9999\n"
	if stdout != expected {
		t.Errorf("HTTP_PROXY in subprocess: got %q, want %q", stdout, expected)
	}
}

func TestCheckDepsIntrusiveSkipped(t *testing.T) {
	binaries := map[string]string{
		"nonexistent-intrusive": "nonexistent-intrusive",
	}
	intrusives := map[string]bool{"nonexistent-intrusive": true}

	// Without -allow-intrusive, intrusive tools are not checked
	missing := CheckDeps(binaries, nil, false, intrusives)
	if len(missing) != 0 {
		t.Errorf("intrusive tool should not be checked without -allow-intrusive: got %v", missing)
	}

	// With -allow-intrusive, it should be checked
	missing = CheckDeps(binaries, nil, true, intrusives)
	if len(missing) != 1 {
		t.Errorf("intrusive tool should be checked with -allow-intrusive: got %v", missing)
	}
}
