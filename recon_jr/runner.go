package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// interrupted is set to true when SIGINT/SIGTERM is received, causing the runner
// to stop launching new tools after the current one finishes.
var interrupted atomic.Bool

// ToolResult holds the outcome of a single tool invocation.
type ToolResult struct {
	Name       string
	ExitCode   int
	Duration   time.Duration
	OutputFile string
	Stdout     string
	Stderr     string
	Skipped    bool
	SkipReason string
	Err        error
}

// Runner executes recon tools in sequence, managing timeouts, inter-tool delays,
// skip logic, and output capture.
type Runner struct {
	cfg       *Config
	engDir    string
	meta      *ReconMeta
	mu        sync.Mutex
	currentTool string
}

func newRunner(cfg *Config, engDir string, meta *ReconMeta) *Runner {
	return &Runner{cfg: cfg, engDir: engDir, meta: meta}
}

// setCurrentTool records which tool is currently running for interrupt state.
func (r *Runner) setCurrentTool(name string) {
	r.mu.Lock()
	r.currentTool = name
	r.mu.Unlock()
}

// CurrentTool returns the name of the currently executing tool.
func (r *Runner) CurrentTool() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.currentTool
}

// ShouldSkip returns (true, reason) if the tool should not run. Checks the
// skip_tools config list and verifies the binary exists in PATH.
func (r *Runner) ShouldSkip(toolName, binary string) (bool, string) {
	for _, skip := range r.cfg.SkipTools {
		if strings.EqualFold(skip, toolName) {
			return true, "listed in skip_tools"
		}
	}
	if _, err := exec.LookPath(binary); err != nil {
		return true, fmt.Sprintf("binary %q not found in PATH", binary)
	}
	return false, ""
}

// Run executes binary with args using cfg.ToolsTimeoutSecs as the deadline.
func (r *Runner) Run(name, binary string, args []string, outputFile string) *ToolResult {
	return r.runWithTimeout(name, binary, args, outputFile,
		time.Duration(r.cfg.ToolsTimeoutSecs)*time.Second)
}

// RunWithOutput runs the tool and returns stdout as a string.
func (r *Runner) RunWithOutput(name, binary string, args []string) (string, *ToolResult) {
	res := r.Run(name, binary, args, "")
	return res.Stdout, res
}

// RunLong executes like Run but uses cfg.FuzzTimeoutSecs. Thread-safe — does
// not mutate cfg, so concurrent goroutines may call RunLong simultaneously.
func (r *Runner) RunLong(name, binary string, args []string, outputFile string) *ToolResult {
	return r.runWithTimeout(name, binary, args, outputFile,
		time.Duration(r.cfg.FuzzTimeoutSecs)*time.Second)
}

// runWithTimeout is the core execution method. All public Run* methods delegate here.
// It is safe to call from multiple goroutines — each invocation is independent.
func (r *Runner) runWithTimeout(name, binary string, args []string, outputFile string, timeout time.Duration) *ToolResult {
	result := &ToolResult{Name: name, OutputFile: outputFile}

	if interrupted.Load() {
		result.Skipped = true
		result.SkipReason = "interrupted"
		return result
	}

	if skip, reason := r.ShouldSkip(name, binary); skip {
		result.Skipped = true
		result.SkipReason = reason
		r.mu.Lock()
		recordToolSkipped(r.meta, name)
		r.mu.Unlock()
		logInfo("  [skip] %s — %s", name, reason)
		return result
	}

	logInfo("  [run]  %s %s", binary, strings.Join(args, " "))

	if dryRun {
		result.Skipped = true
		result.SkipReason = "dry-run"
		return result
	}

	r.setCurrentTool(name)
	defer r.setCurrentTool("")

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, binary, args...)

	if r.cfg.ProxyURL != "" {
		cmd.Env = append(os.Environ(),
			"HTTP_PROXY="+r.cfg.ProxyURL,
			"HTTPS_PROXY="+r.cfg.ProxyURL,
			"http_proxy="+r.cfg.ProxyURL,
			"https_proxy="+r.cfg.ProxyURL,
		)
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	if outputFile != "" {
		if err := ensureDir(filepath.Dir(outputFile)); err != nil {
			result.Err = fmt.Errorf("creating output directory: %w", err)
			return result
		}
		f, err := os.Create(outputFile)
		if err != nil {
			result.Err = fmt.Errorf("creating output file %s: %w", outputFile, err)
			return result
		}
		defer f.Close()
		cmd.Stdout = &teeWriter{w1: f, w2: &stdoutBuf}
	} else {
		cmd.Stdout = &stdoutBuf
	}
	cmd.Stderr = &stderrBuf

	start := time.Now()

	// Heartbeat: log progress every minute for tools that take longer than 2 minutes.
	heartbeatDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatDone:
				return
			case <-ticker.C:
				elapsed := time.Since(start).Round(time.Second)
				if elapsed >= 2*time.Minute {
					logInfo("  [wait] %s still running (%s elapsed)", name, elapsed)
				}
			}
		}
	}()

	err := cmd.Run()
	close(heartbeatDone)

	result.Duration = time.Since(start)
	result.Stdout = stdoutBuf.String()
	result.Stderr = stderrBuf.String()

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			result.Err = fmt.Errorf("timed out after %s", timeout)
			logWarn("%s timed out after %s", name, timeout)
		} else if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
			logDebug("%s exited with code %d", name, result.ExitCode)
		} else {
			result.Err = err
			logWarn("%s failed: %v", name, err)
		}
	}

	// Record the tool as run whenever it executed without a fatal error (timeout/exec
	// failure). Non-zero exit codes are tool-specific (e.g. trufflehog exits 1 when
	// nothing is found, gitleaks exits 1 when secrets are found) and should not
	// prevent the tool from appearing in tools_run.
	if result.Err == nil {
		r.mu.Lock()
		recordToolRun(r.meta, name)
		r.mu.Unlock()
		logDebug("%s completed in %s", name, result.Duration.Round(time.Second))
	}

	return result
}

// Delay sleeps for cfg.ToolDelaySecs between tool invocations.
// Skipped if interrupted or dryRun.
func (r *Runner) Delay() {
	if dryRun || interrupted.Load() || r.cfg.ToolDelaySecs == 0 {
		return
	}
	logDebug("inter-tool delay: %ds", r.cfg.ToolDelaySecs)
	time.Sleep(time.Duration(r.cfg.ToolDelaySecs) * time.Second)
}

// teeWriter writes to two writers simultaneously.
type teeWriter struct {
	w1, w2 interface{ Write([]byte) (int, error) }
}

func (t *teeWriter) Write(p []byte) (int, error) {
	n, err := t.w1.Write(p)
	if err != nil {
		return n, err
	}
	return t.w2.Write(p)
}

// CheckDeps verifies that all required binaries are present in PATH.
// Tools in skipList and intrusive tools (when allowIntrusive is false) are excluded.
// Returns a list of missing binaries.
func CheckDeps(toolBinaries map[string]string, skipList []string, allowIntrusive bool, intrusiveTools map[string]bool) []string {
	skipSet := make(map[string]struct{}, len(skipList))
	for _, s := range skipList {
		skipSet[strings.ToLower(s)] = struct{}{}
	}

	var missing []string
	for tool, binary := range toolBinaries {
		if _, ok := skipSet[strings.ToLower(tool)]; ok {
			continue
		}
		if !allowIntrusive && intrusiveTools[tool] {
			continue
		}
		if _, err := exec.LookPath(binary); err != nil {
			missing = append(missing, fmt.Sprintf("%s (%s)", tool, binary))
		}
	}
	return missing
}
