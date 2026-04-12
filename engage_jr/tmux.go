package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// intPtr is a helper for taking the address of an int literal in layout configs.
func intPtr(n int) *int { return &n }

// notesCommand is the shell command used in the notes pane/window.
// Calls the Obsidian binary directly (via $ENGAGE_OBSIDIAN_BIN) so that:
//   - When Obsidian is not running it starts a new instance, reads obsidian.json,
//     and opens the vault by name.
//   - When Obsidian is already running, Electron's single-instance lock forwards
//     the URI to the live process.
// xdg-open is intentionally avoided: it can only dispatch to an already-running
// instance and will silently do nothing when Obsidian is not open.
// The vault name equals the engagement name (basename of ENGAGE_NOTES_DIR),
// ensuring each engagement's vault has a unique, unambiguous name.
const notesCommand = `VAULT_NAME=$(basename "$ENGAGE_NOTES_DIR"); nohup "$ENGAGE_OBSIDIAN_BIN" "obsidian://open?vault=$VAULT_NAME" >/dev/null 2>&1 & cd "$ENGAGE_NOTES_DIR" 2>/dev/null`

// defaultTmuxLayouts defines the built-in per-mode tmux window/pane layouts.
// Users can override any mode's layout via "tmux_layouts" in config.json.
//
// Pane layout for all modes:
//
//	Work — window "main":
//	  pane 0 (left, 50%): main shell
//	  pane 1 (top-right, 50%): recon_jr
//	  pane 2 (bottom-right, 50%): VPS SSH ($ENGAGE_SSH_HOST)
//	  window "notes": cd to notes dir + open Obsidian vault
//
//	HTB / THM — window "attack":
//	  pane 0 (top): main shell
//	  pane 1 (bottom): enumeration
//	  window "notes": cd to synced vault + open Obsidian
//
//	Exam — window "shell":
//	  pane 0 (top): main shell
//	  pane 1 (bottom): secondary shell
//	  window "notes": cd to synced vault + open Obsidian
//
//	PortSwigger — single window "main":
//	  pane 0 (top): main shell
//	  pane 1 (bottom): cd to synced vault + open Obsidian
var defaultTmuxLayouts = map[string][]TmuxWindowConfig{
	string(ModeWork): {
		{
			Name:      "main",
			FocusPane: 0,
			Panes: []TmuxPaneConfig{
				{},
				{SplitDirection: "h", Percent: 50},
				{SplitDirection: "v", SplitFrom: intPtr(1), Percent: 50,
					Command: `[ -n "$ENGAGE_SSH_HOST" ] && ssh $ENGAGE_SSH_HOST`},
			},
		},
		{
			Name:  "notes",
			Panes: []TmuxPaneConfig{{Command: notesCommand}},
		},
	},
	string(ModeHTB): {
		{
			Name:      "attack",
			FocusPane: 0,
			Panes: []TmuxPaneConfig{
				{},
				{SplitDirection: "v", Percent: 40},
			},
		},
		{
			Name:  "notes",
			Panes: []TmuxPaneConfig{{Command: notesCommand}},
		},
	},
	string(ModeTHM): {
		{
			Name:      "attack",
			FocusPane: 0,
			Panes: []TmuxPaneConfig{
				{},
				{SplitDirection: "v", Percent: 40},
			},
		},
		{
			Name:  "notes",
			Panes: []TmuxPaneConfig{{Command: notesCommand}},
		},
	},
	string(ModeExam): {
		{
			Name:      "shell",
			FocusPane: 0,
			Panes: []TmuxPaneConfig{
				{},
				{SplitDirection: "v", Percent: 40},
			},
		},
		{
			Name:  "notes",
			Panes: []TmuxPaneConfig{{Command: notesCommand}},
		},
	},
	string(ModeSwigger): {
		{
			Name:      "main",
			FocusPane: 0,
			Panes: []TmuxPaneConfig{
				{},
				{SplitDirection: "v", Percent: 35, Command: notesCommand},
			},
		},
	},
}

// tmuxAvailable returns true if tmux is found in PATH.
func tmuxAvailable() bool {
	_, err := exec.LookPath("tmux")
	return err == nil
}

// tmuxSessionName returns the tmux session name for an engagement.
// If cfg.TmuxPrefix is set the name is "<prefix>_<name>"; otherwise it is
// the bare engagement name (e.g. "acmecorp_inc_1_5").
func tmuxSessionName(cfg *Config, name string) string {
	if cfg.TmuxPrefix != "" {
		return cfg.TmuxPrefix + "_" + name
	}
	return name
}

// tmuxSessionExists reports whether a tmux session with the given name is running.
func tmuxSessionExists(name string) bool {
	return exec.Command("tmux", "has-session", "-t", name).Run() == nil
}

// readHostsFile reads non-blank, non-comment lines from path.
// Returns nil if the file does not exist.
func readHostsFile(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
			lines = append(lines, l)
		}
	}
	return lines
}

// expandHome expands a leading ~/ to the user's home directory.
func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

// buildTmuxEnv constructs the KEY=VALUE pairs to inject into the tmux session.
//
// Variables set:
//
//	ENGAGE_NAME, ENGAGE_MODE, ENGAGE_DIR
//	ENGAGE_HOST_FILE, ENGAGE_NMAP_DIR, ENGAGE_BURP_DIR
//	ENGAGE_NOTES_DIR   — <engDir>/notes for work, cfg.ObsidianSyncedVault for others
//	ENGAGE_OBSIDIAN_BIN
//	ENGAGE_SSH_HOST    — sshHost arg takes precedence over cfg.SSHHosts[mode]
//	TARGET_1…N, TARGETS, HTTP_TARGETS  — populated from on-disk host files
func buildTmuxEnv(cfg *Config, mode engagementMode, name, engDir, sshHost string) []string {
	var env []string
	set := func(k, v string) { env = append(env, k+"="+v) }

	set("ENGAGE_NAME", name)
	set("ENGAGE_MODE", string(mode))
	set("ENGAGE_DIR", engDir)
	set("ENGAGE_HOST_FILE", filepath.Join(engDir, "hosts"))
	set("ENGAGE_NMAP_DIR", filepath.Join(engDir, "nmap"))
	set("ENGAGE_BURP_DIR", filepath.Join(engDir, "burp"))

	// Notes directory: isolated engagement vault for work, synced vault for others.
	// Work vaults live at <engDir>/notes/<name>/ so the vault name (its basename)
	// equals the engagement name — unique across all engagements.
	if mode == ModeWork {
		set("ENGAGE_NOTES_DIR", filepath.Join(engDir, "notes", name))
	} else {
		set("ENGAGE_NOTES_DIR", expandHome(cfg.ObsidianSyncedVault))
	}

	set("ENGAGE_OBSIDIAN_BIN", cfg.ObsidianBin)

	// SSH host: CLI flag takes precedence over per-mode config default.
	host := sshHost
	if host == "" && cfg.SSHHosts != nil {
		host = cfg.SSHHosts[string(mode)]
	}
	if host != "" {
		set("ENGAGE_SSH_HOST", host)
	}

	// Individual targets from the hosts file written by processHostFile.
	hosts := readHostsFile(filepath.Join(engDir, "hosts"))
	if len(hosts) > 0 {
		set("TARGETS", strings.Join(hosts, " "))
		for i, h := range hosts {
			set(fmt.Sprintf("TARGET_%d", i+1), h)
		}
	}

	httpHosts := readHostsFile(filepath.Join(engDir, "http_hosts"))
	if len(httpHosts) > 0 {
		set("HTTP_TARGETS", strings.Join(httpHosts, " "))
	}

	return env
}

// applyTmuxEnv sets each KEY=VALUE pair as a tmux environment variable in the
// session using `tmux set-environment`. New windows and panes inherit these.
func applyTmuxEnv(session string, envVars []string) {
	for _, pair := range envVars {
		idx := strings.IndexByte(pair, '=')
		if idx < 0 {
			continue
		}
		if err := exec.Command("tmux", "set-environment", "-t", session,
			pair[:idx], pair[idx+1:]).Run(); err != nil {
			logDebug("set-environment %s failed: %v", pair[:idx], err)
		}
	}
}

// getLayout returns the window layout for the given mode, preferring any
// user-defined layout from config over the built-in default.
func getLayout(cfg *Config, mode engagementMode) []TmuxWindowConfig {
	if cfg.TmuxLayouts != nil {
		if layout, ok := cfg.TmuxLayouts[string(mode)]; ok {
			return layout
		}
	}
	return defaultTmuxLayouts[string(mode)]
}

// applyLayout creates windows and panes according to the layout definition.
// Environment variables set via applyTmuxEnv are inherited by new panes.
// Each pane's unique tmux ID (e.g. %3) is captured on creation so that
// send-keys and select-pane targets are independent of pane-base-index.
func applyLayout(session, engDir string, windows []TmuxWindowConfig) {
	for winIdx, win := range windows {
		var windowTarget string
		if winIdx == 0 {
			exec.Command("tmux", "rename-window", "-t", session+":0", win.Name).Run()
			windowTarget = session + ":" + win.Name
		} else {
			if err := exec.Command("tmux", "new-window", "-t", session,
				"-n", win.Name, "-c", engDir).Run(); err != nil {
				logWarn("could not create tmux window %q: %v", win.Name, err)
				continue
			}
			windowTarget = session + ":" + win.Name
		}

		// Collect unique pane IDs (%N) as each pane is created so targeting
		// is not affected by the user's pane-base-index option.
		paneIDs := make([]string, 0, len(win.Panes))
		out, err := exec.Command("tmux", "display-message", "-t", windowTarget, "-p", "#{pane_id}").Output()
		if err != nil {
			logWarn("could not get initial pane ID in window %q: %v", win.Name, err)
		}
		paneIDs = append(paneIDs, strings.TrimSpace(string(out)))

		for paneIdx, pane := range win.Panes {
			if paneIdx == 0 {
				if pane.Command != "" && paneIDs[0] != "" {
					exec.Command("tmux", "send-keys", "-t", paneIDs[0], pane.Command, "Enter").Run()
				}
				continue
			}

			splitFromIdx := paneIdx - 1
			if pane.SplitFrom != nil {
				splitFromIdx = *pane.SplitFrom
			}
			splitTarget := fmt.Sprintf("%s.%d", windowTarget, splitFromIdx) // numeric fallback
			if splitFromIdx < len(paneIDs) && paneIDs[splitFromIdx] != "" {
				splitTarget = paneIDs[splitFromIdx]
			}

			args := []string{
				"split-window",
				"-t", splitTarget,
				"-c", engDir,
				"-P", "-F", "#{pane_id}",
			}
			if pane.SplitDirection == "v" {
				args = append(args, "-v")
			} else {
				args = append(args, "-h") // default to vertical (top/bottom)
			}
			if pane.Percent > 0 {
				args = append(args, "-p", strconv.Itoa(pane.Percent))
			}

			out, err := exec.Command("tmux", args...).Output()
			if err != nil {
				logWarn("could not create pane %d in window %q: %v", paneIdx, win.Name, err)
				paneIDs = append(paneIDs, "") // keep slice aligned with config indices
				continue
			}
			newID := strings.TrimSpace(string(out))
			paneIDs = append(paneIDs, newID)

			if pane.Command != "" && newID != "" {
				exec.Command("tmux", "send-keys", "-t", newID, pane.Command, "Enter").Run()
			}
		}

		if win.FocusPane < len(paneIDs) && paneIDs[win.FocusPane] != "" {
			exec.Command("tmux", "select-pane", "-t", paneIDs[win.FocusPane]).Run()
		}
	}
}

// attachSession attaches the current terminal to the named tmux session,
// forwarding stdin/stdout/stderr. When already inside a tmux session it uses
// switch-client instead of attach-session, which doesn't work nested.
func attachSession(session string) {
	var cmd *exec.Cmd
	if os.Getenv("TMUX") != "" {
		cmd = exec.Command("tmux", "switch-client", "-t", session)
	} else {
		cmd = exec.Command("tmux", "attach-session", "-t", session)
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "tmux attach exited: %v\n", err)
	}
}

// tmuxServerCanAccess tests whether the running tmux server's shell environment
// can read dir. It uses tmux run-shell -b to execute a test inside the server's
// own process context (which inherits the server's credentials/groups), then
// synchronises via tmux wait-for. Returns true if no server is running (a new
// session will start a fresh server with current credentials), or if the check
// cannot be performed. Only returns false when the check definitively fails.
func tmuxServerCanAccess(dir string) bool {
	// No running server — new-session will start one with current credentials.
	if exec.Command("tmux", "list-sessions").Run() != nil {
		return true
	}

	tmp, err := os.CreateTemp("", "engage_access_*")
	if err != nil {
		return true
	}
	tmp.Close()
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	channel := fmt.Sprintf("engage_access_%d", os.Getpid())
	checkCmd := fmt.Sprintf(`[ -r '%s' ] && printf ok > '%s'; tmux wait-for -S '%s'`,
		dir, tmpPath, channel)
	if exec.Command("tmux", "run-shell", "-b", checkCmd).Run() != nil {
		return true
	}

	done := make(chan error, 1)
	go func() { done <- exec.Command("tmux", "wait-for", channel).Run() }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		return true
	}

	data, _ := os.ReadFile(tmpPath)
	return strings.TrimSpace(string(data)) == "ok"
}

// launchTmux attaches to or creates the tmux session for the named engagement.
//
// On first run: creates the session, injects engagement env vars (including
// ENGAGE_SSH_HOST from sshHost or cfg.SSHHosts), applies the window/pane layout,
// then attaches.
//
// On subsequent runs (-open): attaches directly. If sshHost is non-empty the
// ENGAGE_SSH_HOST variable in the existing session is updated before attaching.
//
// Falls back to a plain shell if tmux is not in PATH.
func launchTmux(cfg *Config, mode engagementMode, name, engDir, sshHost string) {
	if !tmuxAvailable() {
		logWarn("tmux not found in PATH — falling back to plain shell")
		launchPlainShell(engDir)
		return
	}

	session := tmuxSessionName(cfg, name)

	if !tmuxSessionExists(session) {
		// Pre-flight: verify the tmux server can access the engagement directory.
		// If it can't, the server was likely started before the vboxsf group was
		// active. All panes would silently lack access to /Share.
		if !tmuxServerCanAccess(engDir) {
			logWarn("tmux server cannot access %s", engDir)
			logWarn("server was likely started before the vboxsf group was active")
			logWarn("fix: tmux kill-server, then rerun engage_jr")
			launchPlainShell(engDir)
			return
		}

		// Ensure the notes directory and Obsidian vault skeleton exist for work.
		if mode == ModeWork {
			notesDir := filepath.Join(engDir, "notes", name, ".obsidian")
			if err := os.MkdirAll(notesDir, 0755); err != nil {
				logWarn("could not create notes vault: %v", err)
			}
		}

		envVars := buildTmuxEnv(cfg, mode, name, engDir, sshHost)

		// Pass env vars to new-session so the initial pane's shell inherits them.
		args := []string{"new-session", "-d", "-s", session, "-c", engDir}
		for _, e := range envVars {
			args = append(args, "-e", e)
		}
		if out, err := exec.Command("tmux", args...).CombinedOutput(); err != nil {
			logWarn("could not create tmux session: %v (%s) — falling back to plain shell",
				err, strings.TrimSpace(string(out)))
			launchPlainShell(engDir)
			return
		}

		// Also update the session environment so subsequently created panes inherit.
		applyTmuxEnv(session, envVars)

		// Register the notes vault with Obsidian before the notes pane opens it.
		// Work vaults live at <engDir>/notes/<name>/ so the vault name is unique.
		notesDir := filepath.Join(engDir, "notes", name)
		if mode != ModeWork {
			notesDir = expandHome(cfg.ObsidianSyncedVault)
		}
		if err := ensureObsidianVault(notesDir); err != nil {
			logWarn("could not register obsidian vault: %v", err)
		}

		applyLayout(session, engDir, getLayout(cfg, mode))

		// Return to the first window before attaching.
		exec.Command("tmux", "select-window", "-t", session+":0").Run()
		logInfo("created tmux session: %s", session)
	} else {
		// Existing session — update SSH host if a new one was supplied.
		if sshHost != "" {
			exec.Command("tmux", "set-environment", "-t", session,
				"ENGAGE_SSH_HOST", sshHost).Run()
			logInfo("updated ENGAGE_SSH_HOST=%s in session %s", sshHost, session)
		}
		logInfo("attaching to existing tmux session: %s", session)
	}

	attachSession(session)
}
