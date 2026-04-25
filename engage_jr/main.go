package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

const version = "2.4"

var reValidName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

func main() {
	// Mode flags — mutually exclusive; work is the default.
	// Explicit -w takes priority over all other mode flags.
	doWork    := flag.Bool("w", false, "Work engagement (default; takes priority if combined with other modes)")
	doTHM     := flag.Bool("t", false, "TryHackMe lab")
	doHTB     := flag.Bool("b", false, "HackTheBox lab")
	doExam    := flag.Bool("e", false, "Exam assessment")
	doSwigger := flag.Bool("p", false, "PortSwigger project")

	// Config override flags.
	cliBurpJar  := flag.String("burp-jar", "", "Path to Burp Suite jar (overrides config/env)")
	cliBaseDir  := flag.String("base-dir", "", "Base directory override (overrides config/env)")
	cliConfig   := flag.String("config", "", "Path to config JSON (default: ~/.config/engage_jr/config.json)")
	cliSSHHost  := flag.String("ssh", "", "SSH config alias for the VPS connection (sets ENGAGE_SSH_HOST)")
	showVer     := flag.Bool("v", false, "Show version")
	verboseFlag := flag.Bool("verbose", false, "Print debug information")
	dryRunFlag  := flag.Bool("dry-run", false, "Show what would be created without making changes")
	listFlag    := flag.Bool("list", false, "List existing engagements and exit")
	openFlag    := flag.String("open", "", "Resume an existing engagement by name")
	finishFlag  := flag.String("finish", "", "Archive and GPG-sign an engagement by name")

	flag.Usage = usage
	flag.Parse()

	verbose = *verboseFlag
	dryRun  = *dryRunFlag

	if *showVer {
		fmt.Printf("engage_jr version %s\nBuilt by Daniel Roberts\n", version)
		return
	}

	cfg, err := loadConfig(*cliConfig, *cliBurpJar, *cliBaseDir)
	if err != nil {
		fatal("loading config: %v", err)
	}

	mode := resolveMode(*doWork, *doTHM, *doHTB, *doExam, *doSwigger)

	if *listFlag {
		var filterMode *engagementMode
		if countTrue(*doWork, *doTHM, *doHTB, *doExam, *doSwigger) > 0 {
			filterMode = &mode
		}
		listEngagements(cfg, filterMode)
		return
	}

	if *openFlag != "" {
		openEngagement(cfg, mode, *openFlag, *cliSSHHost)
		return
	}

	if *finishFlag != "" {
    		finishEngagement(cfg, mode, *finishFlag)
   	 	return
	}

	args := flag.Args()
	if len(args) < 1 {
		usage()
		os.Exit(1)
	}

	name := args[0]
	if err := validateName(name); err != nil {
		fatal("%v", err)
	}

	if countTrue(*doWork, *doTHM, *doHTB, *doExam, *doSwigger) > 1 {
		logWarn("multiple mode flags set — using %s", mode)
	}

	// Validate and resolve the host file path before creating any directories
	// so a typo does not leave behind an empty engagement directory.
	var absHostFile string
	if (mode == ModeWork || mode == ModeExam) && len(args) >= 2 {
		absHostFile, err = filepath.Abs(args[1])
		if err != nil {
			fatal("resolving host file path: %v", err)
		}
		info, err := os.Stat(absHostFile)
		if err != nil {
			fatal("host file not accessible: %v", err)
		}
		if !info.Mode().IsRegular() {
			fatal("host file %q is not a regular file", absHostFile)
		}
		logDebug("host file validated: %s", absHostFile)
	} else if mode == ModeWork || mode == ModeExam {
		logWarn("no host file provided — directories will be created but hosts will not be processed")
	}

	logDebug("mode=%s name=%s baseDir=%s", mode, name, cfg.BaseDir)

	engagementDir, err := buildDir(cfg, mode, name)
	if err != nil {
		fatal("building directories: %v", err)
	}
	logInfo("engagement directory: %s", engagementDir)

	var stats hostStats
	if absHostFile != "" {
		logDebug("processing host file: %s", absHostFile)
		stats, err = processHostFile(absHostFile, engagementDir)
		if err != nil {
			fatal("processing hosts: %v", err)
		}
		logInfo("hosts processed: %d unique (%d with URL, %d without)",
			stats.Unique, stats.HTTP, stats.Unique-stats.HTTP)
	}

	if dryRun {
		logInfo("[dry-run] complete — no changes were made")
		return
	}

	// Build engagement env vars and persist the full context to .engage.json so
	// that recon_jr and other tools can load it without requiring an active session.
	engageEnv := buildTmuxEnv(cfg, mode, name, engagementDir, *cliSSHHost)
	if err := updateMetaContext(engagementDir, cfg, mode, name, stats, *cliSSHHost, engageEnv); err != nil {
		logWarn("could not update engagement context: %v", err)
	}

	launchShell(cfg, mode, name, engagementDir, *cliSSHHost)
}

// validateName rejects engagement names that could create unexpected filesystem
// paths. Names must start with a letter or digit and contain only letters,
// digits, hyphens, underscores, and dots.
func validateName(name string) error {
	if !reValidName.MatchString(name) {
		return fmt.Errorf("invalid engagement name %q — use letters, digits, hyphens, underscores, and dots only", name)
	}
	return nil
}

// resolveMode maps CLI flags to an engagementMode. Explicit -w takes priority
// over all other flags. Otherwise the first match in order wins. Defaults to
// ModeWork when no flag is set.
func resolveMode(work, thm, htb, exam, swigger bool) engagementMode {
	switch {
	case work:
		return ModeWork
	case thm:
		return ModeTHM
	case htb:
		return ModeHTB
	case exam:
		return ModeExam
	case swigger:
		return ModeSwigger
	default:
		return ModeWork
	}
}

func countTrue(flags ...bool) int {
	n := 0
	for _, f := range flags {
		if f {
			n++
		}
	}
	return n
}

func usage() {
	fmt.Fprint(os.Stderr, `engage_jr [mode] [options] <name> [hostfile]

Modes (default: -w):
  -w    Work engagement — creates subdirs, processes hostfile
  -t    TryHackMe lab
  -b    HackTheBox lab
  -e    Exam assessment
  -p    PortSwigger project

Options:
  -list              List all existing engagements and exit (combine with mode to filter)
  -open <name>       Resume an existing engagement (attaches to tmux session if enabled)
  -finish <name>     Archive and GPG-sign an existing engagement (kills tmux session)
  -ssh <alias>       SSH config alias for VPS connection (sets ENGAGE_SSH_HOST in tmux session)
  -burp-jar <path>   Path to Burp Suite jar
  -base-dir <path>   Base directory (default: /Share)
  -config   <path>   Config JSON file (default: ~/.config/engage_jr/config.json)
  -dry-run           Show what would be created without making any changes
  -verbose           Print debug information
  -v                 Version

Config precedence (highest to lowest):
  CLI flags > env vars > config file > defaults

Env vars:
  ENGAGE_BURP_JAR, ENGAGE_BASE_DIR, ENGAGE_BURP_TIMEOUT
  ENGAGE_TMUX (1/true to enable tmux), ENGAGE_TMUX_SESSION_PREFIX
  ENGAGE_OBSIDIAN_BIN, ENGAGE_OBSIDIAN_VAULT

Config file format (~/.config/engage_jr/config.json):
  {
    "burp_jar":              "/path/to/burpsuite.jar",
    "base_dir":              "/path/to/base",
    "burp_timeout_secs":     90,
    "work_dirs":             ["nmap", "burp", "nessus", "gobuster", "screenshots"],
    "tmux_enabled":          true,
    "tmux_prefix":           "",
    "obsidian_bin":          "obsidian",
    "obsidian_synced_vault": "~/Notes",
    "ssh_hosts":             {"work": "my-vps"},
    "tmux_layouts": {
      "work": [
        {
          "name": "main", "focus_pane": 0,
          "panes": [
            {},
            {"split_direction": "v", "percent": 40},
            {"split_direction": "h", "split_from": 1,
             "command": "[ -n \"$ENGAGE_SSH_HOST\" ] && ssh $ENGAGE_SSH_HOST"}
          ]
        },
        {"name": "notes", "panes": [{"command": "cd \"$ENGAGE_NOTES_DIR\" && xdg-open \"obsidian://open?path=$ENGAGE_NOTES_DIR\" 2>/dev/null"}]}
      ]
    }
  }

`)
}
