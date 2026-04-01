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
	showVer     := flag.Bool("v", false, "Show version")
	verboseFlag := flag.Bool("verbose", false, "Print debug information")
	dryRunFlag  := flag.Bool("dry-run", false, "Show what would be created without making changes")
	listFlag    := flag.Bool("list", false, "List existing engagements and exit")
	openFlag    := flag.String("open", "", "Resume an existing engagement by name")

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
		openEngagement(cfg, mode, *openFlag)
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
	if mode == ModeWork && len(args) >= 2 {
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
	} else if mode == ModeWork {
		logWarn("no host file provided — directories will be created but hosts will not be processed")
	}

	logDebug("mode=%s name=%s baseDir=%s", mode, name, cfg.BaseDir)

	engagementDir, err := buildDir(cfg, mode, name)
	if err != nil {
		fatal("building directories: %v", err)
	}
	logInfo("engagement directory: %s", engagementDir)

	if absHostFile != "" {
		logDebug("processing host file: %s", absHostFile)
		stats, err := processHostFile(absHostFile, engagementDir)
		if err != nil {
			fatal("processing hosts: %v", err)
		}
		logInfo("hosts processed: %d unique (%d with URL, %d without)",
			stats.Unique, stats.HTTP, stats.Unique-stats.HTTP)

		if err := updateMetaHostCount(engagementDir, stats.Unique); err != nil {
			logWarn("could not update engagement metadata with host count: %v", err)
		}
	}

	if dryRun {
		logInfo("[dry-run] complete — no changes were made")
		return
	}

	launchShell(engagementDir)
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
  -open <name>       Resume an existing engagement by name
  -burp-jar <path>   Path to Burp Suite jar
  -base-dir <path>   Base directory (default: ~/Share)
  -config   <path>   Config JSON file (default: ~/.config/engage_jr/config.json)
  -dry-run           Show what would be created without making any changes
  -verbose           Print debug information
  -v                 Version

Config precedence (highest to lowest):
  CLI flags > env vars > config file > defaults

Env vars:  ENGAGE_BURP_JAR, ENGAGE_BASE_DIR, ENGAGE_BURP_TIMEOUT

Config file format (~/.config/engage_jr/config.json):
  {
    "burp_jar":          "/path/to/burpsuite.jar",
    "base_dir":          "/path/to/base",
    "burp_timeout_secs": 90,
    "work_dirs":         ["nmap", "burp", "nessus", "gobuster", "screenshots"]
  }

`)
}
