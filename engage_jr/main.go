package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

const version = "2.5"

var reValidName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

func main() {
	// Work sub-type flag. Accepts "web-app" (default), "infra", or "cloud".
	// Other mode flags select an entirely different engagement category.
	workType  := flag.String("w", "", `Work engagement sub-type: web-app (default), infra, cloud`)
	doTHM     := flag.Bool("t", false, "TryHackMe lab")
	doHTB     := flag.Bool("b", false, "HackTheBox lab")
	doExam    := flag.Bool("e", false, "Exam assessment")
	doSwigger := flag.Bool("p", false, "PortSwigger project")

	// Template override — selects any named template (built-in or user-defined).
	cliTemplate := flag.String("template", "", "Load a named template (built-in or ~/.config/engage_jr/templates/)")

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

	mode := resolveMode(*workType, *doTHM, *doHTB, *doExam, *doSwigger)

	// Determine which template to load. -template overrides mode-derived name.
	templateName := *cliTemplate
	if templateName == "" {
		templateName = string(mode)
	}
	tmpl, err := loadTemplate(templateName)
	if err != nil {
		fatal("loading template %q: %v", templateName, err)
	}

	if *listFlag {
		var filterSubDir *string
		if *workType != "" || *doTHM || *doHTB || *doExam || *doSwigger || *cliTemplate != "" {
			s := tmpl.SubDir
			filterSubDir = &s
		}
		listEngagements(cfg, filterSubDir)
		return
	}

	if *openFlag != "" {
		openEngagement(cfg, tmpl, *openFlag, *cliSSHHost)
		return
	}

	if *finishFlag != "" {
		finishEngagement(cfg, tmpl, *finishFlag)
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

	if countTrue(*doTHM, *doHTB, *doExam, *doSwigger) > 1 {
		logWarn("multiple mode flags set — using %s", mode)
	}

	// Validate and resolve the host/profiles file path before creating any
	// directories so a typo does not leave behind an empty engagement directory.
	var absSecondArg string
	if len(args) >= 2 {
		if tmpl.HostFile.Enabled || tmpl.AWS.ProfilesFile {
			absSecondArg, err = filepath.Abs(args[1])
			if err != nil {
				fatal("resolving file path: %v", err)
			}
			info, err := os.Stat(absSecondArg)
			if err != nil {
				fatal("file not accessible: %v", err)
			}
			if !info.Mode().IsRegular() {
				fatal("%q is not a regular file", absSecondArg)
			}
			logDebug("file validated: %s", absSecondArg)
		} else {
			logWarn("second argument %q ignored — template %q does not accept a host or profiles file", args[1], templateName)
		}
	} else if tmpl.HostFile.Enabled {
		logWarn("no host file provided — directories will be created but hosts will not be processed")
	} else if tmpl.AWS.ProfilesFile {
		logWarn("no profiles file provided — AWS profiles will not be configured")
	}

	logDebug("mode=%s template=%s name=%s baseDir=%s", mode, templateName, name, cfg.BaseDir)

	engagementDir, err := buildDir(cfg, tmpl, name)
	if err != nil {
		fatal("building directories: %v", err)
	}
	logInfo("engagement directory: %s", engagementDir)

	var stats hostStats
	var awsProfiles []awsProfile
	var awsProfile string

	if absSecondArg != "" {
		if tmpl.HostFile.Enabled {
			logDebug("processing host file: %s", absSecondArg)
			stats, err = processHostFile(absSecondArg, engagementDir)
			if err != nil {
				fatal("processing hosts: %v", err)
			}
			logInfo("hosts processed: %d unique (%d with URL, %d without)",
				stats.Unique, stats.HTTP, stats.Unique-stats.HTTP)

			dst := filepath.Join(engagementDir, filepath.Base(absSecondArg))
			if err := copyFile(absSecondArg, dst); err != nil {
				logWarn("could not copy original host file to engagement directory: %v", err)
			} else {
				logDebug("copied original host file to %s", dst)
			}
		} else if tmpl.AWS.ProfilesFile {
			logDebug("processing AWS profiles file: %s", absSecondArg)
			awsProfiles, err = parseAWSProfilesFile(absSecondArg)
			if err != nil {
				fatal("parsing AWS profiles: %v", err)
			}
			if len(awsProfiles) > 0 {
				awsProfile = awsProfiles[0].Name
				logInfo("AWS profiles: %d loaded, default profile: %s", len(awsProfiles), awsProfile)
			}
		}
	}

	if dryRun {
		logInfo("[dry-run] complete — no changes were made")
		return
	}

	// Configure AWS profiles in ~/.aws/credentials.
	if len(awsProfiles) > 0 {
		if err := configureAWSProfiles(awsProfiles, tmpl.AWS.DefaultOutput); err != nil {
			logWarn("could not configure AWS profiles: %v", err)
		} else {
			logInfo("AWS profiles configured; AWS_PROFILE=%s", awsProfile)
		}
	}

	// Build engagement env vars and persist the full context to .engage.json so
	// that recon_jr and other tools can load it without requiring an active session.
	engageEnv := buildTmuxEnv(cfg, tmpl, name, engagementDir, *cliSSHHost, awsProfile)
	if err := updateMetaContext(engagementDir, cfg, mode, name, stats, *cliSSHHost, engageEnv); err != nil {
		logWarn("could not update engagement context: %v", err)
	}

	launchShell(cfg, tmpl, name, engagementDir, *cliSSHHost, awsProfile)
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

// copyFile copies src to dst, creating dst if it does not exist.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// resolveMode maps CLI flags to an engagementMode.
// -w <type> takes priority; valid types are "web-app", "infra", "cloud" (and "").
// Unknown -w values are rejected. Among the other flags the first match wins.
// Defaults to ModeWork when no flag is set.
func resolveMode(workType string, thm, htb, exam, swigger bool) engagementMode {
	switch {
	case workType == "infra":
		return ModeInfra
	case workType == "cloud":
		return ModeCloud
	case workType == "web-app" || workType == "":
		// fall through to other flags
	default:
		fatal("unknown work type %q — valid types: web-app, infra, cloud", workType)
	}

	switch {
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
	fmt.Fprint(os.Stderr, `engage_jr [mode] [options] <name> [hostfile|profilesfile]

Modes (default: web-app work engagement):
  -w <type>        Work engagement sub-type: web-app (default), infra, cloud
  -t               TryHackMe lab
  -b               HackTheBox lab
  -e               Exam assessment
  -p               PortSwigger project
  -template <name> Load any named template (built-in or ~/.config/engage_jr/templates/)

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

Custom templates:
  Place ~/.config/engage_jr/templates/<name>.json to add or override any template.
  Use -template <name> to select a custom template directly.

`)
}
