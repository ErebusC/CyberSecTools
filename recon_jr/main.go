package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const version = "0.1"

func main() {
	// Core options
	cliDir           := flag.String("dir", "", "Engagement directory (default: auto-discover from cwd)")
	cliPhase         := flag.Int("phase", 0, "Run only a specific phase (1-7)")
	cliFromPhase     := flag.Int("from-phase", 0, "Resume from a given phase (uses existing output)")
	cliSkip          := flag.String("skip", "", "Comma-separated list of tools to skip for this run")
	cliScope         := flag.String("scope", "", "Path to scope file (default: <engdir>/scope.txt, auto-derived if absent)")
	cliNoNessus      := flag.Bool("no-nessus", false, "Skip Nessus scan regardless of config credentials")
	cliNoSubdomains  := flag.Bool("no-subdomains", false, "Skip Phase 1 subdomain discovery (only scan original host file targets)")
	cliAllowIntrusive := flag.Bool("allow-intrusive", false, "Enable intrusive tools (nikto, arjun, wpscan, etc.)")
	cliDryRun        := flag.Bool("dry-run", false, "Show what would run without executing anything")
	cliCheckDeps     := flag.Bool("check-deps", false, "Verify all required tools are installed and exit")
	cliVerbose       := flag.Bool("verbose", false, "Print debug information")
	cliConfig        := flag.String("config", "", "Config file path (default: ~/.config/recon_jr/config.json)")
	cliNessusHost    := flag.String("nessus-host", "", "Nessus host URL override")
	cliWordlist      := flag.String("wordlist", "", "Wordlist path override")
	cliNucleiTpls    := flag.String("nuclei-templates", "", "Nuclei templates directory override")
	cliProxy         := flag.String("proxy", "", "HTTP proxy URL for all tool traffic (e.g. http://127.0.0.1:8080)")
	cliBurp          := flag.Bool("burp", false, "Route all tool traffic through Burp Suite (http://127.0.0.1:8080)")
	showVer          := flag.Bool("v", false, "Show version")

	flag.Usage = usage
	flag.Parse()

	verbose = *cliVerbose
	dryRun  = *cliDryRun

	if *showVer {
		fmt.Printf("recon_jr version %s\nBuilt by Daniel Roberts\n", version)
		return
	}

	proxyURL := *cliProxy
	if *cliBurp && proxyURL == "" {
		proxyURL = burpProxyURL
	}

	cfg, err := loadConfig(*cliConfig, *cliNessusHost, *cliWordlist, *cliNucleiTpls, proxyURL)
	if err != nil {
		fatal("loading config: %v", err)
	}

	// Merge per-run -skip flag into config skip list
	if *cliSkip != "" {
		for _, s := range strings.Split(*cliSkip, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				cfg.SkipTools = append(cfg.SkipTools, s)
			}
		}
	}

	// -check-deps: verify environment and exit
	if *cliCheckDeps {
		runDepsCheck(cfg, *cliAllowIntrusive)
		return
	}

	// Resolve engagement directory
	engDir := *cliDir
	if engDir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			fatal("getting working directory: %v", err)
		}
		engDir, err = findEngagementDir(cwd)
		if err != nil {
			fatal("%v\nUse -dir to specify the engagement directory explicitly", err)
		}
	} else {
		engDir, err = filepath.Abs(engDir)
		if err != nil {
			fatal("resolving engagement directory: %v", err)
		}
	}
	logDebug("engagement directory: %s", engDir)

	// Read engagement metadata from engage_jr
	engMeta, err := readEngageMeta(engDir)
	if err != nil {
		fatal("reading %s: %v\nIs %s an engage_jr engagement directory?", engageMetaFile, err, engDir)
	}
	logInfo("engagement: %s (mode: %s)", engMeta.Name, engMeta.Mode)

	// Load or initialise .recon.json
	reconMeta := initReconMeta(engDir, engMeta)

	// Preflight: config validation, scope, deps
	// Load host lists early so resolveScope can show derived scope entries
	allHosts, httpHosts, noHTTPHosts, err := masterHostList(engDir)
	if err != nil {
		fatal("loading host files: %v", err)
	}
	if len(allHosts) == 0 {
		fatal("no hosts found in %s/hosts — did engage_jr process a host file?", engDir)
	}

	scope, err := resolveScope(engDir, *cliScope, engMeta, allHosts)
	if err != nil {
		fatal("scope: %v", err)
	}

	// Dependency preflight (warn, do not fail, for Nessus credentials)
	runPreflightWarnings(cfg, *cliAllowIntrusive)

	logDebug("hosts loaded: %d total, %d http, %d no-http", len(allHosts), len(httpHosts), len(noHTTPHosts))

	// Merge any previously discovered hosts
	allHosts, err = mergeDiscovered(engDir, allHosts)
	if err != nil {
		logWarn("could not merge discovered_hosts: %v", err)
	}

	// Filter master host list to scope
	allHosts, oos := filterInScope(allHosts, scope)
	if len(oos) > 0 {
		logWarn("%d hosts in host file are out of scope — they will not be scanned", len(oos))
	}
	httpHosts, _ = filterInScope(httpHosts, scope)
	noHTTPHosts, _ = filterInScope(noHTTPHosts, scope)

	domains := extractRootDomains(allHosts)

	// Nessus insecure TLS warning (shown at pre-run, not just on connection)
	if cfg.NessusInsecureTLS && !*cliNoNessus {
		logWarn("TLS verification disabled for Nessus (nessus_insecure_tls=true) — ensure you are on a trusted network")
	}

	// Pre-run confirmation for work-mode engagements.
	// Skipped when targeting a single phase (-phase N) to reduce friction during re-runs.
	if !dryRun && engMeta.Mode == "work" && *cliPhase == 0 {
		if !confirmRun(engMeta.Name, allHosts, *cliAllowIntrusive, *cliNoNessus || !cfg.nessusEnabled(), cfg.ProxyURL) {
			logInfo("cancelled")
			return
		}
	}

	// Determine phase range
	phaseStart, phaseEnd := resolvePhaseRange(*cliPhase, *cliFromPhase)

	// Initialise report data — seed findings from prior runs stored in .recon.json
	report := &ReportData{
		EngagementName:  engMeta.Name,
		GeneratedAt:     time.Now(),
		PhaseStatus:     reconMeta.PhaseStatus,
		DiscoveredHosts: allHosts,
		HTTPHosts:       httpHosts,
		Domains:         domains,
		CMSDetected:     make(map[string]string),
		WAFDetected:     make(map[string]string),
	}
	for _, f := range reconMeta.Findings {
		report.AddFinding(f)
	}

	state := &RunState{
		Cfg:            cfg,
		EngDir:         engDir,
		EngMeta:        &engMeta,
		ReconMeta:      reconMeta,
		Scope:          scope,
		AllHosts:       allHosts,
		HTTPHosts:      httpHosts,
		NoHTTPHosts:    noHTTPHosts,
		Domains:        domains,
		AllowIntrusive: *cliAllowIntrusive,
		NoNessus:       *cliNoNessus,
		NoSubdomains:   *cliNoSubdomains,
		CMSDetected:    make(map[string]string),
		WAFDetected:    make(map[string]bool),
		Report:         report,
	}

	runner := newRunner(cfg, engDir, reconMeta)

	// Signal handler — clean shutdown on Ctrl-C / SIGTERM
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logWarn("received %s — stopping after current tool completes", sig)
		interrupted.Store(true)
	}()

	if dryRun {
		logInfo("[dry-run] would run phases %d-%d against %d hosts", phaseStart, phaseEnd, len(allHosts))
	}

	// Execute phases
	for phase := phaseStart; phase <= phaseEnd; phase++ {
		if interrupted.Load() {
			break
		}

		// Skip phases already completed in a previous run (unless -phase targets exactly this one)
		if *cliFromPhase > 0 && *cliPhase == 0 {
			phaseName := fmt.Sprintf("phase%d", phase)
			if ps, ok := reconMeta.PhaseStatus[phaseName]; ok && ps.Status == "completed" {
				logInfo("[phase %d] already completed — skipping (use -phase %d to re-run)", phase, phase)
				continue
			}
		}

		if err := runPhase(phase, runner, state); err != nil {
			logWarn("phase %d error: %v", phase, err)
		}

		// Persist findings so partial/repeated runs accumulate correctly
		reconMeta.Findings = report.AllFindings

		// Flush state after each phase
		if err := flushReconMeta(engDir, reconMeta); err != nil {
			logWarn("flushing .recon.json: %v", err)
		}

		if interrupted.Load() {
			break
		}
	}

	// Final flush and report
	if interrupted.Load() {
		logInfo("run interrupted — state saved to .recon.json (use -from-phase to resume)")
	} else {
		now := time.Now()
		reconMeta.CompletedAt = &now
	}

	report.GeneratedAt = time.Now()
	report.PhaseStatus = reconMeta.PhaseStatus
	if err := RenderReport(engDir, report); err != nil {
		logWarn("generating report: %v", err)
	}
	if err := copyReportToNotes(engDir); err != nil {
		logDebug("could not copy report to notes: %v", err)
	}

	if err := flushReconMeta(engDir, reconMeta); err != nil {
		logWarn("writing final .recon.json: %v", err)
	}

	if !interrupted.Load() {
		logInfo("recon complete")
	}
}

// runPhase dispatches to the appropriate phase runner.
func runPhase(n int, r *Runner, s *RunState) error {
	switch n {
	case 1:
		return runPhase1(r, s)
	case 2:
		return runPhase2(r, s)
	case 3:
		return runPhase3(r, s, s.NoNessus)
	case 4:
		return runPhase4(r, s)
	case 5:
		return runPhase5(r, s)
	case 6:
		return runPhase6(r, s)
	case 7:
		return runPhase7(r, s)
	default:
		return fmt.Errorf("unknown phase %d", n)
	}
}

// resolvePhaseRange returns (start, end) based on -phase and -from-phase flags.
func resolvePhaseRange(cliPhase, cliFromPhase int) (int, int) {
	switch {
	case cliPhase > 0:
		return cliPhase, cliPhase
	case cliFromPhase > 0:
		return cliFromPhase, 7
	default:
		return 1, 7
	}
}

// confirmRun displays the pre-run summary and waits for explicit "y" confirmation.
// Required for work-mode engagements to prevent accidental scanning.
func confirmRun(engName string, hosts []string, allowIntrusive, nessusSkipped bool, proxy string) bool {
	fmt.Printf("\n=== recon_jr pre-run confirmation ===\n\n")
	fmt.Printf("Engagement : %s\n", engName)
	fmt.Printf("Host count : %d\n", len(hosts))

	preview := hosts
	if len(preview) > 5 {
		preview = preview[:5]
	}
	for _, h := range preview {
		fmt.Printf("             %s\n", h)
	}
	if len(hosts) > 5 {
		fmt.Printf("             ... and %d more\n", len(hosts)-5)
	}

	fmt.Printf("Intrusive  : %v\n", allowIntrusive)
	fmt.Printf("Nessus     : %v\n", !nessusSkipped)
	if proxy != "" {
		fmt.Printf("Proxy      : %s\n", proxy)
	}
	fmt.Printf("\nType 'y' to proceed, anything else to cancel: ")

	return strings.ToLower(strings.TrimSpace(readLine())) == "y"
}

// runDepsCheck checks all required binaries and prints a status report.
func runDepsCheck(cfg *Config, allowIntrusive bool) {
	missing := CheckDeps(toolBinaries, cfg.SkipTools, allowIntrusive, intrusiveTools)
	if len(missing) == 0 {
		logInfo("all required tools found in PATH")
		return
	}
	logWarn("%d tool(s) missing from PATH:", len(missing))
	for _, m := range missing {
		fmt.Fprintf(os.Stderr, "  missing: %s\n", m)
	}
	os.Exit(1)
}

// runPreflightWarnings emits non-fatal warnings about configuration.
func runPreflightWarnings(cfg *Config, allowIntrusive bool) {
	if !cfg.nessusEnabled() {
		logWarn("Nessus credentials not configured — Nessus scan will be skipped")
	}
	if cfg.Wordlist != "" {
		if _, err := os.Stat(cfg.Wordlist); err != nil {
			logWarn("wordlist %s not found — feroxbuster will fail", cfg.Wordlist)
		}
	}
	if cfg.NucleiTemplates != "" {
		if _, err := os.Stat(cfg.NucleiTemplates); err != nil {
			logWarn("nuclei templates directory %s not found", cfg.NucleiTemplates)
		}
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `recon_jr [options]

Runs sequential web application reconnaissance against an engage_jr engagement directory.
Auto-discovers the engagement by walking up from the current directory for .engage.json.

Options:
  -dir <path>               Engagement directory (default: auto-discover from cwd)
  -phase <n>                Run only a specific phase (1-7)
  -from-phase <n>           Resume from a given phase (uses existing output)
  -skip <tool[,tool]>       Skip named tools for this run
  -scope <path>             Scope file path (default: <engdir>/scope.txt)
  -no-nessus                Skip Nessus scan regardless of config credentials
  -allow-intrusive          Enable intrusive tools (nikto, arjun, wpscan, naabu, etc.)
  -dry-run                  Show what would run without executing anything
  -check-deps               Verify all required tools are installed and exit
  -verbose                  Print debug information
  -config <path>            Config JSON file (default: ~/.config/recon_jr/config.json)
  -nessus-host <url>        Nessus host URL override
  -wordlist <path>          Wordlist path override
  -nuclei-templates <path>  Nuclei templates directory override
  -proxy <url>              HTTP proxy for all tool traffic (e.g. http://127.0.0.1:8080)
  -burp                     Shorthand: proxy all traffic through Burp (http://127.0.0.1:8080)
  -v                        Show version

Config file (~/.config/recon_jr/config.json):
  {
    "nessus_host":             "https://nessus.example.com:8834",
    "nessus_access_key":       "",
    "nessus_secret_key":       "",
    "nessus_template_uuid":    "",
    "nessus_insecure_tls":     false,
    "nessus_poll_secs":        60,
    "nessus_max_scan_minutes": 240,
    "wordlist":                "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
    "nuclei_templates":        "~/.local/nuclei-templates",
    "tools_timeout_secs":      300,
    "tool_delay_secs":         5,
    "skip_tools":              [],
    "proxy_url":               ""
  }

Config precedence (highest to lowest):
  CLI flags > env vars > config file > defaults

Env vars (RECON_ prefix):
  RECON_NESSUS_HOST, RECON_NESSUS_ACCESS_KEY, RECON_NESSUS_SECRET_KEY
  RECON_NESSUS_TEMPLATE_UUID, RECON_NESSUS_INSECURE_TLS
  RECON_NESSUS_POLL_SECS, RECON_NESSUS_MAX_SCAN_MINUTES
  RECON_WORDLIST, RECON_NUCLEI_TEMPLATES
  RECON_TOOLS_TIMEOUT_SECS, RECON_TOOL_DELAY_SECS
  RECON_PROXY

Phases:
  1 — DNS & Subdomain Enumeration (dig, subfinder, theHarvester, crt.sh, dnsx)
  2 — Host Probing & Fingerprinting (httpx, whatweb, wafw00f, gowitness)
  3 — Infrastructure Scanning (nmap, testssl, Nessus API)
  4 — Web Content Discovery (katana, feroxbuster, waybackurls/gau, arjun*)
  5 — Vulnerability Scanning (nuclei, nikto*, wpscan*, joomscan*, droopescan*)
  6 — JavaScript & Secrets (subjs, linkfinder, gitleaks/trufflehog)
  7 — Security Headers (curl)

  * requires -allow-intrusive

Output files (in engagement directory):
  recon_report.md          — full findings summary
  .recon.json              — run state and phase status
  discovered_hosts         — subdomains found in Phase 1
  discovered_endpoints     — endpoints from Phase 4/6
  nmap/                    — nmap output (.xml/.nmap/.gnmap per scan per host)
  nessus/                  — .nessus file and filtered JSON
  other/                   — all other tool output

`)
}
