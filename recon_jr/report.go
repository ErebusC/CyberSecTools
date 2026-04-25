package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const reportFile = "recon_report.md"

// ReportData holds all parsed findings and summary information collected across
// all phases, used to render recon_report.md.
type ReportData struct {
	mu              sync.Mutex
	EngagementName  string
	GeneratedAt     time.Time
	PhaseStatus     map[string]PhaseStatus
	DiscoveredHosts []string
	HTTPHosts       []string
	Domains         []string
	WAFDetected     map[string]string // host -> waf name
	CMSDetected     map[string]string // host -> cms type
	AllFindings     []Finding
}

// AddFinding appends a finding, suppressing duplicates (same tool + host + title).
// Thread-safe — may be called from concurrent goroutines.
func (rd *ReportData) AddFinding(f Finding) {
	rd.mu.Lock()
	defer rd.mu.Unlock()
	for _, existing := range rd.AllFindings {
		if existing.Tool == f.Tool && existing.Host == f.Host && existing.Title == f.Title {
			return
		}
	}
	rd.AllFindings = append(rd.AllFindings, f)
}

// AddFindings appends multiple findings.
func (rd *ReportData) AddFindings(findings []Finding) {
	for _, f := range findings {
		rd.AddFinding(f)
	}
}

// RenderReport writes recon_report.md into engDir.
func RenderReport(engDir string, rd *ReportData) error {
	if err := ensureDir(engDir); err != nil {
		return err
	}

	var b strings.Builder

	writeHeader(&b, rd)
	writeSummary(&b, rd)
	writeHostDiscovery(&b, rd)
	writeInfrastructure(&b, rd)
	writeFindings(&b, rd)
	writeAppendix(&b, rd)

	path := filepath.Join(engDir, reportFile)
	if err := os.WriteFile(path, []byte(b.String()), 0644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	logInfo("report written to %s", path)
	return nil
}

func writeHeader(b *strings.Builder, rd *ReportData) {
	fmt.Fprintf(b, "# Recon Report — %s\n\n", rd.EngagementName)
	fmt.Fprintf(b, "Generated: %s\n\n", rd.GeneratedAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintln(b, "---")
	fmt.Fprintln(b)
}

func writeSummary(b *strings.Builder, rd *ReportData) {
	fmt.Fprintln(b, "## Summary")
	fmt.Fprintln(b)

	// Phase completion table
	fmt.Fprintln(b, "| Phase | Status |")
	fmt.Fprintln(b, "|---|---|")
	phases := []string{"phase1", "phase2", "phase3", "phase4", "phase5", "phase6", "phase7"}
	phaseNames := map[string]string{
		"phase1": "Phase 1 — DNS & Subdomain Enumeration",
		"phase2": "Phase 2 — Host Probing & Fingerprinting",
		"phase3": "Phase 3 — Infrastructure Scanning",
		"phase4": "Phase 4 — Web Content Discovery",
		"phase5": "Phase 5 — Vulnerability Scanning",
		"phase6": "Phase 6 — JavaScript & Secrets",
		"phase7": "Phase 7 — Security Headers",
	}
	for _, p := range phases {
		name := phaseNames[p]
		status := "not run"
		if ps, ok := rd.PhaseStatus[p]; ok {
			status = ps.Status
			if ps.InterruptedTool != "" {
				status = fmt.Sprintf("interrupted (at %s)", ps.InterruptedTool)
			}
		}
		fmt.Fprintf(b, "| %s | %s |\n", name, status)
	}
	fmt.Fprintln(b)

	// Finding counts by severity
	counts := make(map[Severity]int)
	for _, f := range rd.AllFindings {
		if !f.Suppress {
			counts[f.Severity]++
		}
	}
	fmt.Fprintln(b, "| Severity | Count |")
	fmt.Fprintln(b, "|---|---|")
	for _, sev := range []Severity{SevCritical, SevHigh, SevMedium, SevLow, SevInfo} {
		if counts[sev] > 0 {
			fmt.Fprintf(b, "| %s | %d |\n", sev, counts[sev])
		}
	}
	fmt.Fprintln(b)
	fmt.Fprintln(b, "---")
	fmt.Fprintln(b)
}

func writeHostDiscovery(b *strings.Builder, rd *ReportData) {
	fmt.Fprintln(b, "## Phase 1 — DNS & Subdomain Enumeration")
	fmt.Fprintln(b)

	if len(rd.Domains) > 0 {
		fmt.Fprintf(b, "Root domains enumerated: %s\n\n", strings.Join(rd.Domains, ", "))
	}

	if len(rd.DiscoveredHosts) > 0 {
		fmt.Fprintf(b, "Total hosts in scope (original + discovered): **%d**\n\n", len(rd.DiscoveredHosts))
		fmt.Fprintln(b, "<details><summary>Host list</summary>")
		fmt.Fprintln(b)
		fmt.Fprintln(b, "```")
		for _, h := range rd.DiscoveredHosts {
			fmt.Fprintln(b, h)
		}
		fmt.Fprintln(b, "```")
		fmt.Fprintln(b, "</details>")
		fmt.Fprintln(b)
	}

	// DNS-related findings (AXFR, etc.)
	printFindingsSection(b, filterFindings(rd.AllFindings, func(f Finding) bool {
		return f.Tool == "dig" || strings.Contains(strings.ToLower(f.Category), "dns")
	}))

	fmt.Fprintln(b, "---")
	fmt.Fprintln(b)
}

func writeInfrastructure(b *strings.Builder, rd *ReportData) {
	fmt.Fprintln(b, "## Phase 2 — Host Probing & Fingerprinting")
	fmt.Fprintln(b)

	if len(rd.HTTPHosts) > 0 {
		fmt.Fprintf(b, "Live HTTP/HTTPS services: **%d**\n\n", len(rd.HTTPHosts))
		fmt.Fprintln(b, "<details><summary>HTTP host list</summary>")
		fmt.Fprintln(b)
		fmt.Fprintln(b, "```")
		for _, h := range rd.HTTPHosts {
			fmt.Fprintln(b, h)
		}
		fmt.Fprintln(b, "```")
		fmt.Fprintln(b, "</details>")
		fmt.Fprintln(b)
	}

	if len(rd.WAFDetected) > 0 {
		fmt.Fprintln(b, "### WAF Detection")
		fmt.Fprintln(b)
		fmt.Fprintln(b, "| Host | WAF |")
		fmt.Fprintln(b, "|---|---|")
		for host, waf := range rd.WAFDetected {
			fmt.Fprintf(b, "| %s | %s |\n", host, waf)
		}
		fmt.Fprintln(b)
	}

	if len(rd.CMSDetected) > 0 {
		fmt.Fprintln(b, "### CMS Detection")
		fmt.Fprintln(b)
		fmt.Fprintln(b, "| Host | CMS |")
		fmt.Fprintln(b, "|---|---|")
		for host, cms := range rd.CMSDetected {
			fmt.Fprintf(b, "| %s | %s |\n", host, cms)
		}
		fmt.Fprintln(b)
	}

	// Virtual host findings from ffuf
	vhostFindings := filterFindings(rd.AllFindings, func(f Finding) bool {
		return f.Tool == "ffuf" && !f.Suppress
	})
	if len(vhostFindings) > 0 {
		fmt.Fprintln(b, "### Virtual Host Discovery")
		fmt.Fprintln(b)
		printFindingsSection(b, vhostFindings)
	}

	fmt.Fprintln(b, "---")
	fmt.Fprintln(b)
}

func writeFindings(b *strings.Builder, rd *ReportData) {
	phaseMap := map[string][]string{
		"Phase 3 — Infrastructure Scanning": {"nmap", "testssl", "nessus"},
		"Phase 4 — Web Content Discovery":   {"feroxbuster", "katana"},
		"Phase 5 — Vulnerability Scanning":  {"nuclei", "nikto", "wpscan", "joomscan", "droopescan"},
		"Phase 6 — JavaScript & Secrets":    {"gitleaks", "trufflehog", "gh"},
		"Phase 7 — Security Headers":        {"curl", "whatweb"},
	}
	phaseStatusKey := map[string]string{
		"Phase 3 — Infrastructure Scanning": "phase3",
		"Phase 4 — Web Content Discovery":   "phase4",
		"Phase 5 — Vulnerability Scanning":  "phase5",
		"Phase 6 — JavaScript & Secrets":    "phase6",
		"Phase 7 — Security Headers":        "phase7",
	}
	phaseOrder := []string{
		"Phase 3 — Infrastructure Scanning",
		"Phase 4 — Web Content Discovery",
		"Phase 5 — Vulnerability Scanning",
		"Phase 6 — JavaScript & Secrets",
		"Phase 7 — Security Headers",
	}

	for _, phaseName := range phaseOrder {
		key := phaseStatusKey[phaseName]
		ps, ran := rd.PhaseStatus[key]
		if !ran || ps.Status == "" {
			continue // phase never ran — omit entirely
		}

		tools := phaseMap[phaseName]
		phaseFindingsAll := filterFindings(rd.AllFindings, func(f Finding) bool {
			for _, t := range tools {
				if f.Tool == t {
					return true
				}
			}
			return false
		})
		reportable := filterFindings(phaseFindingsAll, func(f Finding) bool { return !f.Suppress })

		fmt.Fprintf(b, "## %s\n\n", phaseName)
		if len(reportable) == 0 {
			fmt.Fprintln(b, "_No significant findings._")
			fmt.Fprintln(b)
		} else {
			printFindingsSection(b, reportable)
		}
		fmt.Fprintln(b, "---")
		fmt.Fprintln(b)
	}
}

func writeAppendix(b *strings.Builder, rd *ReportData) {
	fmt.Fprintln(b, "## Appendix — Output Files")
	fmt.Fprintln(b)
	fmt.Fprintln(b, "Raw tool output is in the engagement directory. All files are in `other/` unless noted.")
	fmt.Fprintln(b)
	fmt.Fprintln(b, "```")
	fmt.Fprintln(b, "nmap/                          — nmap output per host (.xml/.nmap/.gnmap)")
	fmt.Fprintln(b, "  nmap_tcp-fullports_<host>.*  — pass 1: full TCP port sweep")
	fmt.Fprintln(b, "  nmap_tcp-svc_<host>.*        — pass 2: service/version + NSE on open ports")
	fmt.Fprintln(b, "  nmap_udp-top20_<host>.*      — UDP top-20 scan")
	fmt.Fprintln(b, "nessus/                        — .nessus file, filtered JSON summaries")
	fmt.Fprintln(b, "other/")
	fmt.Fprintln(b, "  httpx.json                   — live service probe results")
	fmt.Fprintln(b, "  whatweb.json                 — technology fingerprinting")
	fmt.Fprintln(b, "  wafw00f_<host>.json          — WAF detection per host")
	fmt.Fprintln(b, "  screenshots/                 — gowitness screenshots (multiple files per host)")
	fmt.Fprintln(b, "  testssl_<host>.json          — TLS audit per HTTPS host")
	fmt.Fprintln(b, "  nuclei.json                  — nuclei template scan results")
	fmt.Fprintln(b, "  nikto_<host>.txt             — nikto web server scan (intrusive)")
	fmt.Fprintln(b, "  katana_<host>.json           — active crawl results per host")
	fmt.Fprintln(b, "  feroxbuster_<host>.json      — directory brute-force results per host")
	fmt.Fprintln(b, "  waybackurls_<domain>.txt     — Wayback Machine historical URLs")
	fmt.Fprintln(b, "  gau_<domain>.txt             — gau historical URLs (AlienVault/URLScan/CC)")
	fmt.Fprintln(b, "  arjun_<host>.json            — hidden parameter discovery (intrusive)")
	fmt.Fprintln(b, "  wpscan_<host>.json           — WordPress scan results (intrusive)")
	fmt.Fprintln(b, "  joomscan_<host>.txt          — Joomla scan results (intrusive)")
	fmt.Fprintln(b, "  droopescan_<host>.json       — Drupal scan results (intrusive)")
	fmt.Fprintln(b, "  js_urls.txt                  — JavaScript file URLs found by subjs")
	fmt.Fprintln(b, "  linkfinder_endpoints.txt     — endpoints extracted from JS files")
	fmt.Fprintln(b, "  ffuf_vhost_<domain>.json     — virtual host discovery results")
	fmt.Fprintln(b, "  gitleaks.json                — secrets detected by gitleaks")
	fmt.Fprintln(b, "  secrets_unverified.json      — unverified secrets from trufflehog")
	fmt.Fprintln(b, "  trufflehog_github_<org>.json — GitHub org secret scan results")
	fmt.Fprintln(b, "  gitdorks_<domain>.json       — GitHub code search results")
	fmt.Fprintln(b, "  headers_<host>.txt           — raw HTTP response headers per host")
	fmt.Fprintln(b, "  subfinder_<domain>.txt       — passive subdomain enumeration")
	fmt.Fprintln(b, "  theharvester_<domain>.xml    — theHarvester results")
	fmt.Fprintln(b, "  theharvester_emails.txt      — email addresses found by theHarvester")
	fmt.Fprintln(b, "  dnsx.txt                     — DNS resolution results")
	fmt.Fprintln(b, "  out_of_scope.txt             — hosts filtered out by scope rules")
	fmt.Fprintln(b, "```")
	fmt.Fprintln(b)
}

// copyReportToNotes copies recon_report.md into <engDir>/notes/<projectName>/
// so it lands inside the engagement's Obsidian vault subfolder.
// e.g. /Share/work/erebus_2/notes/erebus_2/recon_report.md
func copyReportToNotes(engDir string) error {
	src := filepath.Join(engDir, reportFile)
	projectName := filepath.Base(engDir)
	dst := filepath.Join(engDir, "notes", projectName, reportFile)
	if err := ensureDir(filepath.Dir(dst)); err != nil {
		return err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

// printFindingsSection renders a sorted table of findings, grouped by severity.
func printFindingsSection(b *strings.Builder, findings []Finding) {
	if len(findings) == 0 {
		return
	}

	// Sort: Critical > High > Medium > Low > Info, then by host
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity > findings[j].Severity
		}
		return findings[i].Host < findings[j].Host
	})

	fmt.Fprintln(b, "| Severity | Host | Title | Detail |")
	fmt.Fprintln(b, "|---|---|---|---|")
	for _, f := range findings {
		detail := strings.ReplaceAll(f.Detail, "\n", " ")
		detail = strings.ReplaceAll(detail, "|", "\\|")
		fmt.Fprintf(b, "| %s | %s | %s | %s |\n",
			f.Severity, escapeMarkdown(f.Host), escapeMarkdown(f.Title), detail)
	}
	fmt.Fprintln(b)
}

func filterFindings(findings []Finding, keep func(Finding) bool) []Finding {
	var out []Finding
	for _, f := range findings {
		if keep(f) {
			out = append(out, f)
		}
	}
	return out
}

func escapeMarkdown(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}
