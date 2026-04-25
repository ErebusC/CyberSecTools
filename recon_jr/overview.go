package main

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const overviewFile = "recon_overview.md"

// RenderOverview writes recon_overview.md into engDir.
// Unlike recon_report.md (which surfaces only security findings), this note
// presents the full picture of everything enumerated: every open port and
// service, all technology fingerprinting, raw nikto output, HTTP headers,
// discovered subdomains and endpoints. Use it as the at-a-glance reference
// during the manual test.
func RenderOverview(engDir string, rd *ReportData) error {
	otherDir := filepath.Join(engDir, "other")
	nmapDir := filepath.Join(engDir, "nmap")

	var b strings.Builder

	fmt.Fprintf(&b, "# Recon Overview — %s\n\n", rd.EngagementName)
	fmt.Fprintf(&b, "Generated: %s\n\n", rd.GeneratedAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintln(&b, "_Full enumeration data — all discovered hosts, ports, services, and tool output._")
	fmt.Fprintln(&b, "_For security findings only, see `recon_report.md`._")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "---")
	fmt.Fprintln(&b)

	writeOverviewHosts(&b, rd)
	writeOverviewWebServices(&b, otherDir)
	writeOverviewTechStack(&b, otherDir)
	writeOverviewWAF(&b, rd)
	writeOverviewNmapTCP(&b, nmapDir)
	writeOverviewNmapUDP(&b, nmapDir)
	writeOverviewNikto(&b, otherDir)
	writeOverviewHeaders(&b, otherDir)
	writeOverviewSubdomains(&b, otherDir)
	writeOverviewEmails(&b, otherDir)
	writeOverviewEndpoints(&b, otherDir)

	path := filepath.Join(engDir, overviewFile)
	if err := os.WriteFile(path, []byte(b.String()), 0644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	logInfo("overview written to %s", path)
	return nil
}

// copyOverviewToNotes copies recon_overview.md into <engDir>/notes/<projectName>/
func copyOverviewToNotes(engDir string) error {
	src := filepath.Join(engDir, overviewFile)
	projectName := filepath.Base(engDir)
	dst := filepath.Join(engDir, "notes", projectName, overviewFile)
	if err := ensureDir(filepath.Dir(dst)); err != nil {
		return err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

// ---- section helpers ---------------------------------------------------------

func overviewHR(b *strings.Builder) {
	fmt.Fprintln(b, "---")
	fmt.Fprintln(b)
}

func writeOverviewHosts(b *strings.Builder, rd *ReportData) {
	fmt.Fprintln(b, "## Discovered Hosts")
	fmt.Fprintln(b)
	if len(rd.DiscoveredHosts) == 0 {
		fmt.Fprintln(b, "_None discovered._")
		fmt.Fprintln(b)
		overviewHR(b)
		return
	}
	fmt.Fprintf(b, "Total in scope: **%d**\n\n", len(rd.DiscoveredHosts))
	fmt.Fprintln(b, "```")
	for _, h := range rd.DiscoveredHosts {
		fmt.Fprintln(b, h)
	}
	fmt.Fprintln(b, "```")
	fmt.Fprintln(b)
	overviewHR(b)
}

func writeOverviewWebServices(b *strings.Builder, otherDir string) {
	fmt.Fprintln(b, "## Live Web Services (httpx)")
	fmt.Fprintln(b)

	entries, _, err := ParseHTTPX(filepath.Join(otherDir, "httpx.json"))
	if err != nil || len(entries) == 0 {
		fmt.Fprintln(b, "_No httpx output found._")
		fmt.Fprintln(b)
		overviewHR(b)
		return
	}

	fmt.Fprintln(b, "| URL | Status | Title | Server | Technologies |")
	fmt.Fprintln(b, "|---|---|---|---|---|")
	for _, e := range entries {
		tech := strings.Join(e.Technologies, ", ")
		title := strings.ReplaceAll(strings.TrimSpace(e.Title), "|", "\\|")
		fmt.Fprintf(b, "| %s | %d | %s | %s | %s |\n",
			e.URL, e.StatusCode, title, e.WebServer, tech)
	}
	fmt.Fprintln(b)
	overviewHR(b)
}

func writeOverviewTechStack(b *strings.Builder, otherDir string) {
	fmt.Fprintln(b, "## Technology Stack (whatweb)")
	fmt.Fprintln(b)

	entries, _, err := ParseWhatWeb(filepath.Join(otherDir, "whatweb.json"))
	if err != nil || len(entries) == 0 {
		fmt.Fprintln(b, "_No whatweb output found._")
		fmt.Fprintln(b)
		overviewHR(b)
		return
	}

	for _, e := range entries {
		fmt.Fprintf(b, "### %s\n\n", e.Target)
		if len(e.Plugins) == 0 {
			fmt.Fprintln(b, "_No plugins detected._")
			fmt.Fprintln(b)
			continue
		}
		names := make([]string, 0, len(e.Plugins))
		for name := range e.Plugins {
			names = append(names, name)
		}
		sort.Strings(names)

		fmt.Fprintln(b, "| Plugin | Version | Info |")
		fmt.Fprintln(b, "|---|---|---|")
		for _, name := range names {
			info := e.Plugins[name]
			vers := strings.Join(info.Version, ", ")
			strs := strings.Join(info.String, ", ")
			if len(strs) > 80 {
				strs = strs[:80] + "…"
			}
			fmt.Fprintf(b, "| %s | %s | %s |\n", name, vers,
				strings.ReplaceAll(strs, "|", "\\|"))
		}
		fmt.Fprintln(b)
	}
	overviewHR(b)
}

func writeOverviewWAF(b *strings.Builder, rd *ReportData) {
	fmt.Fprintln(b, "## WAF Detection")
	fmt.Fprintln(b)
	if len(rd.WAFDetected) == 0 {
		fmt.Fprintln(b, "_No WAFs detected._")
		fmt.Fprintln(b)
		overviewHR(b)
		return
	}
	fmt.Fprintln(b, "| Host | WAF |")
	fmt.Fprintln(b, "|---|---|")
	for host, waf := range rd.WAFDetected {
		fmt.Fprintf(b, "| %s | %s |\n", host, waf)
	}
	fmt.Fprintln(b)
	overviewHR(b)
}

// ---- nmap --------------------------------------------------------------------

// nmapPortRow is a single row in the nmap overview table.
type nmapPortRow struct {
	Host     string
	Port     int
	Protocol string
	State    string
	Service  string
	Version  string
}

// parseNmapAllPorts parses an nmap XML file and returns every open (or
// open|filtered) port entry. Unlike ParseNmap, no filtering is applied.
func parseNmapAllPorts(path string) ([]nmapPortRow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, err
	}

	var rows []nmapPortRow
	for _, h := range run.Hosts {
		addr := ""
		for _, a := range h.Addresses {
			if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
				addr = a.Addr
				break
			}
		}
		for _, p := range h.Ports.Ports {
			if p.State.State != "open" && p.State.State != "open|filtered" {
				continue
			}
			ver := strings.TrimSpace(p.Service.Product + " " + p.Service.Version)
			rows = append(rows, nmapPortRow{
				Host:     addr,
				Port:     p.PortID,
				Protocol: p.Protocol,
				State:    p.State.State,
				Service:  p.Service.Name,
				Version:  ver,
			})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Host != rows[j].Host {
			return rows[i].Host < rows[j].Host
		}
		return rows[i].Port < rows[j].Port
	})
	return rows, nil
}

func writeOverviewNmapSection(b *strings.Builder, heading, glob string, nmapDir string) {
	fmt.Fprintf(b, "## %s\n\n", heading)

	xmlFiles, _ := filepath.Glob(filepath.Join(nmapDir, glob))
	if len(xmlFiles) == 0 {
		fmt.Fprintln(b, "_No nmap output found._")
		fmt.Fprintln(b)
		overviewHR(b)
		return
	}

	// Group rows by host across all matching XML files
	hostRows := make(map[string][]nmapPortRow)
	for _, f := range xmlFiles {
		rows, err := parseNmapAllPorts(f)
		if err != nil {
			continue
		}
		for _, row := range rows {
			hostRows[row.Host] = append(hostRows[row.Host], row)
		}
	}

	if len(hostRows) == 0 {
		fmt.Fprintln(b, "_No open ports found._")
		fmt.Fprintln(b)
		overviewHR(b)
		return
	}

	hosts := make([]string, 0, len(hostRows))
	for h := range hostRows {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	for _, host := range hosts {
		rows := hostRows[host]
		fmt.Fprintf(b, "### %s\n\n", host)
		fmt.Fprintln(b, "| Port | Proto | State | Service | Version |")
		fmt.Fprintln(b, "|---|---|---|---|---|")
		for _, row := range rows {
			fmt.Fprintf(b, "| %d | %s | %s | %s | %s |\n",
				row.Port, row.Protocol, row.State, row.Service,
				strings.ReplaceAll(row.Version, "|", "\\|"))
		}
		fmt.Fprintln(b)
	}
	overviewHR(b)
}

func writeOverviewNmapTCP(b *strings.Builder, nmapDir string) {
	writeOverviewNmapSection(b, "Open Ports — TCP (nmap service scan)", "nmap_tcp-svc_*.xml", nmapDir)
}

func writeOverviewNmapUDP(b *strings.Builder, nmapDir string) {
	writeOverviewNmapSection(b, "Open Ports — UDP top-20 (nmap)", "nmap_udp-top20_*.xml", nmapDir)
}

// ---- nikto -------------------------------------------------------------------

// parseNiktoAllLines returns every finding line from a nikto text output file,
// including lines that the security report filters out.
func parseNiktoAllLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lines []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		if m := reNiktoFinding.FindStringSubmatch(scanner.Text()); m != nil {
			lines = append(lines, strings.TrimSpace(m[1]))
		}
	}
	return lines, scanner.Err()
}

func writeOverviewNikto(b *strings.Builder, otherDir string) {
	fmt.Fprintln(b, "## Nikto Output")
	fmt.Fprintln(b)

	niktoFiles, _ := filepath.Glob(filepath.Join(otherDir, "nikto_*.txt"))
	if len(niktoFiles) == 0 {
		fmt.Fprintln(b, "_Nikto not run (requires `-allow-intrusive`)._")
		fmt.Fprintln(b)
		overviewHR(b)
		return
	}

	for _, f := range niktoFiles {
		host := strings.TrimPrefix(strings.TrimSuffix(filepath.Base(f), ".txt"), "nikto_")
		lines, err := parseNiktoAllLines(f)
		if err != nil {
			continue
		}
		fmt.Fprintf(b, "### %s\n\n", host)
		if len(lines) == 0 {
			fmt.Fprintln(b, "_No findings._")
		} else {
			for _, line := range lines {
				fmt.Fprintf(b, "- %s\n", line)
			}
		}
		fmt.Fprintln(b)
	}
	overviewHR(b)
}

// ---- HTTP headers ------------------------------------------------------------

func writeOverviewHeaders(b *strings.Builder, otherDir string) {
	fmt.Fprintln(b, "## HTTP Response Headers")
	fmt.Fprintln(b)

	headerFiles, _ := filepath.Glob(filepath.Join(otherDir, "headers_*.txt"))
	if len(headerFiles) == 0 {
		fmt.Fprintln(b, "_No header files found._")
		fmt.Fprintln(b)
		overviewHR(b)
		return
	}

	for _, f := range headerFiles {
		host := strings.TrimPrefix(strings.TrimSuffix(filepath.Base(f), ".txt"), "headers_")
		sh, _, err := ParseSecurityHeaders(f, host)
		if err != nil {
			continue
		}
		code := sh.StatusCode
		if code == "" {
			code = "?"
		}
		fmt.Fprintf(b, "### %s  (HTTP %s)\n\n", host, code)
		if sh.ServerHeader != "" {
			fmt.Fprintf(b, "- **Server:** `%s`\n", sh.ServerHeader)
		}
		if sh.XPoweredByHeader != "" {
			fmt.Fprintf(b, "- **X-Powered-By:** `%s`\n", sh.XPoweredByHeader)
		}
		if sh.HSTSValue != "" {
			fmt.Fprintf(b, "- **HSTS:** `%s`\n", sh.HSTSValue)
		} else {
			fmt.Fprintln(b, "- **HSTS:** _not set_")
		}
		if len(sh.MissingHeaders) > 0 {
			fmt.Fprintf(b, "- **Missing:** %s\n", strings.Join(sh.MissingHeaders, ", "))
		}
		if len(sh.InsecureCookies) > 0 {
			fmt.Fprintf(b, "- **Insecure cookies:** %s\n", strings.Join(sh.InsecureCookies, "; "))
		}
		fmt.Fprintln(b)
	}
	overviewHR(b)
}

// ---- subdomains --------------------------------------------------------------

func writeOverviewSubdomains(b *strings.Builder, otherDir string) {
	fmt.Fprintln(b, "## Subdomain Enumeration")
	fmt.Fprintln(b)
	wrote := false

	// dnsx.txt — bulk-resolved superset
	if resolved, err := ParseSubdomainList(filepath.Join(otherDir, "dnsx.txt")); err == nil && len(resolved) > 0 {
		fmt.Fprintf(b, "**dnsx resolved:** %d hosts\n\n", len(resolved))
		fmt.Fprintln(b, "<details><summary>Show resolved hosts</summary>")
		fmt.Fprintln(b)
		fmt.Fprintln(b, "```")
		for _, h := range resolved {
			fmt.Fprintln(b, h)
		}
		fmt.Fprintln(b, "```")
		fmt.Fprintln(b, "</details>")
		fmt.Fprintln(b)
		wrote = true
	}

	// Per-domain subfinder files
	subFiles, _ := filepath.Glob(filepath.Join(otherDir, "subfinder_*.txt"))
	for _, f := range subFiles {
		domain := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), "subfinder_"), ".txt")
		subs, err := ParseSubdomainList(f)
		if err != nil || len(subs) == 0 {
			continue
		}
		fmt.Fprintf(b, "**subfinder — %s:** %d subdomains\n\n", domain, len(subs))
		fmt.Fprintln(b, "<details><summary>Show subdomains</summary>")
		fmt.Fprintln(b)
		fmt.Fprintln(b, "```")
		for _, s := range subs {
			fmt.Fprintln(b, s)
		}
		fmt.Fprintln(b, "```")
		fmt.Fprintln(b, "</details>")
		fmt.Fprintln(b)
		wrote = true
	}

	if !wrote {
		fmt.Fprintln(b, "_No subdomain data found (Phase 1 may not have run)._")
		fmt.Fprintln(b)
	}
	overviewHR(b)
}

// ---- emails ------------------------------------------------------------------

func writeOverviewEmails(b *strings.Builder, otherDir string) {
	emails, err := ParseSubdomainList(filepath.Join(otherDir, "theharvester_emails.txt"))
	if err != nil || len(emails) == 0 {
		return // omit section entirely when nothing was found
	}
	fmt.Fprintln(b, "## Emails Found (theHarvester)")
	fmt.Fprintln(b)
	for _, e := range emails {
		fmt.Fprintf(b, "- %s\n", e)
	}
	fmt.Fprintln(b)
	overviewHR(b)
}

// ---- endpoints ---------------------------------------------------------------

type overviewFeroxRow struct {
	status int
	size   int
	url    string
}

// parseFeroxAllURLs returns all response URLs from a feroxbuster JSONL file
// (200, 301, 302, 403) — not filtered to sensitive patterns like the security report.
func parseFeroxAllURLs(path string) ([]overviewFeroxRow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rows []overviewFeroxRow
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var e feroxEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		if e.Type != "response" {
			continue
		}
		switch e.Status {
		case 200, 301, 302, 403:
			rows = append(rows, overviewFeroxRow{status: e.Status, size: e.ContentLength, url: e.URL})
		}
	}
	return rows, scanner.Err()
}

func writeOverviewEndpoints(b *strings.Builder, otherDir string) {
	fmt.Fprintln(b, "## Discovered Endpoints")
	fmt.Fprintln(b)
	wrote := false

	// Feroxbuster — all notable status codes
	feroxFiles, _ := filepath.Glob(filepath.Join(otherDir, "feroxbuster_*.json"))
	for _, f := range feroxFiles {
		host := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), "feroxbuster_"), ".json")
		rows, err := parseFeroxAllURLs(f)
		if err != nil || len(rows) == 0 {
			continue
		}
		fmt.Fprintf(b, "### feroxbuster — %s (%d URLs)\n\n", host, len(rows))
		fmt.Fprintln(b, "<details><summary>Show URLs</summary>")
		fmt.Fprintln(b)
		fmt.Fprintln(b, "| Status | Size | URL |")
		fmt.Fprintln(b, "|---|---|---|")
		for _, row := range rows {
			fmt.Fprintf(b, "| %d | %d | %s |\n", row.status, row.size, row.url)
		}
		fmt.Fprintln(b, "</details>")
		fmt.Fprintln(b)
		wrote = true
	}

	// Katana — active crawl (plain URL lines)
	katanaFiles, _ := filepath.Glob(filepath.Join(otherDir, "katana_*.json"))
	for _, f := range katanaFiles {
		host := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), "katana_"), ".json")
		urls, err := readLines(f)
		if err != nil || len(urls) == 0 {
			continue
		}
		sort.Strings(urls)
		fmt.Fprintf(b, "### katana — %s (%d endpoints)\n\n", host, len(urls))
		fmt.Fprintln(b, "<details><summary>Show endpoints</summary>")
		fmt.Fprintln(b)
		fmt.Fprintln(b, "```")
		for _, u := range urls {
			fmt.Fprintln(b, u)
		}
		fmt.Fprintln(b, "```")
		fmt.Fprintln(b, "</details>")
		fmt.Fprintln(b)
		wrote = true
	}

	if !wrote {
		fmt.Fprintln(b, "_No endpoint data found (Phase 4 may not have run)._")
		fmt.Fprintln(b)
	}
	overviewHR(b)
}
