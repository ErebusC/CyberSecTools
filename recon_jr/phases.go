package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// RunState holds the mutable state passed to each phase runner.
type RunState struct {
	Cfg            *Config
	EngDir         string
	EngMeta        *EngagementMeta
	ReconMeta      *ReconMeta
	Scope          *Scope  // enumeration + infra scope
	WebScope       *Scope  // web app testing scope; nil = same as Scope
	AllHosts       []string
	HTTPHosts      []string
	NoHTTPHosts    []string
	Domains        []string
	AllowIntrusive bool
	NoNessus       bool
	NoSubdomains   bool
	CMSDetected    map[string]string
	WAFDetected    map[string]bool
	Report         *ReportData
}

// effectiveWebScope returns WebScope when set, otherwise falls back to Scope.
// All web-testing phases use this so they respect the tighter scope when set.
func (s *RunState) effectiveWebScope() *Scope {
	if s.WebScope != nil {
		return s.WebScope
	}
	return s.Scope
}

// toolBinaries maps tool names to the binary expected in PATH.
var toolBinaries = map[string]string{
	"subfinder":    "subfinder",
	"dnsx":         "dnsx",
	"theHarvester": "theharvester",
	"dig":          "dig",
	"naabu":        "naabu",
	"httpx":        "httpx-pd",
	"whatweb":      "whatweb",
	"wafw00f":      "wafw00f",
	"gowitness":    "gowitness",
	"nmap":         "nmap",
	"testssl":      "testssl",
	"katana":       "katana",
	"waybackurls":  "waybackurls",
	"gau":          "gau",
	"feroxbuster":  "feroxbuster",
	"arjun":        "arjun",
	"nuclei":       "nuclei",
	"nikto":        "nikto",
	"wpscan":       "wpscan",
	"joomscan":     "joomscan",
	"droopescan":   "droopescan",
	"subjs":        "subjs",
	"linkfinder":   "linkfinder",
	"trufflehog":   "trufflehog",
	"gitleaks":     "gitleaks",
	"curl":         "curl",
	"ffuf":         "ffuf",
	"gh":           "gh",
}

// intrusiveTools lists tools that require -allow-intrusive to run.
var intrusiveTools = map[string]bool{
	"arjun":      true,
	"naabu":      true,
	"wpscan":     true,
	"joomscan":   true,
	"droopescan": true,
}

// ---- Phase 1: DNS and Subdomain Enumeration --------------------------------

func runPhase1(r *Runner, s *RunState) error {
	logInfo("[phase 1] DNS & Subdomain Enumeration")
	markPhaseStarted(s.ReconMeta, "phase1")

	otherDir := filepath.Join(s.EngDir, "other")
	if err := ensureDir(otherDir); err != nil {
		return err
	}

	var allDiscovered []string

	if s.NoSubdomains {
		logInfo("  subdomain discovery skipped (-no-subdomains)")
	}

	for _, domain := range s.Domains {
		if interrupted.Load() {
			break
		}
		safe := sanitizeForFilename(domain)

		// dig — AXFR zone transfer attempt
		runDigAXFR(r, s, domain)
		r.Delay()

		// DNS record checks — SPF, DMARC, CAA
		if !interrupted.Load() {
			runDNSRecordChecks(r, s, domain)
			r.Delay()
		}

		// subfinder — passive subdomain enumeration, all sources
		if !s.NoSubdomains && !interrupted.Load() {
			outFile := filepath.Join(otherDir, "subfinder_"+safe+".txt")
			subfinderArgs := append([]string{"-d", domain, "-o", outFile, "-silent", "-all"},
				proxyFlagForTool("subfinder", s.Cfg.ProxyURL)...)
			res := r.Run("subfinder", "subfinder", subfinderArgs, outFile)
			if !res.Skipped && res.Err == nil {
				if hosts, err := ParseSubdomainList(outFile); err == nil {
					allDiscovered = append(allDiscovered, hosts...)
				}
			}
			r.Delay()
		}

		// theHarvester — use reliable free sources rather than -b all to avoid
		// wasting time on sources that require API keys or are frequently blocked
		if !s.NoSubdomains && !interrupted.Load() {
			outBase := filepath.Join(otherDir, "theharvester_"+safe)
			res := r.Run("theHarvester", "theharvester", []string{
				"-d", domain,
				"-b", "baidu,bing,crtsh,dnsdumpster,hackertarget,rapiddns,threatminer,urlscan,virustotal",
				"-f", outBase,
			}, "")
			if !res.Skipped && res.Err == nil {
				if hosts, err := parseTheHarvesterXML(outBase+".xml", s.EngDir, domain); err == nil {
					allDiscovered = append(allDiscovered, hosts...)
				}
			}
			r.Delay()
		}

		// crt.sh — passive certificate transparency query
		if !s.NoSubdomains && !interrupted.Load() {
			if hosts, err := queryCRTSH(s.EngDir, domain); err != nil {
				logWarn("crt.sh: %v", err)
			} else {
				allDiscovered = append(allDiscovered, hosts...)
			}
			r.Delay()
		}
	}

	if interrupted.Load() {
		markPhaseInterrupted(s.ReconMeta, "phase1", r.CurrentTool())
		return nil
	}

	allDiscovered = deduplicateHosts(allDiscovered)
	inScope, outOfScope := filterInScope(allDiscovered, s.Scope)

	if len(outOfScope) > 0 {
		logInfo("  scope filter: removed %d out-of-scope hosts", len(outOfScope))
		_ = writeLinesToFile(filepath.Join(otherDir, "out_of_scope.txt"), outOfScope)
	}
	if len(inScope) > 0 {
		if err := writeDiscoveredHosts(s.EngDir, inScope); err != nil {
			logWarn("could not write discovered_hosts: %v", err)
		}
	}

	// dnsx — bulk resolve the full discovered list
	if !interrupted.Load() && len(allDiscovered) > 0 {
		allSubFile := filepath.Join(otherDir, "all_subdomains.txt")
		_ = writeLinesToFile(allSubFile, allDiscovered)

		outFile := filepath.Join(otherDir, "dnsx.txt")
		res := r.Run("dnsx", "dnsx", []string{"-l", allSubFile, "-o", outFile, "-silent"}, outFile)
		if !res.Skipped && res.Err == nil {
			if resolved, err := ParseSubdomainList(outFile); err == nil {
				inResolved, _ := filterInScope(resolved, s.Scope)
				_ = writeDiscoveredHosts(s.EngDir, inResolved)
			}
		}
		r.Delay()
	}

	merged, err := mergeDiscovered(s.EngDir, s.AllHosts)
	if err == nil {
		// Re-filter after merge: discovered_hosts may contain entries from a prior
		// run with a wider scope. Always enforce the current scope.
		inScope, oos := filterInScope(merged, s.Scope)
		if len(oos) > 0 {
			logInfo("  scope: removed %d previously-discovered hosts now out of scope", len(oos))
		}
		s.AllHosts = inScope
		s.Report.DiscoveredHosts = inScope
	}
	s.ReconMeta.DiscoveredHosts = len(s.AllHosts)

	markPhaseCompleted(s.ReconMeta, "phase1")
	logInfo("  phase 1 complete — %d total hosts in scope", len(s.AllHosts))
	return nil
}

// runDNSRecordChecks checks SPF, DMARC, and CAA records for domain.
func runDNSRecordChecks(r *Runner, s *RunState, domain string) {
	// SPF
	spfOut, res := r.RunWithOutput("dig", "dig", []string{"+short", "TXT", domain})
	if res.Skipped && res.SkipReason != "dry-run" {
		return
	}
	hasSPF := false
	for _, line := range strings.Split(spfOut, "\n") {
		if strings.Contains(line, "v=spf1") {
			hasSPF = true
			break
		}
	}
	if !hasSPF {
		s.Report.AddFinding(Finding{
			Tool: "dig", Host: domain, Category: "DNS",
			Title:    "No SPF record",
			Detail:   "Domain has no SPF record — email spoofing may be possible",
			Severity: SevMedium,
		})
	}

	// DMARC
	dmarcOut, _ := r.RunWithOutput("dig", "dig", []string{"+short", "TXT", "_dmarc." + domain})
	hasDMARC := false
	dmarcPolicy := ""
	for _, line := range strings.Split(dmarcOut, "\n") {
		if strings.Contains(line, "v=DMARC1") {
			hasDMARC = true
			for _, part := range strings.Split(line, ";") {
				part = strings.TrimSpace(strings.Trim(part, `"`))
				if strings.HasPrefix(part, "p=") {
					dmarcPolicy = strings.ToLower(strings.TrimPrefix(part, "p="))
				}
			}
			break
		}
	}
	if !hasDMARC {
		s.Report.AddFinding(Finding{
			Tool: "dig", Host: domain, Category: "DNS",
			Title:    "No DMARC record",
			Detail:   "Domain has no DMARC record — email authentication cannot be enforced",
			Severity: SevMedium,
		})
	} else if dmarcPolicy == "none" {
		s.Report.AddFinding(Finding{
			Tool: "dig", Host: domain, Category: "DNS",
			Title:    "DMARC policy not enforced (p=none)",
			Detail:   "DMARC record present but policy is 'none' — emails are not rejected or quarantined",
			Severity: SevLow,
		})
	}

	// CAA
	caaOut, _ := r.RunWithOutput("dig", "dig", []string{"+short", "CAA", domain})
	if strings.TrimSpace(caaOut) == "" {
		s.Report.AddFinding(Finding{
			Tool: "dig", Host: domain, Category: "DNS",
			Title:    "No CAA records",
			Detail:   "No Certificate Authority Authorization records — any CA can issue certificates for this domain",
			Severity: SevLow,
		})
	}

	// MX
	mxOut, _ := r.RunWithOutput("dig", "dig", []string{"+short", "MX", domain})
	mxOut = strings.TrimSpace(mxOut)
	if mxOut == "" {
		s.Report.AddFinding(Finding{
			Tool: "dig", Host: domain, Category: "DNS",
			Title:    "No MX records",
			Detail:   "Domain has no MX records — does not directly receive email",
			Severity: SevInfo,
		})
	} else {
		var servers []string
		for _, line := range strings.Split(mxOut, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			// "10 mail.example.com." → extract the hostname
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				servers = append(servers, strings.TrimRight(parts[1], "."))
			} else {
				servers = append(servers, strings.TrimRight(line, "."))
			}
		}
		s.Report.AddFinding(Finding{
			Tool: "dig", Host: domain, Category: "DNS",
			Title:    "Mail servers",
			Detail:   strings.Join(servers, ", "),
			Severity: SevInfo,
		})
	}
}

// runDigAXFR attempts a zone transfer for domain and records the result.
func runDigAXFR(r *Runner, s *RunState, domain string) {
	stdout, nsRes := r.RunWithOutput("dig", "dig", []string{"+short", domain, "NS"})
	if nsRes.Skipped {
		return
	}
	var nameservers []string
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		line = strings.TrimRight(strings.TrimSpace(line), ".")
		if line != "" {
			nameservers = append(nameservers, line)
		}
	}
	for _, ns := range nameservers {
		axfrOut, axfrRes := r.RunWithOutput("dig", "dig", []string{
			fmt.Sprintf("@%s", ns), domain, "AXFR",
		})
		if axfrRes.Skipped {
			continue
		}
		if ParseDigAXFR(axfrOut, domain) {
			logInfo("  [!] DNS zone transfer permitted on %s for %s", ns, domain)
			s.Report.AddFinding(Finding{
				Tool: "dig", Host: domain, Category: "DNS",
				Title:    "DNS zone transfer permitted",
				Detail:   fmt.Sprintf("Nameserver %s allowed AXFR for %s", ns, domain),
				Severity: SevHigh,
			})
		}
	}
}

// parseTheHarvesterXML extracts subdomains and emails from theHarvester XML output.
func parseTheHarvesterXML(xmlPath, engDir, domain string) ([]string, error) {
	data, err := os.ReadFile(xmlPath)
	if err != nil {
		return nil, err
	}
	var hosts []string
	var emails []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "<hostname>") && strings.HasSuffix(line, "</hostname>") {
			if h := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "<hostname>"), "</hostname>")); h != "" {
				hosts = append(hosts, h)
			}
		}
		if strings.HasPrefix(line, "<email>") && strings.HasSuffix(line, "</email>") {
			if e := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "<email>"), "</email>")); e != "" {
				emails = append(emails, e)
			}
		}
	}
	if len(emails) > 0 {
		_ = writeLinesToFile(filepath.Join(engDir, "other", "theharvester_emails.txt"), emails)
		logDebug("theHarvester: found %d email addresses for %s", len(emails), domain)
	}
	return hosts, nil
}

// ---- Phase 2: Host Probing and Fingerprinting ------------------------------

func runPhase2(r *Runner, s *RunState) error {
	logInfo("[phase 2] Host Probing & Fingerprinting")
	markPhaseStarted(s.ReconMeta, "phase2")

	otherDir := filepath.Join(s.EngDir, "other")
	if err := ensureDir(otherDir); err != nil {
		return err
	}

	// httpx — bulk probe all hosts (including phase 1 subdomain discoveries in s.AllHosts)
	if !interrupted.Load() {
		// Write the full s.AllHosts list (which includes phase 1 subdomain discoveries)
		// to a probe file so httpx covers every known host, not just the original hosts file.
		probeFile := filepath.Join(otherDir, "httpx_probe_list.txt")
		if err := writeLinesToFile(probeFile, s.AllHosts); err != nil {
			logWarn("httpx: could not write probe list: %v — falling back to hosts file", err)
			probeFile = findHostsFile(s.EngDir)
			if probeFile == "" {
				probeFile = filepath.Join(s.EngDir, "hosts")
			}
		}
		outFile := filepath.Join(otherDir, "httpx.json")
		httpxArgs := append([]string{
			"-l", probeFile, "-o", outFile,
			"-json", "-title", "-tech-detect", "-status-code", "-web-server",
			"-location", "-favicon",
			"-silent",
		}, proxyFlagForTool("httpx", s.Cfg.ProxyURL)...)
		res := r.Run("httpx", "httpx-pd", httpxArgs, outFile)
		if !res.Skipped && res.Err == nil {
			if entries, cms, err := ParseHTTPX(outFile); err == nil {
				for host, cmsType := range cms {
					s.CMSDetected[host] = cmsType
					s.Report.CMSDetected[host] = cmsType
				}
				if len(entries) > 0 {
					// Deduplicate against existing s.HTTPHosts (important when resuming
					// with -from-phase 2 so we don't re-add hosts already in memory).
					seen := make(map[string]struct{}, len(s.HTTPHosts))
					for _, h := range s.HTTPHosts {
						seen[h] = struct{}{}
					}
					var discovered []string
					for _, e := range entries {
						if e.URL == "" {
							continue
						}
						if _, ok := seen[e.URL]; !ok {
							seen[e.URL] = struct{}{}
							discovered = append(discovered, e.URL)
						}
					}
					if len(discovered) > 0 {
						// Apply web scope: if set, only web-test the subset of
						// discovered HTTP services that fall within it.
						webScoped, oos := filterInScope(discovered, s.effectiveWebScope())
						if len(oos) > 0 {
							logInfo("  httpx: %d host(s) excluded from web testing by web scope", len(oos))
						}
						s.HTTPHosts = append(s.HTTPHosts, webScoped...)
						s.Report.HTTPHosts = s.HTTPHosts
						logDebug("httpx discovered %d new live HTTP services (%d in web scope)", len(discovered), len(webScoped))
						_ = writeLinesToFile(filepath.Join(s.EngDir, "http_hosts"), s.HTTPHosts)
					}
				}
			}
		}
		r.Delay()
	}

	// Re-filter http_hosts through current scope before any tool reads it.
	// Matters when resuming with -from-phase 2 after scope changes.
	if _, err := refreshHTTPHostsFile(s); err != nil {
		logWarn("scope: could not refresh http_hosts: %v", err)
	}

	// whatweb — technology fingerprinting + version disclosures
	if !interrupted.Load() {
		outFile := filepath.Join(otherDir, "whatweb.json")
		httpHostsFile := filepath.Join(s.EngDir, "http_hosts")
		whatwebArgs := append([]string{"-i", httpHostsFile, "--log-json=" + outFile, "-q"},
			proxyFlagForTool("whatweb", s.Cfg.ProxyURL)...)
		res := r.Run("whatweb", "whatweb", whatwebArgs, outFile)
		if !res.Skipped && res.Err == nil {
			if _, cms, err := ParseWhatWeb(outFile); err == nil {
				for host, cmsType := range cms {
					if _, exists := s.CMSDetected[host]; !exists {
						s.CMSDetected[host] = cmsType
						s.Report.CMSDetected[host] = cmsType
					}
				}
			}
			if findings, err := ParseWhatWebVersions(outFile); err == nil {
				s.Report.AddFindings(findings)
			}
		}
		r.Delay()
	}

	// wafw00f — WAF detection per HTTP host
	if !interrupted.Load() {
		for _, host := range s.HTTPHosts {
			if interrupted.Load() {
				break
			}
			safe := sanitizeForFilename(host)
			outFile := filepath.Join(otherDir, "wafw00f_"+safe+".json")
			res := r.Run("wafw00f", "wafw00f", []string{"-o", outFile, "-f", "json", host}, outFile)
			if !res.Skipped && res.Err == nil {
				if detected, wafName, err := ParseWafw00f(outFile); err == nil && detected {
					s.WAFDetected[host] = true
					if s.Report.WAFDetected == nil {
						s.Report.WAFDetected = make(map[string]string)
					}
					s.Report.WAFDetected[host] = wafName
					logInfo("  WAF detected on %s: %s", host, wafName)
				}
			}
			r.Delay()
		}
	}

	// gowitness — screenshots of all live HTTP services
	if !interrupted.Load() {
		screenshotsDir := filepath.Join(otherDir, "screenshots")
		if err := ensureDir(screenshotsDir); err == nil {
			httpHostsFile := filepath.Join(s.EngDir, "http_hosts")
			gowitArgs := append([]string{"file", "-f", httpHostsFile, "-P", screenshotsDir, "--no-http"},
				proxyFlagForTool("gowitness", s.Cfg.ProxyURL)...)
			r.Run("gowitness", "gowitness", gowitArgs, "")
			r.Delay()
		}
	}

	// vhost fuzzing — only when root domains are in scope
	if !interrupted.Load() && len(s.Domains) > 0 {
		runVhostFuzzing(r, s)
	}

	if interrupted.Load() {
		markPhaseInterrupted(s.ReconMeta, "phase2", r.CurrentTool())
		return nil
	}

	markPhaseCompleted(s.ReconMeta, "phase2")
	logInfo("  phase 2 complete — %d live HTTP services", len(s.HTTPHosts))
	return nil
}

// ---- Phase 3: Infrastructure Scanning -------------------------------------

func runPhase3(r *Runner, s *RunState, noNessus bool) error {
	logInfo("[phase 3] Infrastructure Scanning")
	markPhaseStarted(s.ReconMeta, "phase3")

	nmapDir := filepath.Join(s.EngDir, "nmap")
	if err := ensureDir(nmapDir); err != nil {
		return err
	}
	otherDir := filepath.Join(s.EngDir, "other")
	if err := ensureDir(otherDir); err != nil {
		return err
	}

	coveredWebPorts := buildCoveredWebPorts(s.HTTPHosts)

	// nmap — two-pass TCP (fast port discovery → detailed scan on open ports)
	// + UDP top-20. IP groups run concurrently (max 3 at a time); hosts within
	// a group run sequentially so the same IP is never hit by parallel scans.
	type nmapResult struct {
		host     string
		findings []Finding
		webPorts []NmapWebPort
	}

	// Group hosts by resolved IP so we only run nmap once per machine. Hosts
	// that share an IP are collected as aliases — nmap is skipped for them but
	// they still receive web-port findings, and all other tools run against
	// them normally in their own phases.
	type ipGroup struct {
		ip      string
		primary string   // the host nmap actually scans
		aliases []string // same machine; nmap skipped, web ports attributed
	}
	var ipOrder []string
	ipGroups := make(map[string]*ipGroup)
	for _, h := range s.AllHosts {
		addrs, err := net.LookupHost(h)
		ip := h // fallback for unresolvable hosts
		if err == nil && len(addrs) > 0 {
			ip = addrs[0]
		}
		if g, exists := ipGroups[ip]; exists {
			g.aliases = append(g.aliases, h)
		} else {
			ipGroups[ip] = &ipGroup{ip: ip, primary: h}
			ipOrder = append(ipOrder, ip)
		}
	}

	// Buffer is large enough for one result per host (primary + all aliases).
	nmapResults := make(chan nmapResult, len(s.AllHosts))
	var udpRootWarnOnce sync.Once
	sem := make(chan struct{}, 3)
	var wg sync.WaitGroup

	for _, ip := range ipOrder {
		group := ipGroups[ip]
		if interrupted.Load() {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(g *ipGroup) {
			defer wg.Done()
			defer func() { <-sem }()

			h := g.primary
			safe := sanitizeForFilename(h)
			var allFindings []Finding
			var webPorts []NmapWebPort

			// Pass 1: fast full-port TCP scan to identify open ports
			// -oA writes <base>.xml, <base>.nmap (human-readable), <base>.gnmap
			tcpFullBase := filepath.Join(nmapDir, "nmap_tcp-fullports_"+safe)
			portRes := r.RunLong("nmap", "nmap", []string{
				"-p-", "--open",
				"-oA", tcpFullBase, h,
			}, "")

			if !portRes.Skipped && portRes.Err == nil {
				openPorts, err := extractOpenPortList(tcpFullBase + ".xml")
				if err == nil && len(openPorts) > 0 {
					// Pass 2: detailed service/version + NSE on open ports only
					tcpSvcBase := filepath.Join(nmapDir, "nmap_tcp-svc_"+safe)
					detailRes := r.RunLong("nmap", "nmap", []string{
						"-sV", "-sC",
						"-p", strings.Join(openPorts, ","),
						"-oA", tcpSvcBase, h,
					}, "")
					if !detailRes.Skipped && detailRes.Err == nil {
						if f, err := ParseNmap(tcpSvcBase+".xml", h); err == nil {
							allFindings = append(allFindings, f...)
						}
						if wp, err := ParseNmapWebPorts(tcpSvcBase + ".xml"); err == nil {
							webPorts = wp
						}
					}
				} else if err == nil {
					logInfo("  nmap: no open ports found on %s", h)
				}
			}

			// UDP top-20 scan
			if !interrupted.Load() {
				udpTop20Base := filepath.Join(nmapDir, "nmap_udp-top20_"+safe)
				udpRes := r.RunLong("nmap", "nmap", []string{
					"-sU", "--top-ports", "20", "-oA", udpTop20Base, h,
				}, "")
				if udpRes.ExitCode != 0 &&
					(strings.Contains(udpRes.Stderr, "root") || strings.Contains(udpRes.Stderr, "privileged")) {
					udpRootWarnOnce.Do(func() {
						logWarn("  UDP scan requires root privileges — skipping (run as root to enable)")
					})
				} else if !udpRes.Skipped && udpRes.Err == nil {
					if f, err := ParseNmap(udpTop20Base+".xml", h); err == nil {
						allFindings = append(allFindings, f...)
					}
				}
			}

			nmapResults <- nmapResult{host: h, findings: allFindings, webPorts: webPorts}

			// Aliases share the same IP — nmap would produce identical results.
			// Skip the scan but attribute any web-port findings to each alias so
			// non-standard port discoveries are recorded against every hostname.
			// All other tools (ferox, nuclei, katana, etc.) run against aliases
			// independently via s.HTTPHosts in their own phases.
			for _, alias := range g.aliases {
				logInfo("  nmap: skipping scan of %s — same IP (%s) as %s; web-port findings attributed, other tools unaffected", alias, g.ip, h)
				nmapResults <- nmapResult{host: alias, findings: nil, webPorts: webPorts}
			}
		}(group)
	}
	wg.Wait()
	close(nmapResults)

	var newWebHosts []string
	for result := range nmapResults {
		s.Report.AddFindings(result.findings)
		for _, wp := range result.webPorts {
			key := fmt.Sprintf("%s:%d", result.host, wp.Port)
			if _, covered := coveredWebPorts[key]; !covered {
				s.Report.AddFinding(Finding{
					Tool:     "nmap",
					Host:     wp.URL(result.host),
					Category: "Network Exposure",
					Title:    fmt.Sprintf("Web service on non-standard port %d", wp.Port),
					Detail:   fmt.Sprintf("nmap identified %s on port %d/%s — adding to web scan targets", strings.TrimSpace(wp.Service), wp.Port, wp.Proto),
					Severity: SevInfo,
				})
				newWebHosts = append(newWebHosts, wp.URL(result.host))
			}
		}
	}

	// Add nmap-discovered non-standard-port web services to s.HTTPHosts so that
	// phases 4+ (ferox, nuclei, katana, nikto, etc.) pick them up automatically.
	if len(newWebHosts) > 0 {
		webScoped, oos := filterInScope(newWebHosts, s.effectiveWebScope())
		if len(oos) > 0 {
			logInfo("  nmap: %d web service(s) excluded from web testing by scope", len(oos))
		}
		existing := make(map[string]struct{}, len(s.HTTPHosts))
		for _, h := range s.HTTPHosts {
			existing[h] = struct{}{}
		}
		var added []string
		for _, h := range webScoped {
			if _, ok := existing[h]; !ok {
				s.HTTPHosts = append(s.HTTPHosts, h)
				added = append(added, h)
			}
		}
		if len(added) > 0 {
			logInfo("  nmap: adding %d non-standard-port web service(s) to scan targets: %s", len(added), strings.Join(added, ", "))
			s.Report.HTTPHosts = s.HTTPHosts
			_ = writeLinesToFile(filepath.Join(s.EngDir, "http_hosts"), s.HTTPHosts)
		}
	}

	// testssl — TLS audit per HTTPS host (sequential, relies on nmap findings being complete)
	for _, host := range s.HTTPHosts {
		if interrupted.Load() {
			break
		}
		if !strings.HasPrefix(host, "https://") {
			continue
		}
		safe := sanitizeForFilename(host)
		outFile := filepath.Join(otherDir, "testssl_"+safe+".json")
		res := r.RunLong("testssl", "testssl", []string{
			"--jsonfile", outFile, "--overwrite", "--quiet", "--color", "0", host,
		}, "")
		if !res.Skipped && res.Err == nil {
			if findings, err := ParseTestSSL(outFile, host); err == nil {
				s.Report.AddFindings(findings)
			}
		}
		r.Delay()
	}

	if !interrupted.Load() {
		runNessusPhase(s)
	}

	if interrupted.Load() {
		markPhaseInterrupted(s.ReconMeta, "phase3", r.CurrentTool())
		return nil
	}

	markPhaseCompleted(s.ReconMeta, "phase3")
	return nil
}

// buildCoveredWebPorts returns a "host:port" set of web services already being tested.
// refreshHTTPHostsFile reads http_hosts from disk, re-filters it through the
// effective web scope, and rewrites the file if any entries were removed.
// Returns the (possibly pruned) host list. Safe to call when the file does not
// yet exist — returns nil, nil in that case.
// This guards against stale entries when the user resumes with -from-phase N
// after scope.txt or web_scope.txt has changed.
func refreshHTTPHostsFile(s *RunState) ([]string, error) {
	path := filepath.Join(s.EngDir, "http_hosts")
	raw, err := readLines(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	inScope, oos := filterInScope(raw, s.effectiveWebScope())
	if len(oos) > 0 {
		logWarn("scope: removed %d out-of-scope host(s) from http_hosts before scanning", len(oos))
		if err := writeLinesToFile(path, inScope); err != nil {
			return nil, fmt.Errorf("rewriting http_hosts: %w", err)
		}
	}
	return inScope, nil
}

func buildCoveredWebPorts(httpHosts []string) map[string]struct{} {
	covered := make(map[string]struct{})
	for _, h := range httpHosts {
		scheme := "http"
		rest := h
		if strings.HasPrefix(h, "https://") {
			scheme = "https"
			rest = strings.TrimPrefix(h, "https://")
		} else if strings.HasPrefix(h, "http://") {
			rest = strings.TrimPrefix(h, "http://")
		}
		rest = strings.TrimSuffix(rest, "/")
		if idx := strings.LastIndex(rest, ":"); idx != -1 {
			if port, err := strconv.Atoi(rest[idx+1:]); err == nil {
				covered[fmt.Sprintf("%s:%d", rest[:idx], port)] = struct{}{}
				continue
			}
		}
		defaultPort := 80
		if scheme == "https" {
			defaultPort = 443
		}
		covered[fmt.Sprintf("%s:%d", rest, defaultPort)] = struct{}{}
	}
	return covered
}

func runNessusPhase(s *RunState) {
	if s.NoNessus {
		s.ReconMeta.NessusSkipped = true
		s.ReconMeta.NessusSkipReason = "flag"
		logInfo("  nessus: skipped (-no-nessus flag)")
		return
	}
	if !s.Cfg.nessusEnabled() {
		s.ReconMeta.NessusSkipped = true
		s.ReconMeta.NessusSkipReason = "no credentials"
		logInfo("  nessus: skipped — no API credentials configured")
		return
	}
	if s.Cfg.NessusTemplateUUID == "" {
		s.ReconMeta.NessusSkipped = true
		s.ReconMeta.NessusSkipReason = "no template UUID"
		logWarn("nessus: skipped — nessus_template_uuid not configured")
		return
	}

	nessusFile, err := RunNessusScan(s.Cfg, s.EngDir, s.EngMeta.Name, s.AllHosts, s.ReconMeta)
	if err != nil {
		logWarn("nessus scan failed: %v", err)
		return
	}
	if nessusFile == "" {
		return
	}

	reportItems, lowInfo, err := ParseNessusXML(nessusFile)
	if err != nil {
		logWarn("parsing nessus output: %v", err)
		return
	}

	for _, item := range reportItems {
		sev := SevMedium
		switch item.Severity {
		case 4:
			sev = SevCritical
		case 3:
			sev = SevHigh
		case 2:
			sev = SevMedium
		}
		s.Report.AddFinding(Finding{
			Tool: "nessus", Host: item.Host, Category: "Vulnerability Scan",
			Title: item.PluginName, Detail: item.Synopsis, Severity: sev,
		})
	}

	nessusDir := filepath.Join(s.EngDir, "nessus")
	writeNessusJSON(filepath.Join(nessusDir, "nessus_results.json"), reportItems)
	writeNessusJSON(filepath.Join(nessusDir, "nessus_low_info.json"), lowInfo)
	logInfo("  nessus: %d reportable findings, %d low/info (see nessus/)", len(reportItems), len(lowInfo))
}

func writeNessusJSON(path string, items []NessusItem) {
	_ = ensureDir(filepath.Dir(path))
	data, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0644)
}

// ---- Phase 4: Web Content Discovery and Crawling ---------------------------

func runPhase4(r *Runner, s *RunState) error {
	logInfo("[phase 4] Web Content Discovery & Crawling")
	markPhaseStarted(s.ReconMeta, "phase4")

	otherDir := filepath.Join(s.EngDir, "other")

	// katana + feroxbuster run concurrently per host (max 2 pairs at a time)
	sem := make(chan struct{}, 2)
	var wg sync.WaitGroup

	for _, host := range s.HTTPHosts {
		if interrupted.Load() {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()
			safe := sanitizeForFilename(h)

			// katana — active crawl, depth 5
			katanaOut := filepath.Join(otherDir, "katana_"+safe+".json")
			katanaArgs := append([]string{
				"-u", h, "-rate-limit", "20", "-o", katanaOut,
				"-jc", "-kf", "all", "-d", "5", "-silent",
			}, proxyFlagForTool("katana", s.Cfg.ProxyURL)...)
			katanaRes := r.Run("katana", "katana", katanaArgs, katanaOut)
			if !katanaRes.Skipped && katanaRes.Err == nil {
				if endpoints, err := readLines(katanaOut); err == nil {
					inScope, oos := filterEndpointsInScope(endpoints, s.Scope)
					if len(oos) > 0 {
						logInfo("  katana: filtered %d out-of-scope URLs", len(oos))
					}
					_ = writeDiscoveredEndpoints(s.EngDir, inScope)
				}
			}

			// feroxbuster — directory + extension brute-force
			if !interrupted.Load() {
				feroxOut := filepath.Join(otherDir, "feroxbuster_"+safe+".json")
				feroxArgs := append([]string{
					"-u", h,
					"-w", s.Cfg.Wordlist,
					"-x", "php,asp,aspx,jsp,txt,bak,old,conf,config,log",
					"-o", feroxOut, "--json", "-q", "--no-state",
					"--threads", strconv.Itoa(s.Cfg.FeroxThreads),
					"--extract-links",
				}, proxyFlagForTool("feroxbuster", s.Cfg.ProxyURL)...)
				feroxRes := r.RunLong("feroxbuster", "feroxbuster", feroxArgs, feroxOut)
				if !feroxRes.Skipped && feroxRes.Err == nil {
					if findings, err := ParseFeroxbuster(feroxOut, h); err == nil {
						s.Report.AddFindings(findings)
					}
				}
			}
		}(host)
	}
	wg.Wait()
	r.Delay()

	// waybackurls AND gau — both run for maximum historical URL coverage
	for _, domain := range s.Domains {
		if interrupted.Load() {
			break
		}
		safe := sanitizeForFilename(domain)

		waybackOut := filepath.Join(otherDir, "waybackurls_"+safe+".txt")
		res := r.Run("waybackurls", "waybackurls", []string{domain}, waybackOut)
		if !res.Skipped && res.Err == nil {
			if endpoints, err := readLines(waybackOut); err == nil {
				inScope, oos := filterEndpointsInScope(endpoints, s.Scope)
				if len(oos) > 0 {
					logInfo("  waybackurls: filtered %d out-of-scope URLs", len(oos))
				}
				_ = writeDiscoveredEndpoints(s.EngDir, inScope)
			}
		}
		r.Delay()

		if !interrupted.Load() {
			gauOut := filepath.Join(otherDir, "gau_"+safe+".txt")
			gauRes := r.Run("gau", "gau", []string{domain, "--o", gauOut}, gauOut)
			if !gauRes.Skipped && gauRes.Err == nil {
				if endpoints, err := readLines(gauOut); err == nil {
					inScope, oos := filterEndpointsInScope(endpoints, s.Scope)
					if len(oos) > 0 {
						logInfo("  gau: filtered %d out-of-scope URLs", len(oos))
					}
					_ = writeDiscoveredEndpoints(s.EngDir, inScope)
				}
			}
			r.Delay()
		}
	}

	// well-known URLs — robots.txt, sitemap, security.txt
	for _, host := range s.HTTPHosts {
		if interrupted.Load() {
			break
		}
		runWellKnown(r, s, host, otherDir)
		r.Delay()
	}

	// API surface enumeration — common API roots, OpenAPI/Swagger docs, GraphQL
	for _, host := range s.HTTPHosts {
		if interrupted.Load() {
			break
		}
		runAPISurface(r, s, host, otherDir)
		r.Delay()
	}

	// Auth and OAuth endpoint discovery
	for _, host := range s.HTTPHosts {
		if interrupted.Load() {
			break
		}
		runAuthSurface(r, s, host, otherDir)
		r.Delay()
	}

	// arjun — hidden parameter discovery (intrusive)
	if s.AllowIntrusive && !interrupted.Load() {
		for _, host := range s.HTTPHosts {
			if interrupted.Load() {
				break
			}
			safe := sanitizeForFilename(host)
			outFile := filepath.Join(otherDir, "arjun_"+safe+".json")
			r.Run("arjun", "arjun", []string{"-u", host, "-oJ", outFile}, "")
			r.Delay()
		}
	}

	// SSRF and open redirect surface mapping — post-processing, no new requests
	if !interrupted.Load() {
		buildSSRFSurface(s.EngDir, otherDir)
	}

	if interrupted.Load() {
		markPhaseInterrupted(s.ReconMeta, "phase4", r.CurrentTool())
		return nil
	}

	markPhaseCompleted(s.ReconMeta, "phase4")
	return nil
}

// ---- Phase 5: Vulnerability Scanning --------------------------------------

func runPhase5(r *Runner, s *RunState) error {
	logInfo("[phase 5] Vulnerability Scanning")
	markPhaseStarted(s.ReconMeta, "phase5")

	otherDir := filepath.Join(s.EngDir, "other")

	// nuclei — template-based scanning with redirect following and retries
	if !interrupted.Load() {
		httpHostsFile := filepath.Join(s.EngDir, "http_hosts")
		outFile := filepath.Join(otherDir, "nuclei.json")

		// Re-filter http_hosts through current scope before invoking nuclei.
		// Stale entries from a prior run with a wider scope must not reach nuclei.
		scoped, err := refreshHTTPHostsFile(s)
		if err != nil {
			logWarn("nuclei: could not refresh http_hosts: %v — skipping", err)
		} else if len(scoped) == 0 {
			logInfo("nuclei: no in-scope HTTP hosts — skipping")
		} else {
			nucleiArgs := []string{
				"-l", httpHostsFile,
				"-severity", "critical,high,medium",
				"-exclude-tags", "exploit,dos",
				"-je", outFile,
				"-follow-redirects",
				"-retries", "2",
				"-silent",
			}
			if !s.AllowIntrusive {
				nucleiArgs = append(nucleiArgs, "-exclude-tags", "fuzz")
			}
			if s.Cfg.NucleiTemplates != "" {
				if _, err := os.Stat(s.Cfg.NucleiTemplates); err == nil {
					nucleiArgs = append(nucleiArgs, "-t", s.Cfg.NucleiTemplates)
				} else {
					logWarn("nuclei: templates dir %q not found — using nuclei built-in templates", s.Cfg.NucleiTemplates)
				}
			}
			nucleiArgs = append(nucleiArgs, proxyFlagForTool("nuclei", s.Cfg.ProxyURL)...)

			res := r.RunLong("nuclei", "nuclei", nucleiArgs, outFile)
			if !res.Skipped && res.Err == nil {
				if findings, err := ParseNuclei(outFile, ""); err == nil {
					s.Report.AddFindings(findings)
				}
			}
			r.Delay()
		}
	}

	// nikto — one per HTTP host
	if !interrupted.Load() {
		for _, host := range s.HTTPHosts {
			if interrupted.Load() {
				break
			}
			safe := sanitizeForFilename(host)
			outFile := filepath.Join(otherDir, "nikto_"+safe+".txt")
			niktoArgs := append([]string{"-h", host, "-o", outFile, "-Format", "txt", "-Pause", "1"},
				proxyFlagForTool("nikto", s.Cfg.ProxyURL)...)
			res := r.RunLong("nikto", "nikto", niktoArgs, outFile)
			if !res.Skipped && res.Err == nil {
				if findings, err := ParseNikto(outFile, host); err == nil {
					s.Report.AddFindings(findings)
				}
			}
			r.Delay()
		}
	}

	if !interrupted.Load() {
		runCMSScanners(r, s)
	}

	if interrupted.Load() {
		markPhaseInterrupted(s.ReconMeta, "phase5", r.CurrentTool())
		return nil
	}

	markPhaseCompleted(s.ReconMeta, "phase5")
	return nil
}

func runCMSScanners(r *Runner, s *RunState) {
	otherDir := filepath.Join(s.EngDir, "other")

	for host, cmsType := range s.CMSDetected {
		if interrupted.Load() {
			break
		}
		safe := sanitizeForFilename(host)
		switch cmsType {
		case "wordpress":
			if s.Cfg.WPScanAPIToken == "" {
				logWarn("  wpscan: WordPress detected on %s but no API token configured — vulnerability database lookup disabled (set wpscan_api_token in config)", host)
			}
			outFile := filepath.Join(otherDir, "wpscan_"+safe+".json")
			wpscanArgs := []string{
				"--url", host,
				"--output", outFile, "--format", "json", "--no-banner",
				"--enumerate", "vp,vt,u,cb,dbe",
			}
			if s.Cfg.WPScanAPIToken != "" {
				wpscanArgs = append(wpscanArgs, "--api-token", s.Cfg.WPScanAPIToken)
			}
			wpscanArgs = append(wpscanArgs, proxyFlagForTool("wpscan", s.Cfg.ProxyURL)...)
			r.RunLong("wpscan", "wpscan", wpscanArgs, "")
		case "joomla":
			outFile := filepath.Join(otherDir, "joomscan_"+safe+".txt")
			r.Run("joomscan", "joomscan", []string{"-u", host, "-ec", "-o", outFile}, outFile)
		case "drupal":
			outFile := filepath.Join(otherDir, "droopescan_"+safe+".json")
			r.Run("droopescan", "droopescan", []string{"scan", "drupal", "-u", host, "--output", "json"}, outFile)
		}
		r.Delay()
	}
}

// ---- Phase 6: JavaScript and Secrets Analysis ------------------------------

func runPhase6(r *Runner, s *RunState) error {
	logInfo("[phase 6] JavaScript & Secrets Analysis")
	markPhaseStarted(s.ReconMeta, "phase6")

	otherDir := filepath.Join(s.EngDir, "other")

	// Re-filter http_hosts through current scope before any tool reads it.
	// Matters when resuming with -from-phase 6 after scope changes.
	if _, err := refreshHTTPHostsFile(s); err != nil {
		logWarn("scope: could not refresh http_hosts: %v", err)
	}

	// subjs — extract JS URLs from all discovered endpoints
	jsURLsFile := filepath.Join(otherDir, "js_urls.txt")
	if !interrupted.Load() {
		jsInputFile := filepath.Join(s.EngDir, "discovered_endpoints")
		if lines, _ := readLines(jsInputFile); len(lines) == 0 {
			jsInputFile = filepath.Join(s.EngDir, "http_hosts")
		}
		r.Run("subjs", "subjs", []string{"-i", jsInputFile, "-o", jsURLsFile}, jsURLsFile)
		r.Delay()
	}

	// linkfinder — extract endpoints from JS files
	if !interrupted.Load() {
		if jsURLs, err := readLines(jsURLsFile); err == nil && len(jsURLs) > 0 {
			linkfinderOut := filepath.Join(otherDir, "linkfinder_endpoints.txt")
			if f, err := os.Create(linkfinderOut); err == nil {
				f.Close()
				for _, jsURL := range jsURLs {
					if interrupted.Load() {
						break
					}
					stdout, res := r.RunWithOutput("linkfinder", "linkfinder", []string{"-i", jsURL, "-o", "cli"})
					if !res.Skipped && res.Err == nil {
						appendToFile(linkfinderOut, stdout)
						if endpoints, err := parseEndpointLines(stdout); err == nil {
							inScope, oos := filterEndpointsInScope(endpoints, s.Scope)
							if len(oos) > 0 {
								logInfo("  linkfinder: filtered %d out-of-scope endpoints", len(oos))
							}
							_ = writeDiscoveredEndpoints(s.EngDir, inScope)
						}
					}
					r.Delay()
				}
			}
		}
	}

	// JS source map detection — check for .map files alongside discovered .js URLs
	if !interrupted.Load() {
		if jsURLs, err := readLines(jsURLsFile); err == nil && len(jsURLs) > 0 {
			checkJSSourceMaps(r, s, jsURLs)
		}
	}

	// Secrets scanning — gitleaks first, trufflehog as fallback
	if !interrupted.Load() {
		secretsOut := filepath.Join(otherDir, "secrets_unverified.json")
		gitleaksOut := filepath.Join(otherDir, "gitleaks.json")
		gRes := r.Run("gitleaks", "gitleaks", []string{
			"detect", "--source", s.EngDir,
			"--report-format", "json", "--report-path", gitleaksOut,
		}, "")
		if !gRes.Skipped {
			if findings, err := ParseGitleaks(gitleaksOut, ""); err == nil {
				s.Report.AddFindings(findings)
			}
		} else {
			trufflehogOut := filepath.Join(otherDir, "trufflehog.json")
			tRes := r.Run("trufflehog", "trufflehog", []string{"filesystem", s.EngDir, "--json"}, trufflehogOut)
			if !tRes.Skipped && tRes.Err == nil {
				if findings, err := ParseTrufflehog(trufflehogOut, ""); err == nil {
					var unverified []Finding
					for _, f := range findings {
						if f.Suppress {
							unverified = append(unverified, f)
						} else {
							s.Report.AddFinding(f)
						}
					}
					if len(unverified) > 0 {
						data, _ := json.MarshalIndent(unverified, "", "  ")
						_ = os.WriteFile(secretsOut, data, 0644)
					}
				}
			}
		}
		r.Delay()
	}

	// trufflehog GitHub — scan configured orgs for leaked secrets
	if !interrupted.Load() && len(s.Cfg.GithubOrgs) > 0 {
		runTrufflehogGitHub(r, s)
	}

	// GitHub code dorking — search public code for domain references + sensitive keywords
	if !interrupted.Load() {
		runGitdorks(r, s)
	}

	if interrupted.Load() {
		markPhaseInterrupted(s.ReconMeta, "phase6", r.CurrentTool())
		return nil
	}

	markPhaseCompleted(s.ReconMeta, "phase6")
	return nil
}

// checkJSSourceMaps checks whether .map files exist alongside discovered JS URLs.
// Checks the first 50 .js URLs to avoid excessive requests.
func checkJSSourceMaps(r *Runner, s *RunState, jsURLs []string) {
	checked := 0
	seen := make(map[string]struct{})
	for _, jsURL := range jsURLs {
		if checked >= 50 || interrupted.Load() {
			break
		}
		if !strings.HasSuffix(strings.ToLower(jsURL), ".js") {
			continue
		}
		mapURL := jsURL + ".map"
		if _, ok := seen[mapURL]; ok {
			continue
		}
		seen[mapURL] = struct{}{}

		stdout, res := r.RunWithOutput("curl", "curl", []string{
			"-s", "-o", "/dev/null", "-w", "%{http_code}",
			"-m", "5", "--max-redirs", "3", mapURL,
		})
		if res.Skipped {
			break
		}
		if strings.TrimSpace(stdout) == "200" {
			host := urlHost(mapURL)
			s.Report.AddFinding(Finding{
				Tool: "curl", Host: host, Category: "Information Disclosure",
				Title:    "JavaScript source map exposed",
				Detail:   fmt.Sprintf("Source map accessible at %s — original application source code may be recoverable", mapURL),
				Severity: SevMedium,
			})
		}
		checked++
	}
}

// ---- Phase 7: Security Headers ---------------------------------------------

func runPhase7(r *Runner, s *RunState) error {
	logInfo("[phase 7] Security Headers & Exposure")
	markPhaseStarted(s.ReconMeta, "phase7")

	otherDir := filepath.Join(s.EngDir, "other")
	if err := ensureDir(otherDir); err != nil {
		return err
	}

	for _, host := range s.HTTPHosts {
		if interrupted.Load() {
			break
		}
		safe := sanitizeForFilename(host)

		// Response headers check
		outFile := filepath.Join(otherDir, "headers_"+safe+".txt")
		curlArgs := append([]string{"-s", "-I", "-m", "10", "--max-redirs", "5", "-L", host},
			proxyFlagForTool("curl", s.Cfg.ProxyURL)...)
		res := r.Run("curl", "curl", curlArgs, outFile)
		if !res.Skipped && res.Err == nil {
			if sh, findings, err := ParseSecurityHeaders(outFile, host); err == nil {
				s.Report.AddFindings(findings)
				writeRateLimitSummary(sh, otherDir)
			}
		}
		r.Delay()

		// HTTP methods check
		if !interrupted.Load() {
			checkHTTPMethods(r, s, host)
			r.Delay()
		}

		// CORS misconfiguration check
		if !interrupted.Load() {
			checkCORSMisconfiguration(r, s, host)
			r.Delay()
		}
	}

	if interrupted.Load() {
		markPhaseInterrupted(s.ReconMeta, "phase7", r.CurrentTool())
		return nil
	}

	markPhaseCompleted(s.ReconMeta, "phase7")
	return nil
}

// checkHTTPMethods probes OPTIONS and flags dangerous methods (PUT, DELETE, TRACE).
func checkHTTPMethods(r *Runner, s *RunState, host string) {
	stdout, res := r.RunWithOutput("curl", "curl", []string{
		"-s", "-X", "OPTIONS", "-i", "-m", "10", "--max-redirs", "3", host,
	})
	if res.Skipped || res.Err != nil {
		return
	}
	var allowedMethods []string
	for _, line := range strings.Split(stdout, "\n") {
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lower, "allow:") {
			raw := strings.TrimSpace(line[strings.Index(line, ":")+1:])
			for _, m := range strings.Split(raw, ",") {
				if m = strings.TrimSpace(strings.ToUpper(m)); m != "" {
					allowedMethods = append(allowedMethods, m)
				}
			}
		}
	}
	var dangerous []string
	for _, m := range allowedMethods {
		switch m {
		case "PUT", "DELETE", "TRACE", "CONNECT", "TRACK":
			dangerous = append(dangerous, m)
		}
	}
	if len(dangerous) == 0 {
		return
	}
	sev := SevMedium
	for _, m := range dangerous {
		if m == "PUT" || m == "DELETE" {
			sev = SevHigh
			break
		}
	}
	s.Report.AddFinding(Finding{
		Tool: "curl", Host: host, Category: "Web Configuration",
		Title:    fmt.Sprintf("Dangerous HTTP methods enabled: %s", strings.Join(dangerous, ", ")),
		Detail:   fmt.Sprintf("OPTIONS Allow header returned: %s", strings.Join(allowedMethods, ", ")),
		Severity: sev,
	})
}

// checkCORSMisconfiguration tests for arbitrary-origin reflection and credential exposure.
func checkCORSMisconfiguration(r *Runner, s *RunState, host string) {
	stdout, res := r.RunWithOutput("curl", "curl", []string{
		"-s", "-I", "-m", "10",
		"-H", "Origin: https://evil.example.com",
		host,
	})
	if res.Skipped || res.Err != nil {
		return
	}
	var acaoValue, acacValue string
	for _, line := range strings.Split(stdout, "\n") {
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lower, "access-control-allow-origin:") {
			acaoValue = strings.TrimSpace(line[strings.Index(line, ":")+1:])
		}
		if strings.HasPrefix(lower, "access-control-allow-credentials:") {
			acacValue = strings.TrimSpace(line[strings.Index(line, ":")+1:])
		}
	}
	if acaoValue == "" {
		return
	}
	credentials := strings.ToLower(acacValue) == "true"
	switch {
	case acaoValue == "https://evil.example.com" && credentials:
		s.Report.AddFinding(Finding{
			Tool: "curl", Host: host, Category: "CORS",
			Title:    "CORS: arbitrary origin reflected with credentials",
			Detail:   "Server reflects attacker-controlled Origin in Access-Control-Allow-Origin and sets Allow-Credentials: true — allows cross-origin authenticated requests from any domain",
			Severity: SevHigh,
		})
	case acaoValue == "https://evil.example.com":
		s.Report.AddFinding(Finding{
			Tool: "curl", Host: host, Category: "CORS",
			Title:    "CORS: arbitrary origin reflected",
			Detail:   "Server reflects attacker-controlled Origin in Access-Control-Allow-Origin — review whether sensitive data is exposed cross-origin",
			Severity: SevMedium,
		})
	case acaoValue == "*" && credentials:
		s.Report.AddFinding(Finding{
			Tool: "curl", Host: host, Category: "CORS",
			Title:    "CORS: wildcard origin with credentials header",
			Detail:   "Access-Control-Allow-Origin: * combined with Allow-Credentials: true is invalid per spec — may indicate misconfigured CORS policy",
			Severity: SevLow,
		})
	}
}

// ---- Auth and OAuth endpoint discovery --------------------------------------

var authProbePaths = []string{
	"/login", "/signin", "/sign-in", "/log-in",
	"/logout", "/signout", "/sign-out", "/log-out",
	"/register", "/signup", "/sign-up",
	"/auth", "/auth/login", "/auth/callback", "/auth/token",
	"/oauth", "/oauth/authorize", "/oauth/token", "/oauth/callback", "/oauth/revoke",
	"/oauth2", "/oauth2/authorize", "/oauth2/token", "/oauth2/callback",
	"/saml", "/saml/sso", "/saml/acs", "/saml/metadata",
	"/sso", "/sso/login", "/sso/callback",
	"/account/login", "/account/signin", "/user/login",
	"/admin", "/admin/login", "/administrator",
	"/forgot-password", "/reset-password", "/password/reset",
	"/mfa", "/2fa", "/two-factor",
}

var oidcWellKnownPaths = []string{
	"/.well-known/openid-configuration",
	"/.well-known/oauth-authorization-server",
	"/.well-known/jwks.json",
}

// runAuthSurface probes a host for authentication endpoints and OAuth/OIDC
// well-known documents. Results are written to other/auth_endpoints_<host>.txt
// and appended to discovered_endpoints.
func runAuthSurface(r *Runner, s *RunState, host, otherDir string) {
	safe := sanitizeForFilename(host)
	base := strings.TrimRight(host, "/")
	outFile := filepath.Join(otherDir, "auth_endpoints_"+safe+".txt")

	proxyArgs := proxyFlagForTool("curl", s.Cfg.ProxyURL)
	var found []string

	// Probe common auth paths
	for _, p := range authProbePaths {
		url := base + p
		stdout, res := r.RunWithOutput("curl", "curl", append([]string{
			"-s", "-o", "/dev/null", "-w", "%{http_code}",
			"-m", "10", "--max-redirs", "3", url,
		}, proxyArgs...))
		if res.Skipped || res.Err != nil {
			continue
		}
		code := strings.TrimSpace(stdout)
		switch code {
		case "200", "301", "302", "401", "403":
			found = append(found, fmt.Sprintf("%s  [HTTP %s]", url, code))
		}
	}

	// Fetch and parse OIDC/OAuth well-known documents
	for _, p := range oidcWellKnownPaths {
		url := base + p
		body, res := r.RunWithOutput("curl", "curl", append([]string{
			"-s", "-m", "10", "-L", "--max-redirs", "3", url,
		}, proxyArgs...))
		if res.Skipped || res.Err != nil || strings.TrimSpace(body) == "" {
			continue
		}
		bodyLower := strings.ToLower(strings.TrimSpace(body))
		if strings.HasPrefix(bodyLower, "<!doctype") || strings.HasPrefix(bodyLower, "<html") {
			continue
		}

		// Parse JSON for known endpoint keys
		var doc map[string]interface{}
		if err := json.Unmarshal([]byte(body), &doc); err != nil {
			continue
		}

		oidcKeys := []string{
			"authorization_endpoint", "token_endpoint", "userinfo_endpoint",
			"jwks_uri", "revocation_endpoint", "introspection_endpoint",
			"end_session_endpoint", "registration_endpoint",
		}
		var extracted []string
		for _, key := range oidcKeys {
			if v, ok := doc[key].(string); ok && v != "" {
				extracted = append(extracted, fmt.Sprintf("  %s: %s", key, v))
				found = append(found, fmt.Sprintf("%s  [from %s]", v, p))
			}
		}

		if len(extracted) > 0 {
			logInfo("  auth: %s — OIDC/OAuth config found at %s (%d endpoints)", host, p, len(extracted))
			s.Report.AddFinding(Finding{
				Tool:     "curl",
				Host:     host,
				Category: "Auth Surface",
				Title:    fmt.Sprintf("OIDC/OAuth configuration discovered at %s", p),
				Detail:   fmt.Sprintf("Endpoints extracted:\n%s", strings.Join(extracted, "\n")),
				Severity: SevInfo,
			})
		}
	}

	if len(found) == 0 {
		return
	}

	logInfo("  auth: %d auth surface entries found for %s", len(found), host)
	header := fmt.Sprintf("# Auth Surface — %s\n# Login, auth, OAuth, and OIDC endpoints\n\n", host)
	_ = os.WriteFile(outFile, []byte(header+strings.Join(found, "\n")+"\n"), 0644)

	var urls []string
	for _, line := range found {
		if parts := strings.Fields(line); len(parts) > 0 {
			urls = append(urls, parts[0])
		}
	}
	inScopeURLs, oos := filterEndpointsInScope(urls, s.Scope)
	if len(oos) > 0 {
		logInfo("  auth: filtered %d out-of-scope endpoints (e.g. external OIDC provider URLs)", len(oos))
	}
	_ = writeDiscoveredEndpoints(s.EngDir, inScopeURLs)
}

// ---- API surface enumeration ------------------------------------------------

// apiProbePaths are the paths probed on every live HTTP host. A 200 or 401
// response indicates the path exists — 401 is included because protected API
// roots still confirm the surface is present.
var apiProbePaths = []string{
	"/api", "/api/v1", "/api/v2", "/api/v3",
	"/rest", "/rest/v1", "/rest/v2",
	"/v1", "/v2", "/v3",
	"/graphql", "/graphiql", "/playground",
	"/swagger", "/swagger.json", "/swagger.yaml",
	"/swagger-ui.html", "/swagger-ui/",
	"/api-docs", "/api-docs.json",
	"/openapi.json", "/openapi.yaml", "/openapi/",
	"/docs", "/redoc",
}

// swaggerPathFields are the JSON keys in an OpenAPI/Swagger spec that contain
// endpoint path definitions.
var reSwaggerPath = regexp.MustCompile(`"(/[^"]+)"\s*:\s*\{`)

// graphqlIntrospectionQuery is the minimal query used to detect a live
// GraphQL endpoint. It requests only __typename which every compliant
// implementation must return, minimising server-side cost.
const graphqlIntrospectionQuery = `{"query":"{__typename}"}`

// runAPISurface probes a host for API roots, OpenAPI/Swagger documentation,
// and GraphQL endpoints. Discovered endpoints are appended to discovered_endpoints
// and written to other/api_endpoints_<host>.txt.
func runAPISurface(r *Runner, s *RunState, host, otherDir string) {
	safe := sanitizeForFilename(host)
	base := strings.TrimRight(host, "/")
	outFile := filepath.Join(otherDir, "api_endpoints_"+safe+".txt")

	var found []string
	var graphqlEndpoints []string

	proxyArgs := proxyFlagForTool("curl", s.Cfg.ProxyURL)

	for _, p := range apiProbePaths {
		url := base + p

		// Use -o /dev/null -w "%{http_code}" to get only the status code
		stdout, res := r.RunWithOutput("curl", "curl", append([]string{
			"-s", "-o", "/dev/null", "-w", "%{http_code}",
			"-m", "10", "-L", "--max-redirs", "3", url,
		}, proxyArgs...))
		if res.Skipped || res.Err != nil {
			continue
		}
		code := strings.TrimSpace(stdout)
		if code != "200" && code != "401" && code != "403" {
			continue
		}

		found = append(found, fmt.Sprintf("%s  [HTTP %s]", url, code))

		// If it looks like a Swagger/OpenAPI spec, fetch and parse it
		if code == "200" && (strings.HasSuffix(p, ".json") || strings.HasSuffix(p, ".yaml") ||
			strings.Contains(p, "swagger") || strings.Contains(p, "openapi") || strings.Contains(p, "api-docs")) {
			body, res2 := r.RunWithOutput("curl", "curl", append([]string{
				"-s", "-m", "15", "-L", "--max-redirs", "3", url,
			}, proxyArgs...))
			if res2.Skipped || res2.Err != nil {
				continue
			}
			paths := reSwaggerPath.FindAllStringSubmatch(body, -1)
			for _, m := range paths {
				ep := base + m[1]
				found = append(found, fmt.Sprintf("%s  [from OpenAPI spec]", ep))
			}
			if len(paths) > 0 {
				logInfo("  api: %s — %d endpoints extracted from OpenAPI spec at %s", host, len(paths), p)
			}
		}

		// Track GraphQL paths for introspection
		if strings.Contains(p, "graphql") || strings.Contains(p, "graphiql") || strings.Contains(p, "playground") {
			if code == "200" || code == "400" {
				graphqlEndpoints = append(graphqlEndpoints, url)
			}
		}
	}

	// GraphQL introspection — POST {__typename} to confirm endpoint is live
	for _, gqlURL := range graphqlEndpoints {
		stdout, res := r.RunWithOutput("curl", "curl", append([]string{
			"-s", "-m", "10", "-X", "POST",
			"-H", "Content-Type: application/json",
			"-d", graphqlIntrospectionQuery,
			gqlURL,
		}, proxyArgs...))
		if res.Skipped || res.Err != nil {
			continue
		}
		if strings.Contains(stdout, `"data"`) && strings.Contains(stdout, `__typename`) {
			s.Report.AddFinding(Finding{
				Tool:     "curl",
				Host:     host,
				Category: "API Surface",
				Title:    "GraphQL endpoint identified",
				Detail:   fmt.Sprintf("Endpoint: %s — responds to {__typename} introspection. Verify whether full schema introspection is enabled (should be disabled in production).", gqlURL),
				Severity: SevInfo,
			})
			logInfo("  api: GraphQL endpoint confirmed at %s", gqlURL)
		}
	}

	if len(found) == 0 {
		return
	}

	logInfo("  api: %d API surface entries found for %s", len(found), host)
	header := fmt.Sprintf("# API Surface — %s\n# Paths returning HTTP 200/401/403 or extracted from OpenAPI specs\n\n", host)
	_ = os.WriteFile(outFile, []byte(header+strings.Join(found, "\n")+"\n"), 0644)

	// Extract just the URLs (strip the annotation) for discovered_endpoints
	var urls []string
	for _, line := range found {
		if parts := strings.Fields(line); len(parts) > 0 {
			urls = append(urls, parts[0])
		}
	}
	inScopeURLs, oos := filterEndpointsInScope(urls, s.Scope)
	if len(oos) > 0 {
		logInfo("  api: filtered %d out-of-scope endpoints (e.g. absolute URLs from OpenAPI specs)", len(oos))
	}
	_ = writeDiscoveredEndpoints(s.EngDir, inScopeURLs)
}

// ---- SSRF / open redirect surface mapping -----------------------------------

var ssrfParamNames = map[string]struct{}{
	"url": {}, "uri": {}, "path": {}, "dest": {}, "destination": {},
	"target": {}, "proxy": {}, "host": {}, "endpoint": {}, "redirect_to": {},
	"callback": {}, "webhook": {}, "fetch": {}, "load": {}, "source": {},
	"src": {}, "img": {}, "image": {}, "file": {}, "document": {},
	"page": {}, "feed": {}, "data": {}, "resource": {}, "link": {},
}

var redirectParamNames = map[string]struct{}{
	"redirect": {}, "return": {}, "next": {}, "continue": {}, "goto": {},
	"back": {}, "redir": {}, "returnurl": {}, "returnto": {}, "successurl": {},
	"failurl": {}, "cancelurl": {}, "forward": {}, "location": {}, "ref": {},
	"referrer": {}, "url": {}, "to": {},
}

// reURLParam matches query-string parameter names from a URL.
var reURLParam = regexp.MustCompile(`[?&]([^=&#+]+)=`)

// buildSSRFSurface walks discovered_endpoints and arjun output files looking
// for parameter names that match known SSRF or open redirect patterns. Matching
// URLs are written to other/ssrf_surface.txt and other/redirect_surface.txt.
// No HTTP requests are made — this is purely string matching on existing data.
func buildSSRFSurface(engDir, otherDir string) {
	endpoints, _ := readLines(filepath.Join(engDir, "discovered_endpoints"))

	// Also pull in arjun output (JSON: map of url -> []param)
	arjunFiles, _ := filepath.Glob(filepath.Join(otherDir, "arjun_*.json"))
	for _, f := range arjunFiles {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var arjun map[string][]string
		if err := json.Unmarshal(data, &arjun); err != nil {
			continue
		}
		for u, params := range arjun {
			for _, p := range params {
				endpoints = append(endpoints, fmt.Sprintf("%s?%s=", u, p))
			}
		}
	}

	var ssrf, redirect []string
	seenS := make(map[string]struct{})
	seenR := make(map[string]struct{})

	for _, ep := range endpoints {
		for _, m := range reURLParam.FindAllStringSubmatch(ep, -1) {
			param := strings.ToLower(m[1])
			if _, ok := ssrfParamNames[param]; ok {
				key := ep + "|" + param
				if _, seen := seenS[key]; !seen {
					seenS[key] = struct{}{}
					ssrf = append(ssrf, fmt.Sprintf("%s  [param: %s]", ep, m[1]))
				}
			}
			if _, ok := redirectParamNames[param]; ok {
				key := ep + "|" + param
				if _, seen := seenR[key]; !seen {
					seenR[key] = struct{}{}
					redirect = append(redirect, fmt.Sprintf("%s  [param: %s]", ep, m[1]))
				}
			}
		}
	}

	if len(ssrf) > 0 {
		header := "# SSRF Surface — candidate endpoints with URL-accepting parameters\n" +
			"# These are surface maps only. No payloads have been sent.\n\n"
		_ = os.WriteFile(filepath.Join(otherDir, "ssrf_surface.txt"),
			[]byte(header+strings.Join(ssrf, "\n")+"\n"), 0644)
		logInfo("  surface: %d SSRF candidate parameters written to other/ssrf_surface.txt", len(ssrf))
	}
	if len(redirect) > 0 {
		header := "# Open Redirect Surface — candidate endpoints with redirect-accepting parameters\n" +
			"# These are surface maps only. No payloads have been sent.\n\n"
		_ = os.WriteFile(filepath.Join(otherDir, "redirect_surface.txt"),
			[]byte(header+strings.Join(redirect, "\n")+"\n"), 0644)
		logInfo("  surface: %d open redirect candidate parameters written to other/redirect_surface.txt", len(redirect))
	}
}

// ---- rate limit summary -----------------------------------------------------

// writeRateLimitSummary writes a human-readable summary of observed (or absent)
// rate limiting headers to other/ratelimit_<host>.txt.
func writeRateLimitSummary(sh *SecurityHeaders, otherDir string) {
	safe := sanitizeForFilename(sh.Host)
	path := filepath.Join(otherDir, "ratelimit_"+safe+".txt")

	var b strings.Builder
	fmt.Fprintf(&b, "Rate Limit Surface — %s\n\n", sh.Host)
	if sh.HasRateLimit {
		fmt.Fprintln(&b, "Rate limiting headers present:")
		for k, v := range sh.RateLimitHeaders {
			fmt.Fprintf(&b, "  %s: %s\n", k, v)
		}
	} else {
		fmt.Fprintln(&b, "No rate limiting headers observed in response.")
		fmt.Fprintln(&b, "Verify manually whether rate limiting is enforced at the application or infrastructure layer.")
	}
	_ = os.WriteFile(path, []byte(b.String()), 0644)
}

// ---- well-known URL fetching -----------------------------------------------

// runWellKnown fetches robots.txt, sitemap.xml, sitemap_index.xml, and
// security.txt for a host. Discovered paths/URLs are appended to
// discovered_endpoints. Raw responses are written to other/wellknown_<host>.txt.
func runWellKnown(r *Runner, s *RunState, host, otherDir string) {
	safe := sanitizeForFilename(host)
	outFile := filepath.Join(otherDir, "wellknown_"+safe+".txt")
	base := strings.TrimRight(host, "/")

	paths := []string{
		"/robots.txt",
		"/sitemap.xml",
		"/sitemap_index.xml",
		"/.well-known/security.txt",
		"/.well-known/change-password",
	}

	var allContent strings.Builder
	var allEndpoints []string

	for _, p := range paths {
		url := base + p
		stdout, res := r.RunWithOutput("curl", "curl", append([]string{
			"-s", "-L", "-m", "10", "--max-redirs", "3",
			"-H", "Accept: text/plain,text/xml,application/xml,*/*",
			url,
		}, proxyFlagForTool("curl", s.Cfg.ProxyURL)...))
		if res.Skipped || res.Err != nil || strings.TrimSpace(stdout) == "" {
			continue
		}
		// Skip obvious error pages (HTML where plain text is expected)
		bodyLower := strings.ToLower(strings.TrimSpace(stdout))
		if strings.HasPrefix(bodyLower, "<!doctype") || strings.HasPrefix(bodyLower, "<html") {
			continue
		}

		fmt.Fprintf(&allContent, "### %s\n\n%s\n\n", url, stdout)

		switch {
		case strings.HasSuffix(p, "robots.txt"):
			endpoints := ParseRobotsTxt(stdout, base)
			allEndpoints = append(allEndpoints, endpoints...)
			if len(endpoints) > 0 {
				logInfo("  wellknown: %s — %d paths from robots.txt", host, len(endpoints))
			}
		case strings.Contains(p, "sitemap"):
			endpoints := ParseSitemapXML(stdout)
			allEndpoints = append(allEndpoints, endpoints...)
			if len(endpoints) > 0 {
				logInfo("  wellknown: %s — %d URLs from %s", host, len(endpoints), p)
			}
		}
	}

	if allContent.Len() == 0 {
		return
	}

	_ = os.WriteFile(outFile, []byte(allContent.String()), 0644)

	if len(allEndpoints) > 0 {
		inScope, oos := filterEndpointsInScope(allEndpoints, s.Scope)
		if len(oos) > 0 {
			logInfo("  wellknown: filtered %d out-of-scope URLs", len(oos))
		}
		_ = writeDiscoveredEndpoints(s.EngDir, inScope)
	}
}

// ---- vhost fuzzing ---------------------------------------------------------

// runVhostFuzzing runs ffuf against each root domain's HTTP service to discover
// virtual hosts that share the same IP but don't resolve via public DNS.
func runVhostFuzzing(r *Runner, s *RunState) {
	otherDir := filepath.Join(s.EngDir, "other")

	if _, err := os.Stat(s.Cfg.VhostWordlist); err != nil {
		logWarn("vhost fuzzing: wordlist %q not found — skipping (set vhost_wordlist in config)", s.Cfg.VhostWordlist)
		return
	}

	for _, domain := range s.Domains {
		if interrupted.Load() {
			break
		}

		// Find an HTTP service for this root domain
		var targetURL string
		for _, h := range s.HTTPHosts {
			stripped := strings.TrimPrefix(strings.TrimPrefix(h, "https://"), "http://")
			if stripped == domain || stripped == "www."+domain {
				targetURL = h
				break
			}
		}
		if targetURL == "" {
			logDebug("vhost fuzzing: no live HTTP service found for %s — skipping", domain)
			continue
		}

		// Establish baseline response size using a random non-existent vhost so
		// ffuf can filter responses that match the default "not found" behaviour.
		baselineOut, baselineRes := r.RunWithOutput("curl", "curl", []string{
			"-s", "-o", "/dev/null", "-w", "%{size_download}",
			"-H", fmt.Sprintf("Host: reconjr-baseline-probe.%s", domain),
			"-m", "10", "-k", "-L", targetURL,
		})
		if baselineRes.Skipped && baselineRes.SkipReason != "dry-run" {
			continue
		}
		baselineSize := strings.TrimSpace(baselineOut)
		if baselineSize == "" {
			baselineSize = "0"
		}

		safe := sanitizeForFilename(domain)
		outFile := filepath.Join(otherDir, "ffuf_vhost_"+safe+".json")
		ffufArgs := []string{
			"-w", s.Cfg.VhostWordlist,
			"-u", targetURL,
			"-H", fmt.Sprintf("Host: FUZZ.%s", domain),
			"-fs", baselineSize,
			"-o", outFile, "-of", "json",
			"-mc", "all",
			"-t", "40",
			"-s",
		}
		if strings.HasPrefix(targetURL, "https://") {
			ffufArgs = append(ffufArgs, "-k")
		}
		ffufArgs = append(ffufArgs, proxyFlagForTool("ffuf", s.Cfg.ProxyURL)...)

		logInfo("  [vhost] fuzzing %s (baseline size: %s bytes)", domain, baselineSize)
		res := r.RunLong("ffuf", "ffuf", ffufArgs, outFile)
		if !res.Skipped && res.Err == nil {
			if findings, err := ParseFFufVhost(outFile, domain); err == nil {
				s.Report.AddFindings(findings)
				if len(findings) > 0 {
					logInfo("  vhost: %d potential vhost(s) found for %s", len(findings), domain)
				}
			}
		}
		r.Delay()
	}
}

// ---- GitHub secrets and dorking --------------------------------------------

// runTrufflehogGitHub scans each configured GitHub org for leaked secrets.
func runTrufflehogGitHub(r *Runner, s *RunState) {
	otherDir := filepath.Join(s.EngDir, "other")
	for _, org := range s.Cfg.GithubOrgs {
		if interrupted.Load() {
			break
		}
		safe := sanitizeForFilename(org)
		outFile := filepath.Join(otherDir, "trufflehog_github_"+safe+".json")
		logInfo("  [github] trufflehog scanning org: %s", org)
		res := r.RunLong("trufflehog", "trufflehog", []string{
			"github", "--org", org, "--json",
		}, outFile)
		if !res.Skipped && res.Err == nil {
			if findings, err := ParseTrufflehog(outFile, org); err == nil {
				for _, f := range findings {
					if !f.Suppress {
						s.Report.AddFinding(f)
					}
				}
			}
		}
		r.Delay()
	}
}

// gitdorkQueries are the sensitive keyword patterns used in GitHub code search.
var gitdorkQueries = []string{
	"password", "secret", "api_key", "apikey", "access_key",
	"token", "credentials", "private_key", "auth_token", "passwd",
}

// runGitdorks searches GitHub public code for the target domains combined with
// sensitive keywords. Requires gh CLI to be authenticated (gh auth login).
func runGitdorks(r *Runner, s *RunState) {
	// Check once whether gh is available/skip-listed before entering the loop.
	if skip, reason := r.ShouldSkip("gh", "gh"); skip {
		logInfo("  [skip] gh — %s", reason)
		return
	}

	otherDir := filepath.Join(s.EngDir, "other")

	for _, domain := range s.Domains {
		if interrupted.Load() {
			break
		}
		safe := sanitizeForFilename(domain)
		outFile := filepath.Join(otherDir, "gitdorks_"+safe+".json")

		seen := make(map[string]struct{})
		var findings []Finding

		for _, keyword := range gitdorkQueries {
			if interrupted.Load() {
				break
			}
			query := fmt.Sprintf(`"%s" %s`, domain, keyword)
			logInfo("  [run]  gh search code %s --limit 10 --json repository,path,url", query)
			if dryRun {
				continue
			}
			stdout, res := r.RunWithOutput("gh", "gh", []string{
				"search", "code", query,
				"--limit", "10",
				"--json", "repository,path,url",
			})
			if res.Err != nil || strings.TrimSpace(stdout) == "" || stdout == "[]" {
				continue
			}
			if ghFindings := parseGitdorkResults(stdout, domain, keyword); len(ghFindings) > 0 {
				for _, f := range ghFindings {
					if _, ok := seen[f.Host+f.Detail]; !ok {
						seen[f.Host+f.Detail] = struct{}{}
						findings = append(findings, f)
					}
				}
			}
		}

		if len(findings) > 0 {
			s.Report.AddFindings(findings)
			logInfo("  gitdorks: %d potential exposures found for %s", len(findings), domain)
			if data, err := json.MarshalIndent(findings, "", "  "); err == nil {
				_ = os.WriteFile(outFile, data, 0644)
			}
		} else {
			logDebug("gitdorks: no matches found for %s", domain)
		}
		r.Delay()
	}
}

// ---- helpers ---------------------------------------------------------------

// proxyFlagForTool returns tool-specific CLI proxy arguments.
func proxyFlagForTool(tool, proxyURL string) []string {
	if proxyURL == "" {
		return nil
	}
	switch tool {
	case "curl":
		return []string{"-x", proxyURL}
	case "nuclei":
		return []string{"-proxy", proxyURL}
	case "feroxbuster":
		return []string{"--proxy", proxyURL}
	case "httpx":
		return []string{"-http-proxy", proxyURL}
	case "katana":
		return []string{"-proxy", proxyURL}
	case "nikto":
		return []string{"-useproxy", proxyURL}
	case "whatweb":
		return []string{"--proxy", proxyURL}
	case "subfinder":
		return []string{"-proxy", proxyURL}
	case "wpscan":
		return []string{"--proxy", proxyURL}
	case "gowitness":
		return []string{"--proxy", proxyURL}
	}
	return nil
}

func appendToFile(path, content string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprint(f, content)
}

func parseEndpointLines(output string) ([]string, error) {
	var endpoints []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && (strings.HasPrefix(line, "/") || strings.HasPrefix(line, "http")) {
			endpoints = append(endpoints, line)
		}
	}
	return endpoints, nil
}

// urlHost extracts the host:port from a URL string.
func urlHost(u string) string {
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	if idx := strings.Index(u, "/"); idx != -1 {
		return u[:idx]
	}
	return u
}
