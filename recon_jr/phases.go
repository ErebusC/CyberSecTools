package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	Scope          *Scope
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
	"nikto":      true,
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
		s.AllHosts = merged
		s.Report.DiscoveredHosts = merged
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

	// httpx — bulk probe all hosts
	if !interrupted.Load() {
		hostsFile := filepath.Join(s.EngDir, "hosts")
		outFile := filepath.Join(otherDir, "httpx.json")
		httpxArgs := append([]string{
			"-l", hostsFile, "-o", outFile,
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
				if len(s.HTTPHosts) == 0 && len(entries) > 0 {
					seen := make(map[string]struct{})
					for _, e := range entries {
						if e.URL == "" {
							continue
						}
						if _, ok := seen[e.URL]; !ok {
							seen[e.URL] = struct{}{}
							s.HTTPHosts = append(s.HTTPHosts, e.URL)
						}
					}
					s.Report.HTTPHosts = s.HTTPHosts
					logDebug("httpx discovered %d live HTTP services", len(s.HTTPHosts))
					_ = writeLinesToFile(filepath.Join(s.EngDir, "http_hosts"), s.HTTPHosts)
				}
			}
		}
		r.Delay()
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
	// + UDP top-20. All hosts scanned concurrently, max 3 at a time.
	type nmapResult struct {
		host     string
		findings []Finding
		webPorts []NmapWebPort
	}

	nmapResults := make(chan nmapResult, len(s.AllHosts))
	var udpRootWarnOnce sync.Once
	sem := make(chan struct{}, 3)
	var wg sync.WaitGroup

	for _, host := range s.AllHosts {
		if interrupted.Load() {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()

			safe := sanitizeForFilename(h)
			var allFindings []Finding
			var webPorts []NmapWebPort

			// Pass 1: fast full-port TCP scan to identify open ports
			portXML := filepath.Join(nmapDir, "nmap_ports_"+safe+".xml")
			portRes := r.RunLong("nmap", "nmap", []string{
				"-p-", "--min-rate", "2000", "-T4", "--open",
				"-oX", portXML, h,
			}, "")

			if !portRes.Skipped && portRes.Err == nil {
				openPorts, err := extractOpenPortList(portXML)
				if err == nil && len(openPorts) > 0 {
					// Pass 2: detailed service/version + NSE on open ports only
					outXML := filepath.Join(nmapDir, "nmap_"+safe+".xml")
					detailRes := r.RunLong("nmap", "nmap", []string{
						"-sV", "-sC", "--version-intensity", "5",
						"-p", strings.Join(openPorts, ","),
						"-oX", outXML, h,
					}, "")
					if !detailRes.Skipped && detailRes.Err == nil {
						if f, err := ParseNmap(outXML, h); err == nil {
							allFindings = append(allFindings, f...)
						}
						if wp, err := ParseNmapWebPorts(outXML); err == nil {
							webPorts = wp
						}
					}
				} else if err == nil {
					logInfo("  nmap: no open ports found on %s", h)
				}
			}

			// UDP top-20 scan
			if !interrupted.Load() {
				udpXML := filepath.Join(nmapDir, "nmap_udp_"+safe+".xml")
				udpRes := r.RunLong("nmap", "nmap", []string{
					"-sU", "--top-ports", "20", "-oX", udpXML, h,
				}, "")
				if udpRes.ExitCode != 0 &&
					(strings.Contains(udpRes.Stderr, "root") || strings.Contains(udpRes.Stderr, "privileged")) {
					udpRootWarnOnce.Do(func() {
						logWarn("  UDP scan requires root privileges — skipping (run as root to enable)")
					})
				} else if !udpRes.Skipped && udpRes.Err == nil {
					if f, err := ParseNmap(udpXML, h); err == nil {
						allFindings = append(allFindings, f...)
					}
				}
			}

			nmapResults <- nmapResult{host: h, findings: allFindings, webPorts: webPorts}
		}(host)
	}
	wg.Wait()
	close(nmapResults)

	for result := range nmapResults {
		s.Report.AddFindings(result.findings)
		for _, wp := range result.webPorts {
			key := fmt.Sprintf("%s:%d", result.host, wp.Port)
			if _, covered := coveredWebPorts[key]; !covered {
				s.Report.AddFinding(Finding{
					Tool:     "nmap",
					Host:     wp.URL(result.host),
					Category: "Network Exposure",
					Title:    fmt.Sprintf("Web service on port %d — not in web scan scope", wp.Port),
					Detail:   fmt.Sprintf("nmap identified %s on port %d/%s — verify whether this URL is in scope for testing", strings.TrimSpace(wp.Service), wp.Port, wp.Proto),
					Severity: SevInfo,
				})
			}
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
					_ = writeDiscoveredEndpoints(s.EngDir, endpoints)
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
					"--threads", "20",
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
				_ = writeDiscoveredEndpoints(s.EngDir, endpoints)
			}
		}
		r.Delay()

		if !interrupted.Load() {
			gauOut := filepath.Join(otherDir, "gau_"+safe+".txt")
			gauRes := r.Run("gau", "gau", []string{domain, "--o", gauOut}, gauOut)
			if !gauRes.Skipped && gauRes.Err == nil {
				if endpoints, err := readLines(gauOut); err == nil {
					_ = writeDiscoveredEndpoints(s.EngDir, endpoints)
				}
			}
			r.Delay()
		}
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

	// nikto — intrusive, one per HTTP host
	if s.AllowIntrusive && !interrupted.Load() {
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
							_ = writeDiscoveredEndpoints(s.EngDir, endpoints)
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
			if _, findings, err := ParseSecurityHeaders(outFile, host); err == nil {
				s.Report.AddFindings(findings)
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
