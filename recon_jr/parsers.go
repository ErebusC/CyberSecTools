package main

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Finding represents a single notable result from a tool that should appear in
// the recon report. Findings with Suppress=true are written to disk but excluded
// from recon_report.md sections.
type Finding struct {
	Tool     string
	Host     string
	Category string
	Title    string
	Detail   string
	Severity Severity
	Suppress bool
}

// Severity levels for findings.
type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevCritical:
		return "Critical"
	case SevHigh:
		return "High"
	case SevMedium:
		return "Medium"
	case SevLow:
		return "Low"
	default:
		return "Info"
	}
}

// ---- httpx ----------------------------------------------------------------

type httpxEntry struct {
	URL          string   `json:"url"`
	StatusCode   int      `json:"status_code"`
	Title        string   `json:"title"`
	WebServer    string   `json:"webserver"`
	Technologies []string `json:"technologies"`
	Scheme       string   `json:"scheme"`
	Host         string   `json:"host"`
	TLSData      *struct {
		SubjectCN string `json:"subject_cn"`
	} `json:"tls,omitempty"`
}

// ParseHTTPX parses a newline-delimited httpx JSON output file.
// Returns entries and a map of host -> detected CMS type.
func ParseHTTPX(path string) ([]httpxEntry, map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("reading httpx output %s: %w", path, err)
	}

	var entries []httpxEntry
	cms := make(map[string]string)

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var e httpxEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			logDebug("httpx: skipping malformed line: %v", err)
			continue
		}
		entries = append(entries, e)

		host := e.Host
		if host == "" {
			host = e.URL
		}
		for _, tech := range e.Technologies {
			lower := strings.ToLower(tech)
			switch {
			case strings.Contains(lower, "wordpress"):
				cms[host] = "wordpress"
			case strings.Contains(lower, "joomla"):
				cms[host] = "joomla"
			case strings.Contains(lower, "drupal"):
				cms[host] = "drupal"
			}
		}
	}
	return entries, cms, scanner.Err()
}

// ---- whatweb ---------------------------------------------------------------

type whatwebEntry struct {
	Target     string                     `json:"target"`
	HTTPStatus int                        `json:"http_status"`
	Plugins    map[string]whatwebPlugin   `json:"plugins"`
}

type whatwebPlugin struct {
	Version []string `json:"version,omitempty"`
	String  []string `json:"string,omitempty"`
}

// ParseWhatWeb parses a whatweb JSON array output file.
// Returns entries and a map of host -> CMS type and a map of host -> version findings.
func ParseWhatWeb(path string) ([]whatwebEntry, map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("reading whatweb output %s: %w", path, err)
	}

	var entries []whatwebEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		// Try newline-delimited fallback
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			var e whatwebEntry
			if err2 := json.Unmarshal([]byte(line), &e); err2 == nil {
				entries = append(entries, e)
			}
		}
		if len(entries) == 0 {
			return nil, nil, fmt.Errorf("parsing whatweb JSON: %w", err)
		}
	}

	cms := make(map[string]string)
	for _, e := range entries {
		host := e.Target
		for plugin := range e.Plugins {
			lower := strings.ToLower(plugin)
			switch {
			case lower == "wordpress":
				cms[host] = "wordpress"
			case lower == "joomla":
				cms[host] = "joomla"
			case lower == "drupal":
				cms[host] = "drupal"
			}
		}
	}
	return entries, cms, nil
}

// serverSideTech lists technologies whose version disclosure is worth reporting.
var serverSideTech = map[string]bool{
	"Apache":     true,
	"Nginx":      true,
	"IIS":        true,
	"LiteSpeed":  true,
	"PHP":        true,
	"Python":     true,
	"Ruby":       true,
	"ASP.NET":    true,
	"Tomcat":     true,
	"JBoss":      true,
	"Jetty":      true,
	"OpenSSL":    true,
	"WordPress":  true,
	"Drupal":     true,
	"Joomla":     true,
}

// ParseWhatWebVersions parses a whatweb JSON output file and returns version
// disclosure findings for server-side technologies.
func ParseWhatWebVersions(path string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading whatweb output %s: %w", path, err)
	}
	var entries []whatwebEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			var e whatwebEntry
			if err2 := json.Unmarshal([]byte(strings.TrimSpace(scanner.Text())), &e); err2 == nil {
				entries = append(entries, e)
			}
		}
	}
	var findings []Finding
	seen := make(map[string]struct{})
	for _, e := range entries {
		host := e.Target
		for plugin, info := range e.Plugins {
			if !serverSideTech[plugin] || len(info.Version) == 0 {
				continue
			}
			for _, ver := range info.Version {
				ver = strings.TrimSpace(ver)
				if ver == "" {
					continue
				}
				key := host + "|" + plugin + "|" + ver
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				findings = append(findings, Finding{
					Tool:     "whatweb",
					Host:     host,
					Category: "Version Disclosure",
					Title:    fmt.Sprintf("%s version disclosed: %s", plugin, ver),
					Detail:   "Version identified by whatweb — aids targeted exploit selection",
					Severity: SevLow,
				})
			}
		}
	}
	return findings, nil
}

// ---- testssl ---------------------------------------------------------------

type testsslEntry struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Finding  string `json:"finding"`
	IP       string `json:"ip"`
	Port     string `json:"port"`
}

// testsslReportIDs are the IDs we include in the report.
var testsslReportIDs = map[string]Severity{
	"SSLv2":             SevCritical,
	"SSLv3":             SevHigh,
	"TLS1":              SevMedium,
	"TLS1_1":            SevMedium,
	"HEARTBLEED":        SevCritical,
	"CCS":               SevHigh,
	"TICKETBLEED":       SevHigh,
	"ROBOT":             SevHigh,
	"BEAST":             SevMedium,
	"POODLE_SSL":        SevMedium,
	"POODLE_TLS1_2":     SevHigh,
	"DROWN":             SevHigh,
	"expiration":        SevHigh,
	"cert_notAfter":     SevHigh,
	"cert_trust":        SevMedium,
	"cert_chain_of_trust": SevMedium,
	"cert_hostname":     SevHigh,
	"HSTS":              SevMedium,
	"HSTS_time":         SevLow,
	"cipher_rc4":        SevMedium,
	"cipher_3des":       SevMedium,
	"cipher_NULL":       SevCritical,
	"cipher_aNULL":      SevCritical,
	"cipher_EXPORT":     SevHigh,
}

// testsslSkipIDs are testssl result IDs we never report because they are either
// handled by another phase, near-universal on modern sites, or purely informational.
var testsslSkipIDs = map[string]struct{}{
	"security_headers": {}, // Phase 7 does a dedicated, more detailed check
	"HTTP_status_code": {},
	"banner_server":    {},
	"DNS_CAArecord":    {}, // Phase 1 already reports missing CAA records
	"BREACH":           {}, // fires on any site with gzip compression; rarely exploitable
}

// testsslSuppressFinding contains substrings that indicate a passing/clean result.
// Entries whose finding text matches any of these are silently dropped.
var testsslSuppressFinding = []string{
	"not offered",
	"not vulnerable",
	"not detectable",
	"No STARTTLS",
	"no cipher order",
	"passed",     // cert_chain_of_trust: "passed."
	"ok via",     // cert_trust: "Ok via SAN and CN (SNI mandatory)"
	"ok (but",
	" ok",        // many testssl checks end in " OK"
}

// ParseTestSSL parses a testssl.sh JSON output file and returns notable findings.
func ParseTestSSL(path, host string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading testssl output %s: %w", path, err)
	}

	var entries []testsslEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parsing testssl JSON: %w", err)
	}

	var findings []Finding
	for _, e := range entries {
		// Skip IDs handled elsewhere or purely informational
		if _, skip := testsslSkipIDs[e.ID]; skip {
			continue
		}
		if shouldSuppressTestSSL(e) {
			continue
		}

		// cert_notAfter: compute severity from days remaining rather than hardcoding High
		if e.ID == "cert_notAfter" || e.ID == "expiration" {
			sev, suppress := parseCertExpiry(e.Finding)
			if suppress {
				continue
			}
			findings = append(findings, Finding{
				Tool:     "testssl",
				Host:     host,
				Category: "TLS / SSL",
				Title:    "Certificate expiry",
				Detail:   e.Finding,
				Severity: sev,
			})
			continue
		}

		sev, known := testsslReportIDs[e.ID]
		if !known {
			switch strings.ToUpper(e.Severity) {
			case "CRITICAL":
				sev = SevCritical
			case "HIGH":
				sev = SevHigh
			case "MEDIUM":
				sev = SevMedium
			case "LOW":
				sev = SevLow
			default:
				continue // WARN, INFO, OK — skip
			}
		}
		findings = append(findings, Finding{
			Tool:     "testssl",
			Host:     host,
			Category: "TLS / SSL",
			Title:    fmt.Sprintf("TLS issue: %s", e.ID),
			Detail:   e.Finding,
			Severity: sev,
		})
	}
	return findings, nil
}

// parseCertExpiry parses a testssl cert_notAfter finding and returns severity
// based on days remaining. Returns suppress=true if the cert expires in > 90 days.
func parseCertExpiry(finding string) (sev Severity, suppress bool) {
	finding = strings.TrimSpace(finding)
	if len(finding) < 16 {
		return SevMedium, false
	}
	expiry, err := time.Parse("2006-01-02 15:04", finding[:16])
	if err != nil {
		return SevMedium, false
	}
	days := int(time.Until(expiry).Hours() / 24)
	switch {
	case days < 0:
		return SevCritical, false // already expired
	case days < 14:
		return SevCritical, false
	case days < 30:
		return SevHigh, false
	case days < 90:
		return SevMedium, false
	default:
		return SevInfo, true // > 90 days — not worth reporting
	}
}

func shouldSuppressTestSSL(e testsslEntry) bool {
	for _, s := range testsslSuppressFinding {
		if strings.Contains(strings.ToLower(e.Finding), strings.ToLower(s)) {
			return true
		}
	}
	return false
}

// ---- nmap ------------------------------------------------------------------

type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses []nmapAddress `xml:"address"`
	Ports     struct {
		Ports []nmapPort `xml:"port"`
	} `xml:"ports"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

// unexpectedPorts are management/dangerous ports that are always reported on
// internet-facing hosts regardless of scope port list.
var unexpectedPorts = map[int]string{
	21:   "FTP",
	22:   "SSH",
	23:   "Telnet",
	25:   "SMTP",
	110:  "POP3",
	135:  "RPC",
	139:  "NetBIOS",
	445:  "SMB",
	1433: "MSSQL",
	1521: "Oracle",
	3306: "MySQL",
	3389: "RDP",
	5432: "PostgreSQL",
	5900: "VNC",
}

// scopePorts are the default allowed ports (HTTP/HTTPS). Users can extend via config.
var defaultScopePorts = map[int]struct{}{80: {}, 443: {}, 8080: {}, 8443: {}}

// extractOpenPortList parses an nmap XML file and returns the open port numbers
// as strings (e.g. ["22","80","443"]), sorted numerically. Used for the second
// pass of the two-pass nmap strategy.
func extractOpenPortList(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading nmap XML %s: %w", path, err)
	}
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("parsing nmap XML: %w", err)
	}
	seen := make(map[int]struct{})
	for _, h := range run.Hosts {
		for _, p := range h.Ports.Ports {
			if p.State.State == "open" {
				seen[p.PortID] = struct{}{}
			}
		}
	}
	var nums []int
	for p := range seen {
		nums = append(nums, p)
	}
	sort.Ints(nums)
	ports := make([]string, len(nums))
	for i, n := range nums {
		ports[i] = strconv.Itoa(n)
	}
	return ports, nil
}

// NmapWebPort represents an HTTP/HTTPS service found on a non-standard port.
type NmapWebPort struct {
	Port    int
	Proto   string
	Service string
	TLS     bool
}

// URL returns the base URL for this web service given the original scan hostname.
func (w NmapWebPort) URL(hostname string) string {
	scheme := "http"
	if w.TLS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, hostname, w.Port)
}

// isHTTPService reports whether the nmap service name indicates an HTTP endpoint.
func isHTTPService(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "http") || n == "https"
}

// ParseNmapWebPorts returns HTTP/HTTPS services found on non-standard ports.
// Standard ports (80, 443, 8080, 8443) are excluded since they are always tested.
func ParseNmapWebPorts(path string) ([]NmapWebPort, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading nmap output %s: %w", path, err)
	}

	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("parsing nmap XML: %w", err)
	}

	var webPorts []NmapWebPort
	for _, h := range run.Hosts {
		for _, p := range h.Ports.Ports {
			if p.State.State != "open" {
				continue
			}
			if _, standard := defaultScopePorts[p.PortID]; standard {
				continue
			}
			if !isHTTPService(p.Service.Name) {
				continue
			}
			svcLower := strings.ToLower(p.Service.Name)
			tls := strings.Contains(svcLower, "ssl") || strings.Contains(svcLower, "https")
			webPorts = append(webPorts, NmapWebPort{
				Port:    p.PortID,
				Proto:   p.Protocol,
				Service: strings.TrimSpace(fmt.Sprintf("%s %s %s", p.Service.Name, p.Service.Product, p.Service.Version)),
				TLS:     tls,
			})
		}
	}
	return webPorts, nil
}

// ParseNmap parses an nmap XML output file and returns notable findings.
func ParseNmap(path, host string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading nmap output %s: %w", path, err)
	}

	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("parsing nmap XML: %w", err)
	}

	var findings []Finding
	for _, h := range run.Hosts {
		addr := ""
		for _, a := range h.Addresses {
			if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
				addr = a.Addr
				break
			}
		}
		if addr == "" {
			addr = host
		}

		for _, p := range h.Ports.Ports {
			if p.State.State != "open" {
				continue
			}
			if _, inScope := defaultScopePorts[p.PortID]; inScope {
				continue
			}
			sev := SevMedium
			title := fmt.Sprintf("Unexpected open port %d/%s", p.PortID, p.Protocol)
			detail := fmt.Sprintf("Service: %s %s %s", p.Service.Name, p.Service.Product, p.Service.Version)

			if svcName, dangerous := unexpectedPorts[p.PortID]; dangerous {
				sev = SevHigh
				title = fmt.Sprintf("Management interface exposed: %s (port %d)", svcName, p.PortID)
			}

			findings = append(findings, Finding{
				Tool:     "nmap",
				Host:     addr,
				Category: "Network Exposure",
				Title:    title,
				Detail:   strings.TrimSpace(detail),
				Severity: sev,
			})
		}
	}
	return findings, nil
}

// ---- nuclei ----------------------------------------------------------------

type nucleiEntry struct {
	TemplateID string `json:"template-id"`
	Name       string `json:"name"`
	Severity   string `json:"severity"`
	Host       string `json:"host"`
	MatchedAt  string `json:"matched-at"`
	Info       struct {
		Name string `json:"name"`
	} `json:"info"`
}

// ParseNuclei parses a nuclei JSONL output file and returns findings.
// Only Critical, High, and filtered Medium findings are returned.
func ParseNuclei(path, host string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading nuclei output %s: %w", path, err)
	}

	var findings []Finding
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var e nucleiEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			logDebug("nuclei: skipping malformed line: %v", err)
			continue
		}

		var sev Severity
		switch strings.ToLower(e.Severity) {
		case "critical":
			sev = SevCritical
		case "high":
			sev = SevHigh
		case "medium":
			sev = SevMedium
		default:
			continue // info/low — skip
		}

		name := e.Info.Name
		if name == "" {
			name = e.Name
		}
		targetHost := e.Host
		if targetHost == "" {
			targetHost = host
		}

		findings = append(findings, Finding{
			Tool:     "nuclei",
			Host:     targetHost,
			Category: "Vulnerability Scan",
			Title:    name,
			Detail:   fmt.Sprintf("Template: %s | Matched: %s", e.TemplateID, e.MatchedAt),
			Severity: sev,
		})
	}
	return findings, scanner.Err()
}

// ---- nikto -----------------------------------------------------------------

var (
	reNiktoFinding  = regexp.MustCompile(`^\+\s+(.+)$`)
	reNiktoVersion  = regexp.MustCompile(`(?i)server:\s*(\S+)`)
	niktoSuppressed = []string{
		"The anti-clickjacking X-Frame-Options",
		"may be interesting",
	}
)

type niktoResult struct {
	Title  string
	Detail string
	Sev    Severity
}

// ParseNikto parses nikto text output and returns notable findings.
func ParseNikto(path, host string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading nikto output %s: %w", path, err)
	}

	var findings []Finding
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		m := reNiktoFinding.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		finding := strings.TrimSpace(m[1])
		if shouldSuppressNikto(finding) {
			continue
		}

		sev := SevMedium
		title := "Nikto finding"
		if r := classifyNiktoFinding(finding); r != nil {
			sev = r.Sev
			title = r.Title
		}

		findings = append(findings, Finding{
			Tool:     "nikto",
			Host:     host,
			Category: "Web Server",
			Title:    title,
			Detail:   finding,
			Severity: sev,
		})
	}
	return findings, scanner.Err()
}

func shouldSuppressNikto(finding string) bool {
	for _, s := range niktoSuppressed {
		if strings.Contains(finding, s) {
			return true
		}
	}
	return false
}

func classifyNiktoFinding(finding string) *niktoResult {
	lower := strings.ToLower(finding)
	switch {
	case strings.Contains(lower, "trace") || strings.Contains(lower, "track"):
		return &niktoResult{Title: "Dangerous HTTP method (TRACE/TRACK — XST risk)", Sev: SevMedium}
	case strings.Contains(lower, "put method") || strings.Contains(lower, "delete method"):
		return &niktoResult{Title: "Dangerous HTTP method enabled (PUT/DELETE)", Sev: SevMedium}
	case strings.Contains(lower, "directory indexing") || strings.Contains(lower, "directory listing"):
		return &niktoResult{Title: "Directory listing enabled", Sev: SevMedium}
	case strings.Contains(lower, "server-side includes"):
		return &niktoResult{Title: "Server-side includes enabled", Sev: SevMedium}
	case strings.Contains(lower, "server:") || strings.Contains(lower, "x-powered-by"):
		return &niktoResult{Title: "Server version disclosure in response header", Sev: SevLow}
	case strings.Contains(lower, "outdated") || strings.Contains(lower, "vulnerable"):
		return &niktoResult{Title: "Outdated or vulnerable software identified", Sev: SevHigh}
	}
	return nil
}

// ---- security headers (curl -I) -------------------------------------------

type SecurityHeaders struct {
	Host                 string
	StatusCode           string
	MissingHeaders       []string
	InsecureCookies      []string
	ServerHeader         string
	XPoweredByHeader     string
	HSTSValue            string
	HSTSMaxAge           int
	RateLimitHeaders     map[string]string // present rate-limit headers and their values
	HasRateLimit         bool              // true if any rate-limit header was observed
}

var (
	reHeaderLine  = regexp.MustCompile(`^([^:]+):\s*(.*)$`)
	reStatusLine  = regexp.MustCompile(`^HTTP/\S+\s+(\d+)`)
	reCookieName  = regexp.MustCompile(`^([^=;]+)`)
	reHSTSMaxAge  = regexp.MustCompile(`(?i)max-age=(\d+)`)
)

// ParseSecurityHeaders parses the output of `curl -s -I <url>` and returns
// a SecurityHeaders summary with missing or misconfigured headers noted.
func ParseSecurityHeaders(path, host string) (*SecurityHeaders, []Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("reading curl output %s: %w", path, err)
	}

	sh := &SecurityHeaders{Host: host}
	present := make(map[string]string)
	var cookieLines []string

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if m := reStatusLine.FindStringSubmatch(line); m != nil {
			sh.StatusCode = m[1]
			continue
		}
		m := reHeaderLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(m[1]))
		value := strings.TrimSpace(m[2])
		present[name] = value

		if name == "set-cookie" {
			cookieLines = append(cookieLines, value)
		}
	}

	// Check for missing security headers.
	requiredHeaders := []string{
		"strict-transport-security",
		"content-security-policy",
		"x-content-type-options",
		"referrer-policy",
		"permissions-policy",
	}
	for _, h := range requiredHeaders {
		if _, ok := present[h]; !ok {
			sh.MissingHeaders = append(sh.MissingHeaders, h)
		}
	}

	// Check X-Frame-Options or CSP frame-ancestors.
	if _, hasXFO := present["x-frame-options"]; !hasXFO {
		if csp, hasCSP := present["content-security-policy"]; !hasCSP || !strings.Contains(csp, "frame-ancestors") {
			sh.MissingHeaders = append(sh.MissingHeaders, "x-frame-options (or CSP frame-ancestors)")
		}
	}

	// HSTS max-age check.
	if hsts, ok := present["strict-transport-security"]; ok {
		sh.HSTSValue = hsts
		if m := reHSTSMaxAge.FindStringSubmatch(hsts); m != nil {
			var age int
			fmt.Sscanf(m[1], "%d", &age)
			sh.HSTSMaxAge = age
			if age < 15552000 { // 180 days
				sh.MissingHeaders = append(sh.MissingHeaders, fmt.Sprintf("HSTS max-age too low (%d, minimum 180 days)", age))
			}
		}
	}

	// Version-disclosing headers.
	if v, ok := present["server"]; ok {
		sh.ServerHeader = v
	}
	if v, ok := present["x-powered-by"]; ok {
		sh.XPoweredByHeader = v
	}

	// Rate limiting headers.
	rateLimitHeaderNames := []string{
		"x-ratelimit-limit",
		"x-ratelimit-remaining",
		"x-ratelimit-reset",
		"x-ratelimit-retry-after",
		"ratelimit-limit",
		"ratelimit-remaining",
		"ratelimit-reset",
		"ratelimit-policy",
		"retry-after",
	}
	sh.RateLimitHeaders = make(map[string]string)
	for _, h := range rateLimitHeaderNames {
		if v, ok := present[h]; ok {
			sh.RateLimitHeaders[h] = v
			sh.HasRateLimit = true
		}
	}

	// Cookie attribute checks.
	for _, cookie := range cookieLines {
		lower := strings.ToLower(cookie)
		var issues []string
		if !strings.Contains(lower, "secure") {
			issues = append(issues, "missing Secure")
		}
		if !strings.Contains(lower, "httponly") {
			issues = append(issues, "missing HttpOnly")
		}
		if !strings.Contains(lower, "samesite") {
			issues = append(issues, "missing SameSite")
		}
		if len(issues) > 0 {
			if m := reCookieName.FindStringSubmatch(cookie); m != nil {
				sh.InsecureCookies = append(sh.InsecureCookies, fmt.Sprintf("%s (%s)", m[1], strings.Join(issues, ", ")))
			}
		}
	}

	var findings []Finding

	if len(sh.MissingHeaders) > 0 {
		findings = append(findings, Finding{
			Tool:     "curl",
			Host:     host,
			Category: "Security Headers",
			Title:    "Security headers missing or misconfigured",
			Detail:   fmt.Sprintf("Missing: %s", strings.Join(sh.MissingHeaders, ", ")),
			Severity: SevLow,
		})
	}

	if len(sh.InsecureCookies) > 0 {
		findings = append(findings, Finding{
			Tool:     "curl",
			Host:     host,
			Category: "Session Management",
			Title:    "Insecure cookie attributes",
			Detail:   strings.Join(sh.InsecureCookies, "; "),
			Severity: SevLow,
		})
	}

	if sh.ServerHeader != "" {
		findings = append(findings, Finding{
			Tool:     "curl",
			Host:     host,
			Category: "Information Disclosure",
			Title:    "Server header discloses version information",
			Detail:   fmt.Sprintf("Server: %s", sh.ServerHeader),
			Severity: SevInfo,
		})
	}

	if sh.XPoweredByHeader != "" {
		findings = append(findings, Finding{
			Tool:     "curl",
			Host:     host,
			Category: "Information Disclosure",
			Title:    "X-Powered-By header present",
			Detail:   fmt.Sprintf("X-Powered-By: %s", sh.XPoweredByHeader),
			Severity: SevInfo,
		})
	}

	if !sh.HasRateLimit {
		findings = append(findings, Finding{
			Tool:     "curl",
			Host:     host,
			Category: "Rate Limiting",
			Title:    "No rate limiting headers observed",
			Detail:   "No X-RateLimit-* or RateLimit-* headers present — verify manually whether rate limiting is enforced at the application or infrastructure layer",
			Severity: SevInfo,
		})
	}

	return sh, findings, nil
}

// ---- feroxbuster -----------------------------------------------------------

type feroxEntry struct {
	Type          string `json:"type"`
	URL           string `json:"url"`
	Status        int    `json:"status"`
	ContentLength int    `json:"content_length"`
}

var sensitivePathPatterns = []struct {
	pattern  *regexp.Regexp
	title    string
	severity Severity
}{
	{regexp.MustCompile(`/\.git/`), "Source code disclosure (.git directory accessible)", SevHigh},
	{regexp.MustCompile(`/\.env$`), "Environment file exposed (.env)", SevHigh},
	{regexp.MustCompile(`\.(bak|old|zip|tar|sql|backup)$`), "Backup file accessible", SevHigh},
	{regexp.MustCompile(`phpinfo\.php$`), "phpinfo() page exposed", SevMedium},
	{regexp.MustCompile(`/server-status$`), "Apache server-status page exposed", SevMedium},
	{regexp.MustCompile(`/server-info$`), "Apache server-info page exposed", SevMedium},
	{regexp.MustCompile(`web\.config$`), "web.config file accessible", SevHigh},
}

// ParseFeroxbuster parses a feroxbuster JSONL output file and returns notable findings.
func ParseFeroxbuster(path, host string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading feroxbuster output %s: %w", path, err)
	}

	var findings []Finding
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
		if e.Type != "response" || (e.Status != 200 && e.Status != 301 && e.Status != 302) {
			continue
		}

		for _, p := range sensitivePathPatterns {
			if p.pattern.MatchString(e.URL) {
				findings = append(findings, Finding{
					Tool:     "feroxbuster",
					Host:     host,
					Category: "Content Discovery",
					Title:    p.title,
					Detail:   fmt.Sprintf("URL: %s (HTTP %d)", e.URL, e.Status),
					Severity: p.severity,
				})
				break
			}
		}
	}
	return findings, scanner.Err()
}

// ---- gitleaks / trufflehog ------------------------------------------------

type gitleaksEntry struct {
	RuleID    string `json:"RuleID"`
	Secret    string `json:"Secret"`
	File      string `json:"File"`
	StartLine int    `json:"StartLine"`
	Commit    string `json:"Commit,omitempty"`
}

// ParseGitleaks parses a gitleaks JSON report and returns findings.
func ParseGitleaks(path, host string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading gitleaks output %s: %w", path, err)
	}

	var entries []gitleaksEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parsing gitleaks JSON: %w", err)
	}

	var findings []Finding
	for _, e := range entries {
		secret := e.Secret
		if len(secret) > 20 {
			secret = secret[:20] + "…"
		}
		findings = append(findings, Finding{
			Tool:     "gitleaks",
			Host:     host,
			Category: "Secrets / Credentials",
			Title:    fmt.Sprintf("Secret exposed: %s", e.RuleID),
			Detail:   fmt.Sprintf("File: %s:%d | Value: %s", e.File, e.StartLine, secret),
			Severity: SevCritical,
		})
	}
	return findings, nil
}

type truffleEntry struct {
	DetectorName string `json:"DetectorName"`
	Raw          string `json:"Raw"`
	Verified     bool   `json:"Verified"`
	SourceMetadata struct {
		Data struct {
			Filesystem struct {
				File string `json:"file"`
				Line int64  `json:"line"`
			} `json:"Filesystem"`
		} `json:"Data"`
	} `json:"SourceMetadata"`
}

// ParseTrufflehog parses trufflehog JSONL output. Unverified findings are
// noted but marked Suppress=true (written to secrets_unverified.json instead).
func ParseTrufflehog(path, host string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading trufflehog output %s: %w", path, err)
	}

	var findings []Finding
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var e truffleEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		raw := e.Raw
		if len(raw) > 20 {
			raw = raw[:20] + "…"
		}
		file := e.SourceMetadata.Data.Filesystem.File
		findings = append(findings, Finding{
			Tool:     "trufflehog",
			Host:     host,
			Category: "Secrets / Credentials",
			Title:    fmt.Sprintf("Potential secret: %s", e.DetectorName),
			Detail:   fmt.Sprintf("File: %s | Value: %s", file, raw),
			Severity: SevCritical,
			Suppress: !e.Verified,
		})
	}
	return findings, scanner.Err()
}

// ---- wafw00f ---------------------------------------------------------------

// ParseWafw00f reads wafw00f JSON output and returns whether a WAF was detected
// and its name.
func ParseWafw00f(path string) (detected bool, wafName string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, "", fmt.Errorf("reading wafw00f output %s: %w", path, err)
	}

	// wafw00f JSON format: {"url": "...", "detected": true, "firewall": "Cloudflare", "manufacturer": "..."}
	var result struct {
		Detected     bool   `json:"detected"`
		Firewall     string `json:"firewall"`
		Manufacturer string `json:"manufacturer"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		// Try array format
		var results []struct {
			Detected bool   `json:"detected"`
			Firewall string `json:"firewall"`
		}
		if err2 := json.Unmarshal(data, &results); err2 == nil && len(results) > 0 {
			result.Detected = results[0].Detected
			result.Firewall = results[0].Firewall
		} else {
			return false, "", fmt.Errorf("parsing wafw00f JSON: %w", err)
		}
	}
	return result.Detected, result.Firewall, nil
}

// ---- dig AXFR --------------------------------------------------------------

// ParseDigAXFR reads dig AXFR output and returns true if a zone transfer succeeded.
func ParseDigAXFR(output, domain string) bool {
	// A successful AXFR contains multiple records including SOA at start and end.
	soaCount := 0
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, "SOA") {
			soaCount++
		}
	}
	// Zone transfer returns SOA twice (beginning and end of transfer)
	return soaCount >= 2
}

// ParseSubdomainList reads a file containing one subdomain per line.
func ParseSubdomainList(path string) ([]string, error) {
	lines, err := readLines(path)
	if err != nil {
		return nil, err
	}
	return lines, nil
}

// ParseNessusXML parses a .nessus XML file and returns Critical/High/Medium findings.
// Low and Informational items are returned separately.
func ParseNessusXML(path string) (reportItems []NessusItem, lowInfo []NessusItem, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("reading .nessus file %s: %w", path, err)
	}

	var report nessusReport
	if err := xml.Unmarshal(data, &report); err != nil {
		return nil, nil, fmt.Errorf("parsing .nessus XML: %w", err)
	}

	for _, host := range report.Report.ReportHosts {
		for _, item := range host.ReportItems {
			ni := NessusItem{
				PluginID:   item.PluginID,
				PluginName: item.PluginName,
				Host:       host.Name,
				Severity:   item.Severity,
				CVE:        item.CVE,
				Synopsis:   item.Synopsis,
				Description: item.Description,
				Solution:   item.Solution,
			}
			switch item.Severity {
			case 3, 4: // High, Critical
				reportItems = append(reportItems, ni)
			case 2: // Medium — filtered
				if shouldIncludeNessusMedium(ni) {
					reportItems = append(reportItems, ni)
				} else {
					lowInfo = append(lowInfo, ni)
				}
			default: // Low, Informational
				lowInfo = append(lowInfo, ni)
			}
		}
	}
	return reportItems, lowInfo, nil
}

// NessusItem represents a single Nessus finding.
type NessusItem struct {
	PluginID    string
	PluginName  string
	Host        string
	Severity    int
	CVE         string
	Synopsis    string
	Description string
	Solution    string
}

func shouldIncludeNessusMedium(item NessusItem) bool {
	lower := strings.ToLower(item.PluginName + " " + item.Synopsis)
	impactful := []string{
		"default credentials",
		"default password",
		"dangerous http method",
		"exploit",
		"remote code",
	}
	for _, k := range impactful {
		if strings.Contains(lower, k) {
			return true
		}
	}
	return false
}

type nessusReport struct {
	XMLName xml.Name `xml:"NessusClientData_v2"`
	Report  struct {
		ReportHosts []struct {
			Name        string `xml:"name,attr"`
			ReportItems []struct {
				PluginID    string `xml:"pluginID,attr"`
				PluginName  string `xml:"pluginName,attr"`
				Severity    int    `xml:"severity,attr"`
				CVE         string `xml:"cve"`
				Synopsis    string `xml:"synopsis"`
				Description string `xml:"description"`
				Solution    string `xml:"solution"`
			} `xml:"ReportItem"`
		} `xml:"ReportHost"`
	} `xml:"Report"`
}

// ParseOutOfScopeList reads the out_of_scope.txt file if present.
func ParseOutOfScopeList(engDir string) []string {
	lines, _ := readLines(filepath.Join(engDir, "other", "out_of_scope.txt"))
	return lines
}

// ---- ffuf vhost ------------------------------------------------------------

type ffufResult struct {
	Results []struct {
		Input  map[string]string `json:"input"`
		Status int               `json:"status"`
		Length int               `json:"length"`
	} `json:"results"`
}

// ParseFFufVhost parses ffuf JSON output from a vhost fuzzing run and returns
// findings for each discovered virtual host.
func ParseFFufVhost(path, domain string) ([]Finding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading ffuf output %s: %w", path, err)
	}
	var result ffufResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("parsing ffuf JSON: %w", err)
	}
	var findings []Finding
	for _, r := range result.Results {
		vhost := r.Input["FUZZ"]
		if vhost == "" {
			continue
		}
		fullVhost := fmt.Sprintf("%s.%s", vhost, domain)
		findings = append(findings, Finding{
			Tool:     "ffuf",
			Host:     domain,
			Category: "Virtual Host Discovery",
			Title:    fmt.Sprintf("Virtual host discovered: %s", fullVhost),
			Detail:   fmt.Sprintf("HTTP %d, %d bytes — vhost not in DNS but responds differently from baseline", r.Status, r.Length),
			Severity: SevMedium,
		})
	}
	return findings, nil
}

// ---- GitHub dorking ---------------------------------------------------------

type ghSearchResult struct {
	Repository struct {
		NameWithOwner string `json:"nameWithOwner"`
		URL           string `json:"url"`
	} `json:"repository"`
	Path string `json:"path"`
	URL  string `json:"url"`
}

// parseGitdorkResults parses gh search code JSON output and returns findings
// for each unique repository that contains the domain + sensitive keyword.
func parseGitdorkResults(output, domain, keyword string) []Finding {
	output = strings.TrimSpace(output)
	if output == "" || output == "[]" {
		return nil
	}
	var results []ghSearchResult
	if err := json.Unmarshal([]byte(output), &results); err != nil {
		return nil
	}
	var findings []Finding
	for _, r := range results {
		repo := r.Repository.NameWithOwner
		if repo == "" {
			continue
		}
		fileURL := r.URL
		if fileURL == "" {
			fileURL = fmt.Sprintf("%s/blob/HEAD/%s", r.Repository.URL, r.Path)
		}
		findings = append(findings, Finding{
			Tool:     "gh",
			Host:     domain,
			Category: "GitHub Exposure",
			Title:    fmt.Sprintf("GitHub code references target with keyword \"%s\"", keyword),
			Detail:   fmt.Sprintf("Repo: %s | File: %s | URL: %s", repo, r.Path, fileURL),
			Severity: SevMedium,
		})
	}
	return findings
}

// ---- robots.txt / sitemap --------------------------------------------------

// ParseRobotsTxt parses robots.txt content and returns the full URLs implied by
// every Disallow and Allow directive, using baseURL as the scheme+host prefix.
// Paths that are just "/" or empty are skipped — they are not useful as endpoints.
func ParseRobotsTxt(content, baseURL string) []string {
	base := strings.TrimRight(baseURL, "/")
	seen := make(map[string]struct{})
	var urls []string

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		var path string
		switch {
		case strings.HasPrefix(strings.ToLower(line), "disallow:"):
			path = strings.TrimSpace(line[len("disallow:"):])
		case strings.HasPrefix(strings.ToLower(line), "allow:"):
			path = strings.TrimSpace(line[len("allow:"):])
		default:
			continue
		}
		// Strip inline comments
		if i := strings.Index(path, "#"); i >= 0 {
			path = strings.TrimSpace(path[:i])
		}
		if path == "" || path == "/" {
			continue
		}
		// Wildcard patterns are useful as-is for the tester but not routable URLs
		if strings.ContainsAny(path, "*?") {
			continue
		}
		full := base + path
		if _, ok := seen[full]; !ok {
			seen[full] = struct{}{}
			urls = append(urls, full)
		}
	}
	return urls
}

// ParseSitemapXML extracts all <loc> URL values from a sitemap or sitemap index
// document. Works for both sitemap.xml and sitemap_index.xml formats.
func ParseSitemapXML(content string) []string {
	var urls []string
	seen := make(map[string]struct{})

	// Simple regex extraction — avoids a full XML parse that can choke on
	// malformed sitemaps, which are surprisingly common.
	reLoc := regexp.MustCompile(`(?i)<loc>\s*(https?://[^\s<]+)\s*</loc>`)
	for _, m := range reLoc.FindAllStringSubmatch(content, -1) {
		u := strings.TrimSpace(m[1])
		if _, ok := seen[u]; !ok {
			seen[u] = struct{}{}
			urls = append(urls, u)
		}
	}
	return urls
}
