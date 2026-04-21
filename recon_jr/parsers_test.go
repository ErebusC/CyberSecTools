package main

import (
	"os"
	"path/filepath"
	"testing"
)

// ---- testssl ---------------------------------------------------------------

func TestParseTestSSL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "testssl.json")

	// Simulate testssl JSON with a mix of reportable and suppressed entries
	data := `[
		{"id":"TLS1","severity":"MEDIUM","finding":"offered (deprecated)","ip":"1.2.3.4","port":"443"},
		{"id":"SSLv2","severity":"CRITICAL","finding":"offered","ip":"1.2.3.4","port":"443"},
		{"id":"OK_field","severity":"OK","finding":"not offered","ip":"1.2.3.4","port":"443"},
		{"id":"HEARTBLEED","severity":"CRITICAL","finding":"vulnerable","ip":"1.2.3.4","port":"443"},
		{"id":"cipher_order","severity":"WARN","finding":"not offered","ip":"1.2.3.4","port":"443"}
	]`
	os.WriteFile(path, []byte(data), 0644)

	findings, err := ParseTestSSL(path, "1.2.3.4")
	if err != nil {
		t.Fatalf("ParseTestSSL: %v", err)
	}

	// SSLv2 + TLS1 + HEARTBLEED should be included; OK and suppressed should not
	if len(findings) < 2 {
		t.Errorf("expected at least 2 findings, got %d", len(findings))
	}

	hasCritical := false
	for _, f := range findings {
		if f.Severity == SevCritical {
			hasCritical = true
		}
	}
	if !hasCritical {
		t.Error("expected at least one critical finding (SSLv2 or HEARTBLEED)")
	}
}

func TestParseTestSSLSuppressed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "testssl.json")

	// All entries should be suppressed
	data := `[
		{"id":"INFO","severity":"INFO","finding":"not offered","ip":"1.2.3.4","port":"443"},
		{"id":"OK_thing","severity":"OK","finding":"not vulnerable","ip":"1.2.3.4","port":"443"}
	]`
	os.WriteFile(path, []byte(data), 0644)

	findings, err := ParseTestSSL(path, "1.2.3.4")
	if err != nil {
		t.Fatalf("ParseTestSSL: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for suppressed entries, got %d", len(findings))
	}
}

// ---- security headers ------------------------------------------------------

func TestParseSecurityHeaders(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "headers.txt")

	// Response missing several security headers
	data := `HTTP/2 200
Content-Type: text/html
Server: nginx/1.18.0
X-Powered-By: PHP/7.4
Set-Cookie: session=abc123; Path=/
Set-Cookie: auth=xyz; Secure; HttpOnly; SameSite=Strict
`
	os.WriteFile(path, []byte(data), 0644)

	sh, findings, err := ParseSecurityHeaders(path, "example.com")
	if err != nil {
		t.Fatalf("ParseSecurityHeaders: %v", err)
	}

	if sh.ServerHeader != "nginx/1.18.0" {
		t.Errorf("ServerHeader: got %q", sh.ServerHeader)
	}
	if sh.XPoweredByHeader != "PHP/7.4" {
		t.Errorf("XPoweredByHeader: got %q", sh.XPoweredByHeader)
	}
	if len(sh.MissingHeaders) == 0 {
		t.Error("expected missing headers")
	}

	// First cookie (session) is missing Secure/HttpOnly/SameSite
	if len(sh.InsecureCookies) == 0 {
		t.Error("expected at least one insecure cookie")
	}

	// Should have findings for missing headers, insecure cookies, server disclosure
	if len(findings) < 2 {
		t.Errorf("expected at least 2 findings, got %d", len(findings))
	}
}

func TestParseSecurityHeadersAllPresent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "headers_good.txt")

	data := `HTTP/2 200
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=()
`
	os.WriteFile(path, []byte(data), 0644)

	sh, findings, err := ParseSecurityHeaders(path, "secure.example.com")
	if err != nil {
		t.Fatalf("ParseSecurityHeaders: %v", err)
	}

	if len(sh.MissingHeaders) != 0 {
		t.Errorf("expected no missing headers, got: %v", sh.MissingHeaders)
	}

	// Should have no findings (or only info-level)
	for _, f := range findings {
		if f.Severity >= SevLow {
			t.Errorf("unexpected finding: %+v", f)
		}
	}
}

// ---- nuclei ----------------------------------------------------------------

func TestParseNuclei(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nuclei.json")

	data := `{"template-id":"CVE-2022-1234","name":"","severity":"high","host":"https://example.com","matched-at":"https://example.com/admin","info":{"name":"Admin Panel Exposed"}}
{"template-id":"INFO-001","name":"","severity":"info","host":"https://example.com","matched-at":"https://example.com","info":{"name":"Server Info"}}
{"template-id":"CVE-2021-9999","name":"","severity":"critical","host":"https://example.com","matched-at":"https://example.com/cve","info":{"name":"Critical Vuln"}}
`
	os.WriteFile(path, []byte(data), 0644)

	findings, err := ParseNuclei(path, "example.com")
	if err != nil {
		t.Fatalf("ParseNuclei: %v", err)
	}

	// Info should be filtered; high and critical should be included
	if len(findings) != 2 {
		t.Errorf("expected 2 findings (high+critical), got %d: %v", len(findings), findings)
	}

	sevMap := make(map[Severity]int)
	for _, f := range findings {
		sevMap[f.Severity]++
	}
	if sevMap[SevHigh] != 1 {
		t.Errorf("expected 1 high finding, got %d", sevMap[SevHigh])
	}
	if sevMap[SevCritical] != 1 {
		t.Errorf("expected 1 critical finding, got %d", sevMap[SevCritical])
	}
}

// ---- feroxbuster -----------------------------------------------------------

func TestParseFeroxbuster(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ferox.json")

	data := `{"type":"response","url":"https://example.com/.git/HEAD","status":200,"content_length":23}
{"type":"response","url":"https://example.com/normal/page.html","status":200,"content_length":1000}
{"type":"response","url":"https://example.com/backup.zip","status":200,"content_length":5000}
{"type":"response","url":"https://example.com/phpinfo.php","status":200,"content_length":100}
{"type":"statistics","requests":100}
`
	os.WriteFile(path, []byte(data), 0644)

	findings, err := ParseFeroxbuster(path, "https://example.com")
	if err != nil {
		t.Fatalf("ParseFeroxbuster: %v", err)
	}

	// .git, .zip, phpinfo.php should be flagged; normal page should not
	if len(findings) < 3 {
		t.Errorf("expected at least 3 findings, got %d", len(findings))
	}

	urls := make(map[string]bool)
	for _, f := range findings {
		urls[f.Detail] = true
	}
}

// ---- gitleaks --------------------------------------------------------------

func TestParseGitleaks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gitleaks.json")

	data := `[
		{"RuleID":"generic-api-key","Secret":"AKIA1234567890EXAMPLE","File":"config.js","StartLine":42},
		{"RuleID":"aws-secret-key","Secret":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY","File":"deploy.sh","StartLine":10}
	]`
	os.WriteFile(path, []byte(data), 0644)

	findings, err := ParseGitleaks(path, "example.com")
	if err != nil {
		t.Fatalf("ParseGitleaks: %v", err)
	}

	if len(findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(findings))
	}
	for _, f := range findings {
		if f.Severity != SevCritical {
			t.Errorf("expected critical severity, got %v", f.Severity)
		}
		// Secret should be truncated
		if len(f.Detail) > 200 {
			t.Errorf("detail too long: %q", f.Detail)
		}
	}
}

// ---- wafw00f ---------------------------------------------------------------

func TestParseWafw00f(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wafw00f.json")

	data := `{"url":"https://example.com","detected":true,"firewall":"Cloudflare","manufacturer":"Cloudflare Inc."}`
	os.WriteFile(path, []byte(data), 0644)

	detected, waf, err := ParseWafw00f(path)
	if err != nil {
		t.Fatalf("ParseWafw00f: %v", err)
	}
	if !detected {
		t.Error("expected WAF detected=true")
	}
	if waf != "Cloudflare" {
		t.Errorf("WAF name: got %q, want Cloudflare", waf)
	}
}

func TestParseWafw00fNotDetected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wafw00f.json")

	data := `{"url":"https://example.com","detected":false,"firewall":"None","manufacturer":""}`
	os.WriteFile(path, []byte(data), 0644)

	detected, _, err := ParseWafw00f(path)
	if err != nil {
		t.Fatalf("ParseWafw00f: %v", err)
	}
	if detected {
		t.Error("expected WAF detected=false")
	}
}

// ---- dig AXFR --------------------------------------------------------------

func TestParseDigAXFR(t *testing.T) {
	successOutput := `
; <<>> DiG 9.18 <<>> @ns1.example.com example.com AXFR
; (1 server found)
example.com.		3600	IN	SOA	ns1.example.com. admin.example.com. 2024010101 3600 900 604800 300
example.com.		3600	IN	NS	ns1.example.com.
www.example.com.	3600	IN	A	1.2.3.4
mail.example.com.	3600	IN	A	1.2.3.5
example.com.		3600	IN	SOA	ns1.example.com. admin.example.com. 2024010101 3600 900 604800 300
`
	if !ParseDigAXFR(successOutput, "example.com") {
		t.Error("expected AXFR success detection (2x SOA)")
	}

	failOutput := `
; Transfer failed.
; example.com: Transfer failed.
`
	if ParseDigAXFR(failOutput, "example.com") {
		t.Error("expected AXFR failure detection")
	}
}

// ---- nmap ------------------------------------------------------------------

func TestParseNmap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nmap.xml")

	// Nmap XML with RDP (3389) open — unexpected management port
	data := `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="1.2.3.4" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18"/>
      </port>
      <port protocol="tcp" portid="3389">
        <state state="open"/>
        <service name="ms-wbt-server" product="" version=""/>
      </port>
    </ports>
  </host>
</nmaprun>`
	os.WriteFile(path, []byte(data), 0644)

	findings, err := ParseNmap(path, "1.2.3.4")
	if err != nil {
		t.Fatalf("ParseNmap: %v", err)
	}

	// Port 80 is in default scope — no finding. Port 3389 (RDP) should be flagged.
	if len(findings) != 1 {
		t.Errorf("expected 1 finding (RDP), got %d: %v", len(findings), findings)
	}
	if findings[0].Severity != SevHigh {
		t.Errorf("RDP finding should be High severity, got %v", findings[0].Severity)
	}
}

// ---- severity strings ------------------------------------------------------

func TestSeverityString(t *testing.T) {
	tests := []struct{ sev Severity; want string }{
		{SevCritical, "Critical"},
		{SevHigh, "High"},
		{SevMedium, "Medium"},
		{SevLow, "Low"},
		{SevInfo, "Info"},
	}
	for _, tt := range tests {
		if got := tt.sev.String(); got != tt.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tt.sev, got, tt.want)
		}
	}
}
