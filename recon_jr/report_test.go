package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRenderReport(t *testing.T) {
	dir := t.TempDir()

	rd := &ReportData{
		EngagementName: "TEST-2024",
		GeneratedAt:    time.Now(),
		PhaseStatus: map[string]PhaseStatus{
			"phase1": {Status: "completed"},
			"phase3": {Status: "completed"},
			"phase5": {Status: "completed"},
			"phase7": {Status: "completed"},
		},
		DiscoveredHosts: []string{"example.com", "sub.example.com"},
		HTTPHosts:       []string{"https://example.com"},
		Domains:         []string{"example.com"},
		CMSDetected:     map[string]string{"https://example.com": "wordpress"},
		WAFDetected:     map[string]string{"https://example.com": "Cloudflare"},
		AllFindings: []Finding{
			{
				Tool:     "testssl",
				Host:     "example.com",
				Category: "TLS / SSL",
				Title:    "TLS issue: TLS1",
				Detail:   "offered (deprecated)",
				Severity: SevMedium,
			},
			{
				Tool:     "nuclei",
				Host:     "https://example.com",
				Category: "Vulnerability Scan",
				Title:    "SQL Injection",
				Detail:   "Template: sqli-basic",
				Severity: SevCritical,
			},
			{
				Tool:     "curl",
				Host:     "https://example.com",
				Category: "Security Headers",
				Title:    "Security headers missing",
				Detail:   "Missing: strict-transport-security",
				Severity: SevLow,
			},
			{
				Tool:     "trufflehog",
				Host:     "example.com",
				Category: "Secrets",
				Title:    "Potential secret",
				Detail:   "unverified",
				Severity: SevCritical,
				Suppress: true, // should not appear in report
			},
		},
	}

	if err := RenderReport(dir, rd); err != nil {
		t.Fatalf("RenderReport: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(dir, reportFile))
	if err != nil {
		t.Fatalf("reading report: %v", err)
	}
	report := string(content)

	// Check key sections are present
	checks := []string{
		"# Recon Report — TEST-2024",
		"## Summary",
		"Phase 1",
		"Phase 7",
		"## Phase 1 — DNS",
		"## Phase 2 — Host Probing",
		"Cloudflare",
		"wordpress",
		"SQL Injection",
		"TLS issue",
		"Security headers missing",
	}
	for _, check := range checks {
		if !strings.Contains(report, check) {
			t.Errorf("report missing expected content: %q", check)
		}
	}

	// Suppressed findings should not appear
	if strings.Contains(report, "Potential secret") {
		t.Error("suppressed finding should not appear in report")
	}
}

func TestReportDataAddFindingDedup(t *testing.T) {
	rd := &ReportData{}
	f := Finding{Tool: "nuclei", Host: "example.com", Title: "XSS", Severity: SevHigh}

	rd.AddFinding(f)
	rd.AddFinding(f) // duplicate
	rd.AddFinding(Finding{Tool: "nuclei", Host: "example.com", Title: "SQLi", Severity: SevCritical})

	if len(rd.AllFindings) != 2 {
		t.Errorf("expected 2 unique findings, got %d", len(rd.AllFindings))
	}
}

func TestReportDataAddFindings(t *testing.T) {
	rd := &ReportData{}
	findings := []Finding{
		{Tool: "nmap", Host: "1.2.3.4", Title: "RDP exposed", Severity: SevHigh},
		{Tool: "nmap", Host: "1.2.3.5", Title: "SMB exposed", Severity: SevHigh},
	}
	rd.AddFindings(findings)
	if len(rd.AllFindings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(rd.AllFindings))
	}
}

func TestFilterFindings(t *testing.T) {
	findings := []Finding{
		{Tool: "nmap", Severity: SevHigh},
		{Tool: "curl", Severity: SevLow},
		{Tool: "nmap", Severity: SevMedium},
	}

	nmapOnly := filterFindings(findings, func(f Finding) bool {
		return f.Tool == "nmap"
	})
	if len(nmapOnly) != 2 {
		t.Errorf("expected 2 nmap findings, got %d", len(nmapOnly))
	}

	highOnly := filterFindings(findings, func(f Finding) bool {
		return f.Severity >= SevHigh
	})
	if len(highOnly) != 1 {
		t.Errorf("expected 1 high finding, got %d", len(highOnly))
	}
}

func TestReportEmptyFindings(t *testing.T) {
	dir := t.TempDir()
	rd := &ReportData{
		EngagementName: "EMPTY",
		GeneratedAt:    time.Now(),
		PhaseStatus:    map[string]PhaseStatus{},
		CMSDetected:    map[string]string{},
		WAFDetected:    map[string]string{},
	}

	if err := RenderReport(dir, rd); err != nil {
		t.Fatalf("RenderReport with no findings: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, reportFile)); err != nil {
		t.Error("report file should exist even with no findings")
	}
}
