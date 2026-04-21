package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestNewNessusClient(t *testing.T) {
	c := newNessusClient("https://nessus.test:8834", "key1", "secret1", false)
	if c.baseURL != "https://nessus.test:8834" {
		t.Errorf("baseURL: %q", c.baseURL)
	}
	authHeader := c.headers.Get("X-ApiKeys")
	if authHeader != "accessKey=key1;secretKey=secret1" {
		t.Errorf("X-ApiKeys: %q", authHeader)
	}
}

func TestNessusClientCreateScan(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/scans" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.Error(w, "unexpected", http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"scan": map[string]interface{}{"id": 42},
		})
	}))
	defer srv.Close()

	c := newNessusClient(srv.URL, "key", "secret", false)
	id, err := c.createScan("TEST-001", []string{"example.com"}, "template-uuid")
	if err != nil {
		t.Fatalf("createScan: %v", err)
	}
	if id != 42 {
		t.Errorf("scan ID: got %d, want 42", id)
	}
}

func TestNessusClientLaunchScan(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/scans/42/launch" {
			http.Error(w, "unexpected", http.StatusBadRequest)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"scan_uuid": "abc-123"})
	}))
	defer srv.Close()

	c := newNessusClient(srv.URL, "key", "secret", false)
	uuid, err := c.launchScan(42)
	if err != nil {
		t.Fatalf("launchScan: %v", err)
	}
	if uuid != "abc-123" {
		t.Errorf("scan UUID: got %q", uuid)
	}
}

func TestNessusClientScanStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"info": map[string]string{"status": "completed"},
		})
	}))
	defer srv.Close()

	c := newNessusClient(srv.URL, "key", "secret", false)
	status, err := c.scanStatus(42)
	if err != nil {
		t.Fatalf("scanStatus: %v", err)
	}
	if status != "completed" {
		t.Errorf("status: got %q, want completed", status)
	}
}

func TestNessusClientPollUntilComplete(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		status := "running"
		if callCount >= 2 {
			status = "completed"
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"info": map[string]string{"status": status},
		})
	}))
	defer srv.Close()

	c := newNessusClient(srv.URL, "key", "secret", false)
	// Use 1-second poll interval, 1-minute max
	status, err := c.pollUntilComplete(42, 0, 1)
	if err != nil {
		t.Fatalf("pollUntilComplete: %v", err)
	}
	if status != "completed" {
		t.Errorf("final status: %q", status)
	}
}

func TestNessusClientHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := newNessusClient(srv.URL, "bad-key", "bad-secret", false)
	_, err := c.createScan("test", []string{"host"}, "uuid")
	if err == nil {
		t.Error("expected error for HTTP 401")
	}
}

func TestParseNessusXML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.nessus")

	// Minimal .nessus XML with one critical and one informational finding
	data := `<?xml version="1.0"?>
<NessusClientData_v2>
  <Report name="TEST">
    <ReportHost name="192.168.1.1">
      <ReportItem pluginID="1234" pluginName="Critical Vuln" severity="4">
        <synopsis>Critical vulnerability found</synopsis>
        <description>A critical issue exists.</description>
        <solution>Apply patch.</solution>
      </ReportItem>
      <ReportItem pluginID="5678" pluginName="Info Item" severity="0">
        <synopsis>Informational finding</synopsis>
        <description>This is informational.</description>
        <solution>None required.</solution>
      </ReportItem>
      <ReportItem pluginID="9999" pluginName="Default Credentials" severity="2">
        <synopsis>Default credentials detected</synopsis>
        <description>Default credentials found.</description>
        <solution>Change defaults.</solution>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>`
	os.WriteFile(path, []byte(data), 0644)

	report, lowInfo, err := ParseNessusXML(path)
	if err != nil {
		t.Fatalf("ParseNessusXML: %v", err)
	}

	// Critical and the "default credentials" medium should be in reportItems
	if len(report) < 2 {
		t.Errorf("expected at least 2 report items, got %d: %v", len(report), report)
	}

	// Informational should be in lowInfo
	if len(lowInfo) == 0 {
		t.Error("expected at least 1 low/info item")
	}

	// Verify the critical finding
	var foundCrit bool
	for _, item := range report {
		if item.Severity == 4 {
			foundCrit = true
		}
	}
	if !foundCrit {
		t.Error("expected critical finding in report items")
	}
}

func TestShouldIncludeNessusMedium(t *testing.T) {
	tests := []struct {
		item NessusItem
		want bool
	}{
		{NessusItem{PluginName: "Default Credentials Detected"}, true},
		{NessusItem{PluginName: "Dangerous HTTP Methods"}, true},
		{NessusItem{Synopsis: "Remote code execution possible"}, true},
		{NessusItem{PluginName: "SSL Certificate Expiry"}, false},
		{NessusItem{PluginName: "TLS BEAST"}, false},
	}
	for _, tt := range tests {
		if got := shouldIncludeNessusMedium(tt.item); got != tt.want {
			t.Errorf("shouldIncludeNessusMedium(%v) = %v, want %v", tt.item.PluginName, got, tt.want)
		}
	}
}
