package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// NessusClient manages interaction with the Nessus REST API.
type NessusClient struct {
	baseURL    string
	httpClient *http.Client
	headers    http.Header
}

// newNessusClient creates a new NessusClient. If insecureTLS is true, certificate
// verification is disabled (required for Nessus's default self-signed certificate).
// This must be explicitly set; it is never the default.
func newNessusClient(host, accessKey, secretKey string, insecureTLS bool) *NessusClient {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureTLS}, //nolint:gosec
	}
	headers := http.Header{}
	headers.Set("X-ApiKeys", fmt.Sprintf("accessKey=%s;secretKey=%s", accessKey, secretKey))
	headers.Set("Content-Type", "application/json")
	headers.Set("Accept", "application/json")

	return &NessusClient{
		baseURL: strings.TrimRight(host, "/"),
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   60 * time.Second,
		},
		headers: headers,
	}
}

func (c *NessusClient) do(method, path string, body interface{}) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshalling request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	for k, vs := range c.headers {
		for _, v := range vs {
			req.Header.Set(k, v)
		}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request %s %s: %w", method, path, err)
	}
	return resp, nil
}

func (c *NessusClient) doJSON(method, path string, body, out interface{}) error {
	resp, err := c.do(method, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d from Nessus: %s", resp.StatusCode, string(data))
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("parsing response JSON: %w", err)
		}
	}
	return nil
}

// createScan creates a Nessus scan using the pre-configured template UUID.
// Returns the new scan ID.
func (c *NessusClient) createScan(name string, targets []string, templateUUID string) (int64, error) {
	body := map[string]interface{}{
		"uuid": templateUUID,
		"settings": map[string]interface{}{
			"name":    name,
			"enabled": true,
			"text_targets": strings.Join(targets, "\n"),
		},
	}
	var resp struct {
		Scan struct {
			ID int64 `json:"id"`
		} `json:"scan"`
	}
	if err := c.doJSON("POST", "/scans", body, &resp); err != nil {
		return 0, fmt.Errorf("creating scan: %w", err)
	}
	return resp.Scan.ID, nil
}

// launchScan starts a Nessus scan by ID. Returns the scan UUID for the running scan.
func (c *NessusClient) launchScan(scanID int64) (string, error) {
	var resp struct {
		ScanUUID string `json:"scan_uuid"`
	}
	if err := c.doJSON("POST", fmt.Sprintf("/scans/%d/launch", scanID), nil, &resp); err != nil {
		return "", fmt.Errorf("launching scan %d: %w", scanID, err)
	}
	return resp.ScanUUID, nil
}

// scanStatus returns the current status string for a scan.
func (c *NessusClient) scanStatus(scanID int64) (string, error) {
	var resp struct {
		Info struct {
			Status string `json:"status"`
		} `json:"info"`
	}
	if err := c.doJSON("GET", fmt.Sprintf("/scans/%d", scanID), nil, &resp); err != nil {
		return "", fmt.Errorf("checking scan status for %d: %w", scanID, err)
	}
	return resp.Info.Status, nil
}

// pollUntilComplete polls scan status every pollSecs seconds until the scan reaches
// a terminal state or maxMins is exceeded. Returns the final status string.
func (c *NessusClient) pollUntilComplete(scanID int64, pollSecs, maxMins int) (string, error) {
	deadline := time.Now().Add(time.Duration(maxMins) * time.Minute)
	for {
		status, err := c.scanStatus(scanID)
		if err != nil {
			return "", err
		}
		logDebug("nessus: scan %d status: %s", scanID, status)

		switch status {
		case "completed":
			return status, nil
		case "aborted", "cancelled", "stopped", "paused":
			return status, nil
		}

		if time.Now().After(deadline) {
			return status, fmt.Errorf("scan %d timed out after %dm (status: %s)", scanID, maxMins, status)
		}

		time.Sleep(time.Duration(pollSecs) * time.Second)
	}
}

// exportScan initiates a .nessus file export. Returns the export token.
func (c *NessusClient) exportScan(scanID int64) (string, error) {
	body := map[string]string{"format": "nessus"}
	var resp struct {
		File string `json:"file"`
	}
	if err := c.doJSON("POST", fmt.Sprintf("/scans/%d/export", scanID), body, &resp); err != nil {
		return "", fmt.Errorf("requesting export for scan %d: %w", scanID, err)
	}
	return resp.File, nil
}

// pollExportReady polls until the export is ready for download.
func (c *NessusClient) pollExportReady(scanID int64, token string) error {
	for {
		var resp struct {
			Status string `json:"status"`
		}
		if err := c.doJSON("GET", fmt.Sprintf("/scans/%d/export/%s/status", scanID, token), nil, &resp); err != nil {
			return err
		}
		if resp.Status == "ready" {
			return nil
		}
		time.Sleep(5 * time.Second)
	}
}

// downloadScan downloads the .nessus export file to destPath.
func (c *NessusClient) downloadScan(scanID int64, token, destPath string) error {
	resp, err := c.do("GET", fmt.Sprintf("/scans/%d/export/%s/download", scanID, token), nil)
	if err != nil {
		return fmt.Errorf("downloading scan: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d downloading scan export", resp.StatusCode)
	}

	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("creating nessus output directory: %w", err)
	}
	f, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("creating .nessus file %s: %w", destPath, err)
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("writing .nessus file: %w", err)
	}
	return nil
}

// RunNessusScan executes the full 9-step Nessus API workflow against targets using
// the pre-configured scan template. Returns the path to the downloaded .nessus file.
//
// If a prior in-flight scan ID is present in meta (from a previous interrupted run),
// polling resumes from that scan rather than creating a new one.
func RunNessusScan(cfg *Config, engDir string, engName string, targets []string, meta *ReconMeta) (string, error) {
	if cfg.NessusInsecureTLS {
		logWarn("TLS verification disabled for Nessus — ensure you are on a trusted network")
	}

	client := newNessusClient(cfg.NessusHost, cfg.NessusAccessKey, cfg.NessusSecretKey, cfg.NessusInsecureTLS)

	scanID := meta.NessusScanID

	// Step 1: Create scan (or resume existing)
	if scanID == 0 {
		logInfo("  nessus: creating scan for %d targets", len(targets))
		var err error
		scanID, err = client.createScan(engName, targets, cfg.NessusTemplateUUID)
		if err != nil {
			return "", fmt.Errorf("creating Nessus scan: %w", err)
		}
		meta.NessusScanID = scanID
		logDebug("nessus: scan created with ID %d", scanID)

		// Step 2: Launch scan
		uuid, err := client.launchScan(scanID)
		if err != nil {
			return "", fmt.Errorf("launching Nessus scan %d: %w", scanID, err)
		}
		logDebug("nessus: scan %d launched (UUID: %s)", scanID, uuid)
	} else {
		logInfo("  nessus: resuming polling for existing scan %d", scanID)
	}

	// Step 3: Poll until complete or timeout
	logInfo("  nessus: polling scan %d (max %dm)", scanID, cfg.NessusMaxScanMins)
	status, err := client.pollUntilComplete(scanID, cfg.NessusPollSecs, cfg.NessusMaxScanMins)
	meta.NessusStatus = status

	if err != nil {
		logWarn("Nessus: %v — scan ID %d recorded in .recon.json for manual follow-up", err, scanID)
		return "", nil
	}

	if status != "completed" {
		logWarn("nessus: scan %d reached terminal state %q — skipping export", scanID, status)
		return "", nil
	}

	// Step 4: Export
	logInfo("  nessus: exporting scan %d", scanID)
	token, err := client.exportScan(scanID)
	if err != nil {
		return "", fmt.Errorf("exporting Nessus scan: %w", err)
	}

	// Step 5: Poll export ready
	if err := client.pollExportReady(scanID, token); err != nil {
		return "", fmt.Errorf("waiting for Nessus export: %w", err)
	}

	// Step 6: Download
	destPath := filepath.Join(engDir, "nessus", engName+".nessus")
	logInfo("  nessus: downloading scan to %s", destPath)
	if err := client.downloadScan(scanID, token, destPath); err != nil {
		return "", fmt.Errorf("downloading Nessus scan: %w", err)
	}

	logInfo("  nessus: scan complete — %s", destPath)
	return destPath, nil
}
