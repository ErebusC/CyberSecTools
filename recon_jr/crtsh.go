package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

const crtshMaxRetries = 3
const crtshRetryDelay = 4 * time.Second

const crtshURL = "https://crt.sh/?q=%s&output=json"

type crtshEntry struct {
	NameValue string `json:"name_value"`
}

// queryCRTSH queries the crt.sh certificate transparency API for subdomains of
// domain and writes unique results to other/crtsh_<domain>.txt. Returns the
// list of discovered subdomains.
func queryCRTSH(engDir, domain string) ([]string, error) {
	logInfo("  [run]  crt.sh query for %s", domain)
	if dryRun {
		logInfo("  [dry-run] would query crt.sh for %s", domain)
		return nil, nil
	}

	client := &http.Client{Timeout: 30 * time.Second}
	reqURL := fmt.Sprintf(crtshURL, url.QueryEscape("%."+domain))

	var body []byte
	var lastErr error
	for attempt := 1; attempt <= crtshMaxRetries; attempt++ {
		resp, err := client.Get(reqURL)
		if err != nil {
			lastErr = fmt.Errorf("crt.sh request for %s: %w", domain, err)
			if attempt < crtshMaxRetries {
				logDebug("crt.sh: attempt %d/%d failed for %s, retrying in %s", attempt, crtshMaxRetries, domain, crtshRetryDelay)
				time.Sleep(crtshRetryDelay)
			}
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			lastErr = fmt.Errorf("crt.sh returned HTTP 429 for %s", domain)
			if attempt < crtshMaxRetries {
				logDebug("crt.sh: rate limited for %s, retrying in %s", domain, crtshRetryDelay)
				time.Sleep(crtshRetryDelay)
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("crt.sh returned HTTP %d for %s", resp.StatusCode, domain)
		}
		body, err = io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("reading crt.sh response for %s: %w", domain, err)
			if attempt < crtshMaxRetries {
				time.Sleep(crtshRetryDelay)
			}
			continue
		}
		lastErr = nil
		break
	}
	if lastErr != nil {
		return nil, lastErr
	}

	var entries []crtshEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("parsing crt.sh JSON for %s: %w", domain, err)
	}

	seen := make(map[string]struct{})
	var hosts []string
	for _, e := range entries {
		// name_value may contain newline-separated names (wildcard entries)
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			if name == "" || strings.HasPrefix(name, "*.") {
				continue
			}
			if _, ok := seen[name]; !ok {
				seen[name] = struct{}{}
				hosts = append(hosts, name)
			}
		}
	}

	outFile := filepath.Join(engDir, "other", fmt.Sprintf("crtsh_%s.txt", sanitizeForFilename(domain)))
	if err := writeLinesToFile(outFile, hosts); err != nil {
		logWarn("crt.sh: could not write output for %s: %v", domain, err)
	}

	logDebug("crt.sh: found %d subdomains for %s", len(hosts), domain)
	return hosts, nil
}
