package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var rePlainIP = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)

// readLines reads a file and returns all non-blank, non-comment lines.
// Returns nil (not an error) if the file does not exist.
func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, scanner.Err()
}

// findHostsFile returns the path of the hosts file in engDir, trying
// "hosts", "hosts.txt", and "host.txt" in that order. Returns an empty
// string if none exist.
func findHostsFile(engDir string) string {
	for _, name := range []string{"hosts", "hosts.txt", "host.txt"} {
		p := filepath.Join(engDir, name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// masterHostList reads the host files written by engage_jr and returns the combined,
// deduplicated host lists. Returns allHosts (everything), httpHosts (URLs), noHTTPHosts.
func masterHostList(engDir string) (all, http, noHTTP []string, err error) {
	hostsFile := findHostsFile(engDir)
	if hostsFile == "" {
		return nil, nil, nil, fmt.Errorf("no hosts file found in %s (tried hosts, hosts.txt, host.txt)", engDir)
	}
	all, err = readLines(hostsFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reading hosts: %w", err)
	}
	http, err = readLines(filepath.Join(engDir, "http_hosts"))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reading http_hosts: %w", err)
	}
	noHTTP, err = readLines(filepath.Join(engDir, "nohttp_hosts"))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reading nohttp_hosts: %w", err)
	}
	return all, http, noHTTP, nil
}

// mergeDiscovered reads discovered_hosts from the engagement directory and
// returns a deduplicated union with existing. New hosts discovered by Phase 1
// that pass scope filtering are written here.
func mergeDiscovered(engDir string, existing []string) ([]string, error) {
	discovered, err := readLines(filepath.Join(engDir, "discovered_hosts"))
	if err != nil {
		return nil, fmt.Errorf("reading discovered_hosts: %w", err)
	}

	seen := make(map[string]struct{}, len(existing))
	for _, h := range existing {
		seen[h] = struct{}{}
	}

	merged := make([]string, len(existing))
	copy(merged, existing)
	for _, h := range discovered {
		if _, ok := seen[h]; !ok {
			seen[h] = struct{}{}
			merged = append(merged, h)
		}
	}
	return merged, nil
}

// writeDiscoveredHosts writes hosts to the discovered_hosts file in engDir,
// deduplicating against any entries already present in the file.
func writeDiscoveredHosts(engDir string, hosts []string) error {
	if len(hosts) == 0 {
		return nil
	}

	existing, err := readLines(filepath.Join(engDir, "discovered_hosts"))
	if err != nil {
		return err
	}

	seen := make(map[string]struct{}, len(existing))
	for _, h := range existing {
		seen[h] = struct{}{}
	}

	f, err := os.OpenFile(
		filepath.Join(engDir, "discovered_hosts"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY,
		0644,
	)
	if err != nil {
		return fmt.Errorf("opening discovered_hosts: %w", err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, h := range hosts {
		if _, ok := seen[h]; !ok {
			seen[h] = struct{}{}
			fmt.Fprintln(w, h)
		}
	}
	return w.Flush()
}

// writeDiscoveredEndpoints appends endpoints to the discovered_endpoints file,
// deduplicating against existing entries.
func writeDiscoveredEndpoints(engDir string, endpoints []string) error {
	if len(endpoints) == 0 {
		return nil
	}

	existing, err := readLines(filepath.Join(engDir, "discovered_endpoints"))
	if err != nil {
		return err
	}

	seen := make(map[string]struct{}, len(existing))
	for _, e := range existing {
		seen[e] = struct{}{}
	}

	f, err := os.OpenFile(
		filepath.Join(engDir, "discovered_endpoints"),
		os.O_APPEND|os.O_CREATE|os.O_WRONLY,
		0644,
	)
	if err != nil {
		return fmt.Errorf("opening discovered_endpoints: %w", err)
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, e := range endpoints {
		if _, ok := seen[e]; !ok {
			seen[e] = struct{}{}
			fmt.Fprintln(w, e)
		}
	}
	return w.Flush()
}

// extractRootDomains returns the unique root domains (last two labels) from a
// list of hosts, skipping plain IPs. For hosts with only one label, the host
// itself is returned as-is.
func extractRootDomains(hosts []string) []string {
	seen := make(map[string]struct{})
	var domains []string
	for _, h := range hosts {
		// Strip scheme if present
		h = strings.TrimPrefix(h, "https://")
		h = strings.TrimPrefix(h, "http://")
		if i := strings.Index(h, "/"); i != -1 {
			h = h[:i]
		}
		if rePlainIP.MatchString(h) {
			continue
		}
		parts := strings.Split(h, ".")
		var root string
		if len(parts) >= 2 {
			root = strings.Join(parts[len(parts)-2:], ".")
		} else {
			root = h
		}
		if root == "" {
			continue
		}
		if _, ok := seen[root]; !ok {
			seen[root] = struct{}{}
			domains = append(domains, root)
		}
	}
	return domains
}

// filterEndpointsInScope filters a list of endpoints against scope.
// Relative paths (no scheme) are always kept — they're relative to an already
// in-scope host. Absolute URLs are checked via scope.Contains.
func filterEndpointsInScope(endpoints []string, scope *Scope) (inScope, outOfScope []string) {
	for _, ep := range endpoints {
		if !strings.Contains(ep, "://") {
			inScope = append(inScope, ep)
			continue
		}
		if scope.Contains(ep) {
			inScope = append(inScope, ep)
		} else {
			outOfScope = append(outOfScope, ep)
		}
	}
	return
}

// deduplicateHosts returns a new slice with duplicate entries removed, preserving order.
func deduplicateHosts(hosts []string) []string {
	seen := make(map[string]struct{}, len(hosts))
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if _, ok := seen[h]; !ok {
			seen[h] = struct{}{}
			out = append(out, h)
		}
	}
	return out
}

// sanitizeForFilename converts a host or URL into a string safe for use in a filename.
func sanitizeForFilename(s string) string {
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimSuffix(s, "/")
	replacer := strings.NewReplacer(
		"/", "_",
		":", "_",
		" ", "_",
		"*", "_",
		"?", "_",
		"&", "_",
	)
	return replacer.Replace(s)
}

// ensureDir creates dir and all parents if they do not exist.
func ensureDir(dir string) error {
	return os.MkdirAll(dir, 0755)
}

// writeLinesToFile writes lines to path, one per line.
func writeLinesToFile(path string, lines []string) error {
	if err := ensureDir(filepath.Dir(path)); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
	return w.Flush()
}
