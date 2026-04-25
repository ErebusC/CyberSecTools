package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	reScopeIPRange = regexp.MustCompile(`^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$`)
	reScopeCIDR    = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$`)
	reScopeHTTP    = regexp.MustCompile(`^https?://`)
)

// Scope holds parsed scope entries for fast membership testing.
type Scope struct {
	cidrs   []*net.IPNet
	ips     map[string]struct{}
	domains []string // bare domains; subdomain matching applies
}

// loadScope reads a scope file (same format as engage_jr host files) from path
// and returns a Scope for membership testing.
func loadScope(path string) (*Scope, error) {
	lines, err := readLines(path)
	if err != nil {
		return nil, fmt.Errorf("reading scope file %s: %w", path, err)
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("scope file %s is empty", path)
	}

	s := &Scope{ips: make(map[string]struct{})}
	for _, line := range lines {
		if err := s.addEntry(line); err != nil {
			logWarn("scope: skipping %q: %v", line, err)
		}
	}
	return s, nil
}

// findScopeFile looks for scope.txt in engDir. Returns the path if found, or
// an empty string if the file is absent (implicit scope will be used instead).
func findScopeFile(engDir, cliScope string) string {
	if cliScope != "" {
		return cliScope
	}
	candidate := filepath.Join(engDir, "scope.txt")
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return ""
}

// findWebScopeFile looks for web_scope.txt in engDir. Returns the path if
// found, or an empty string if absent (web testing falls back to main scope).
func findWebScopeFile(engDir, cliWebScope string) string {
	if cliWebScope != "" {
		return cliWebScope
	}
	candidate := filepath.Join(engDir, "web_scope.txt")
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return ""
}

// resolveWebScope loads web_scope.txt if it exists. Returns nil when no web
// scope file is present — callers treat nil as "use main scope for everything".
func resolveWebScope(path string) (*Scope, error) {
	if path == "" {
		return nil, nil
	}
	scope, err := loadScope(path)
	if err != nil {
		return nil, fmt.Errorf("loading web scope file %s: %w", path, err)
	}
	logDebug("web scope loaded from %s", path)
	return scope, nil
}


func (s *Scope) addEntry(entry string) error {
	// Strip scheme for domain/host matching.
	raw := entry
	if reScopeHTTP.MatchString(entry) {
		raw = reScopeHTTP.ReplaceAllString(entry, "")
		if i := strings.Index(raw, "/"); i != -1 {
			raw = raw[:i]
		}
	}

	switch {
	case reScopeCIDR.MatchString(raw):
		_, network, err := net.ParseCIDR(raw)
		if err != nil {
			return fmt.Errorf("invalid CIDR %s: %w", raw, err)
		}
		s.cidrs = append(s.cidrs, network)

	case reScopeIPRange.MatchString(raw):
		ips, err := expandScopeRange(raw)
		if err != nil {
			return err
		}
		for _, ip := range ips {
			s.ips[ip] = struct{}{}
		}

	case rePlainIP.MatchString(raw):
		if net.ParseIP(raw) == nil {
			return fmt.Errorf("invalid IP: %s", raw)
		}
		s.ips[raw] = struct{}{}

	default:
		// Bare hostname or domain.
		s.domains = append(s.domains, strings.ToLower(raw))
	}
	return nil
}

// Contains reports whether host is within this scope.
// host should be a bare hostname, IP address, or URL. Scheme is stripped if present.
func (s *Scope) Contains(host string) bool {
	if host == "" {
		return false
	}
	// Strip scheme and path.
	host = reScopeHTTP.ReplaceAllString(host, "")
	if i := strings.Index(host, "/"); i != -1 {
		host = host[:i]
	}
	host = strings.ToLower(host)

	// IP check.
	if rePlainIP.MatchString(host) {
		ip := net.ParseIP(host)
		if ip == nil {
			return false
		}
		if _, ok := s.ips[host]; ok {
			return true
		}
		for _, cidr := range s.cidrs {
			if cidr.Contains(ip) {
				return true
			}
		}
		return false
	}

	// Hostname/domain check — exact match or subdomain of a scope entry.
	for _, d := range s.domains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// FilterInScope partitions hosts into in-scope and out-of-scope slices.
func filterInScope(hosts []string, scope *Scope) (inScope, outOfScope []string) {
	for _, h := range hosts {
		if scope.Contains(h) {
			inScope = append(inScope, h)
		} else {
			outOfScope = append(outOfScope, h)
		}
	}
	return inScope, outOfScope
}

func expandScopeRange(s string) ([]string, error) {
	m := reScopeIPRange.FindStringSubmatch(s)
	if m == nil {
		return nil, fmt.Errorf("invalid IP range: %s", s)
	}
	prefix := m[1]
	start, _ := strconv.Atoi(m[2])
	end, _ := strconv.Atoi(m[3])
	if start > end {
		return nil, fmt.Errorf("range start %d exceeds end %d in %s", start, end, s)
	}
	if end > 255 {
		return nil, fmt.Errorf("range end %d exceeds 255 in %s", end, s)
	}
	ips := make([]string, 0, end-start+1)
	for i := start; i <= end; i++ {
		ips = append(ips, fmt.Sprintf("%s%d", prefix, i))
	}
	return ips, nil
}
