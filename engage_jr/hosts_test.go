package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStripHTTP(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"http://example.com/path", "example.com"},
		{"https://example.com/path/to/page", "example.com"},
		{"https://example.com", "example.com"},
		{"http://10.10.10.1/admin", "10.10.10.1"},
		{"http://example.com:8080/login", "example.com:8080"},
	}
	for _, c := range cases {
		got := stripHTTP(c.input)
		if got != c.want {
			t.Errorf("stripHTTP(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

func TestExpandRange(t *testing.T) {
	ips, err := expandRange("10.10.10.1-5")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"10.10.10.1", "10.10.10.2", "10.10.10.3", "10.10.10.4", "10.10.10.5"}
	if len(ips) != len(want) {
		t.Fatalf("got %d IPs, want %d: %v", len(ips), len(want), ips)
	}
	for i, ip := range ips {
		if ip != want[i] {
			t.Errorf("ips[%d] = %q, want %q", i, ip, want[i])
		}
	}
}

func TestExpandRangeSingleHost(t *testing.T) {
	ips, err := expandRange("192.168.1.10-10")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 1 || ips[0] != "192.168.1.10" {
		t.Errorf("got %v, want [192.168.1.10]", ips)
	}
}

func TestExpandRangeReversed(t *testing.T) {
	_, err := expandRange("10.10.10.10-1")
	if err == nil {
		t.Error("expected error for reversed range, got nil")
	}
}

func TestExpandRangeOctetOverflow(t *testing.T) {
	_, err := expandRange("10.10.10.250-260")
	if err == nil {
		t.Error("expected error for range end > 255, got nil")
	}
}

func TestExpandCIDRSlash30(t *testing.T) {
	ips, err := expandCIDR("192.168.1.0/30")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 4 {
		t.Fatalf("got %d IPs for /30, want 4: %v", len(ips), ips)
	}
	if ips[0] != "192.168.1.0" {
		t.Errorf("first IP = %q, want 192.168.1.0", ips[0])
	}
	if ips[3] != "192.168.1.3" {
		t.Errorf("last IP = %q, want 192.168.1.3", ips[3])
	}
}

func TestExpandCIDRSlash32(t *testing.T) {
	ips, err := expandCIDR("10.10.10.5/32")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 1 || ips[0] != "10.10.10.5" {
		t.Errorf("got %v, want [10.10.10.5]", ips)
	}
}

func TestExpandCIDRHostBits(t *testing.T) {
	ips, err := expandCIDR("192.168.1.3/30")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ips[0] != "192.168.1.0" {
		t.Errorf("first IP = %q, want 192.168.1.0 (network base)", ips[0])
	}
}

func TestExpandCIDRInvalid(t *testing.T) {
	_, err := expandCIDR("not-a-cidr")
	if err == nil {
		t.Error("expected error for invalid CIDR, got nil")
	}
}

func TestProcessHostFile(t *testing.T) {
	input := strings.Join([]string{
		"http://example.com/path",
		"https://target.com",
		"10.10.10.1-3",
		"192.168.1.0/30",
		"plainhost.local",
		"10.10.10.50",
		"# comment — skip this",
		"",
	}, "\n")

	src := filepath.Join(t.TempDir(), "hosts.txt")
	if err := os.WriteFile(src, []byte(input), 0644); err != nil {
		t.Fatal(err)
	}

	dest := t.TempDir()
	stats, err := processHostFile(src, dest)
	if err != nil {
		t.Fatalf("processHostFile failed: %v", err)
	}

	// Unique: 2 (http stripped) + 3 (range) + 4 (cidr) + 1 (hostname) + 1 (ip) = 11
	if stats.Unique != 11 {
		t.Errorf("stats.Unique = %d, want 11", stats.Unique)
	}
	if stats.HTTP != 2 {
		t.Errorf("stats.HTTP = %d, want 2", stats.HTTP)
	}

	readLines := func(name string) []string {
		data, err := os.ReadFile(filepath.Join(dest, name))
		if err != nil {
			t.Fatalf("could not read %s: %v", name, err)
		}
		return strings.Split(strings.TrimSpace(string(data)), "\n")
	}

	hosts := readLines("hosts")
	if len(hosts) != 11 {
		t.Errorf("hosts: got %d entries, want 11: %v", len(hosts), hosts)
	}

	httpHosts := readLines("http_hosts")
	if len(httpHosts) != 2 {
		t.Errorf("http_hosts: got %d entries, want 2: %v", len(httpHosts), httpHosts)
	}

	noHTTP := readLines("nohttp_hosts")
	if len(noHTTP) != 2 {
		t.Errorf("nohttp_hosts: got %d entries, want 2: %v", len(noHTTP), noHTTP)
	}
	for _, h := range noHTTP {
		if strings.HasPrefix(h, "http") {
			t.Errorf("nohttp_hosts contains protocol prefix: %q", h)
		}
	}
}

func TestProcessHostFileDeduplication(t *testing.T) {
	input := strings.Join([]string{
		"10.10.10.1",
		"10.10.10.1",          // exact duplicate
		"10.10.10.1-3",        // range overlaps with above
		"http://example.com",  // first occurrence
		"https://example.com", // same stripped host — deduplicated
	}, "\n")

	src := filepath.Join(t.TempDir(), "hosts.txt")
	if err := os.WriteFile(src, []byte(input), 0644); err != nil {
		t.Fatal(err)
	}

	dest := t.TempDir()
	stats, err := processHostFile(src, dest)
	if err != nil {
		t.Fatalf("processHostFile failed: %v", err)
	}

	// Unique: 10.10.10.1, 10.10.10.2, 10.10.10.3, example.com = 4
	if stats.Unique != 4 {
		t.Errorf("stats.Unique = %d after dedup, want 4", stats.Unique)
	}
	if stats.HTTP != 1 {
		t.Errorf("stats.HTTP = %d after dedup, want 1", stats.HTTP)
	}

	data, err := os.ReadFile(filepath.Join(dest, "hosts"))
	if err != nil {
		t.Fatal(err)
	}
	hosts := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(hosts) != 4 {
		t.Errorf("hosts: got %d entries after dedup, want 4: %v", len(hosts), hosts)
	}

	httpData, err := os.ReadFile(filepath.Join(dest, "http_hosts"))
	if err != nil {
		t.Fatal(err)
	}
	httpHosts := strings.Split(strings.TrimSpace(string(httpData)), "\n")
	if len(httpHosts) != 1 {
		t.Errorf("http_hosts: got %d entries after dedup, want 1: %v", len(httpHosts), httpHosts)
	}
}

func TestProcessHostFileMissingFile(t *testing.T) {
	_, err := processHostFile("/nonexistent/hosts.txt", t.TempDir())
	if err == nil {
		t.Error("expected error for missing host file, got nil")
	}
}
