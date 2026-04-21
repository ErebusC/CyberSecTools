package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	os.WriteFile(path, []byte("192.168.1.1\n# comment\n\nhostname.com\n"), 0644)

	lines, err := readLines(path)
	if err != nil {
		t.Fatalf("readLines: %v", err)
	}
	if len(lines) != 2 {
		t.Errorf("expected 2 lines, got %d: %v", len(lines), lines)
	}
	if lines[0] != "192.168.1.1" {
		t.Errorf("line 0: got %q", lines[0])
	}
	if lines[1] != "hostname.com" {
		t.Errorf("line 1: got %q", lines[1])
	}
}

func TestReadLinesMissingFile(t *testing.T) {
	lines, err := readLines("/nonexistent/path/hosts")
	if err != nil {
		t.Fatalf("readLines on missing file should not error: %v", err)
	}
	if lines != nil {
		t.Errorf("expected nil for missing file, got %v", lines)
	}
}

func TestMasterHostList(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "hosts"), []byte("192.168.1.1\nexample.com\n"), 0644)
	os.WriteFile(filepath.Join(dir, "http_hosts"), []byte("https://example.com\n"), 0644)
	os.WriteFile(filepath.Join(dir, "nohttp_hosts"), []byte("192.168.1.1\n"), 0644)

	all, http, noHTTP, err := masterHostList(dir)
	if err != nil {
		t.Fatalf("masterHostList: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("all: expected 2, got %d", len(all))
	}
	if len(http) != 1 {
		t.Errorf("http: expected 1, got %d", len(http))
	}
	if len(noHTTP) != 1 {
		t.Errorf("noHTTP: expected 1, got %d", len(noHTTP))
	}
}

func TestWriteDiscoveredHosts(t *testing.T) {
	dir := t.TempDir()

	// First write
	err := writeDiscoveredHosts(dir, []string{"sub1.example.com", "sub2.example.com"})
	if err != nil {
		t.Fatalf("writeDiscoveredHosts: %v", err)
	}

	// Second write with overlap — should deduplicate
	err = writeDiscoveredHosts(dir, []string{"sub2.example.com", "sub3.example.com"})
	if err != nil {
		t.Fatalf("writeDiscoveredHosts (second): %v", err)
	}

	lines, err := readLines(filepath.Join(dir, "discovered_hosts"))
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 3 {
		t.Errorf("expected 3 unique hosts, got %d: %v", len(lines), lines)
	}
}

func TestMergeDiscovered(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "discovered_hosts"), []byte("sub1.example.com\nsub2.example.com\n"), 0644)

	existing := []string{"example.com", "sub1.example.com"}
	merged, err := mergeDiscovered(dir, existing)
	if err != nil {
		t.Fatalf("mergeDiscovered: %v", err)
	}
	// Should have: example.com, sub1.example.com, sub2.example.com
	if len(merged) != 3 {
		t.Errorf("expected 3 merged hosts, got %d: %v", len(merged), merged)
	}
}

func TestExtractRootDomains(t *testing.T) {
	tests := []struct {
		hosts []string
		want  []string
	}{
		{
			[]string{"example.com", "sub.example.com", "other.com", "192.168.1.1"},
			[]string{"example.com", "other.com"},
		},
		{
			[]string{"https://sub.example.com", "http://other.example.com"},
			[]string{"example.com"},
		},
		{
			[]string{"192.168.1.1", "10.10.10.1"},
			[]string{},
		},
	}
	for _, tt := range tests {
		got := extractRootDomains(tt.hosts)
		if len(got) != len(tt.want) {
			t.Errorf("extractRootDomains(%v) = %v, want %v", tt.hosts, got, tt.want)
			continue
		}
		seen := make(map[string]bool)
		for _, d := range got {
			seen[d] = true
		}
		for _, w := range tt.want {
			if !seen[w] {
				t.Errorf("extractRootDomains: missing %q in result %v", w, got)
			}
		}
	}
}

func TestDeduplicateHosts(t *testing.T) {
	hosts := []string{"a.com", "b.com", "a.com", "c.com", "b.com"}
	got := deduplicateHosts(hosts)
	if len(got) != 3 {
		t.Errorf("expected 3 unique hosts, got %d: %v", len(got), got)
	}
}

func TestSanitizeForFilename(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https://example.com", "example.com"},
		{"http://example.com/path", "example.com_path"},
		{"192.168.1.1:8080", "192.168.1.1_8080"},
	}
	for _, tt := range tests {
		if got := sanitizeForFilename(tt.input); got != tt.want {
			t.Errorf("sanitizeForFilename(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestWriteLinesToFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "output.txt")
	lines := []string{"line1", "line2", "line3"}

	if err := writeLinesToFile(path, lines); err != nil {
		t.Fatalf("writeLinesToFile: %v", err)
	}

	got, err := readLines(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(lines) {
		t.Errorf("expected %d lines, got %d", len(lines), len(got))
	}
}
