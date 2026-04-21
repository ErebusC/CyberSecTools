package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScopeContainsIP(t *testing.T) {
	dir := t.TempDir()
	scopeFile := filepath.Join(dir, "scope.txt")
	os.WriteFile(scopeFile, []byte("192.168.1.0/24\n10.10.10.1-10\n10.10.10.50\n"), 0644)

	scope, err := loadScope(scopeFile)
	if err != nil {
		t.Fatalf("loadScope: %v", err)
	}

	tests := []struct {
		host string
		want bool
	}{
		{"192.168.1.1", true},
		{"192.168.1.254", true},
		{"192.168.2.1", false},
		{"10.10.10.1", true},
		{"10.10.10.10", true},
		{"10.10.10.11", false},
		{"10.10.10.50", true},
		{"10.10.10.51", false},
	}
	for _, tt := range tests {
		if got := scope.Contains(tt.host); got != tt.want {
			t.Errorf("scope.Contains(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestScopeContainsDomain(t *testing.T) {
	dir := t.TempDir()
	scopeFile := filepath.Join(dir, "scope.txt")
	os.WriteFile(scopeFile, []byte("example.com\ntest.org\n"), 0644)

	scope, err := loadScope(scopeFile)
	if err != nil {
		t.Fatalf("loadScope: %v", err)
	}

	tests := []struct {
		host string
		want bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"deep.sub.example.com", true},
		{"notexample.com", false},
		{"test.org", true},
		{"www.test.org", true},
		{"other.com", false},
		{"https://sub.example.com", true},
		{"https://sub.example.com/path", true},
	}
	for _, tt := range tests {
		if got := scope.Contains(tt.host); got != tt.want {
			t.Errorf("scope.Contains(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestScopeWithURLFormat(t *testing.T) {
	dir := t.TempDir()
	scopeFile := filepath.Join(dir, "scope.txt")
	os.WriteFile(scopeFile, []byte("https://example.com\nhttp://internal.net\n"), 0644)

	scope, err := loadScope(scopeFile)
	if err != nil {
		t.Fatalf("loadScope: %v", err)
	}

	if !scope.Contains("example.com") {
		t.Error("should match bare domain from scoped URL")
	}
	if !scope.Contains("sub.example.com") {
		t.Error("should match subdomain from scoped URL domain")
	}
}

func TestFilterInScope(t *testing.T) {
	dir := t.TempDir()
	scopeFile := filepath.Join(dir, "scope.txt")
	os.WriteFile(scopeFile, []byte("example.com\n10.0.0.0/8\n"), 0644)

	scope, err := loadScope(scopeFile)
	if err != nil {
		t.Fatalf("loadScope: %v", err)
	}

	hosts := []string{
		"sub.example.com",
		"other.org",
		"10.10.10.1",
		"192.168.1.1",
	}
	inScope, outOfScope := filterInScope(hosts, scope)

	if len(inScope) != 2 {
		t.Errorf("inScope: expected 2, got %d: %v", len(inScope), inScope)
	}
	if len(outOfScope) != 2 {
		t.Errorf("outOfScope: expected 2, got %d: %v", len(outOfScope), outOfScope)
	}
}

func TestLoadScopeEmpty(t *testing.T) {
	dir := t.TempDir()
	scopeFile := filepath.Join(dir, "scope.txt")
	os.WriteFile(scopeFile, []byte("# just a comment\n\n"), 0644)

	if _, err := loadScope(scopeFile); err == nil {
		t.Error("expected error for empty scope file")
	}
}

func TestFindScopeFile(t *testing.T) {
	dir := t.TempDir()

	// No scope.txt — returns empty string (not an error; implicit scope used instead)
	if path := findScopeFile(dir, ""); path != "" {
		t.Errorf("expected empty string when scope.txt absent, got %q", path)
	}

	// Create scope.txt
	scopeFile := filepath.Join(dir, "scope.txt")
	os.WriteFile(scopeFile, []byte("example.com\n"), 0644)

	path := findScopeFile(dir, "")
	if path != scopeFile {
		t.Errorf("got %q, want %q", path, scopeFile)
	}

	// Explicit -scope flag overrides
	explicit := filepath.Join(dir, "custom_scope.txt")
	os.WriteFile(explicit, []byte("other.com\n"), 0644)
	path = findScopeFile(dir, explicit)
	if path != explicit {
		t.Errorf("got %q, want %q", path, explicit)
	}
}

func TestExpandScopeRange(t *testing.T) {
	tests := []struct {
		input   string
		wantLen int
		wantErr bool
	}{
		{"192.168.1.1-5", 5, false},
		{"10.0.0.1-1", 1, false},
		{"10.0.0.5-3", 0, true},  // start > end
		{"10.0.0.1-256", 0, true}, // end > 255
	}
	for _, tt := range tests {
		ips, err := expandScopeRange(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("expandScopeRange(%q): expected error", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("expandScopeRange(%q): unexpected error: %v", tt.input, err)
			continue
		}
		if len(ips) != tt.wantLen {
			t.Errorf("expandScopeRange(%q): got %d IPs, want %d", tt.input, len(ips), tt.wantLen)
		}
	}
}
