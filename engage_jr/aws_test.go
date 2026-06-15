package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseAWSProfilesFileEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials")
	if err := os.WriteFile(path, []byte{}, 0600); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	profiles, err := parseAWSProfilesFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(profiles) != 0 {
		t.Fatalf("expected 0 profiles, got %d", len(profiles))
	}
}

func TestParseAWSProfilesFileMultiProfile(t *testing.T) {
	content := `[client-a]
aws_access_key_id = AKIA1111
aws_secret_access_key = secret1
region = eu-west-1

[client-b]
aws_access_key_id = AKIA2222
aws_secret_access_key = secret2
aws_session_token = token2
output = table
`
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	profiles, err := parseAWSProfilesFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(profiles) != 2 {
		t.Fatalf("expected 2 profiles, got %d", len(profiles))
	}

	a := profiles[0]
	if a.Name != "client-a" {
		t.Errorf("client-a: expected Name %q, got %q", "client-a", a.Name)
	}
	if a.AccessKeyID != "AKIA1111" {
		t.Errorf("client-a: expected AccessKeyID %q, got %q", "AKIA1111", a.AccessKeyID)
	}
	if a.SecretAccessKey != "secret1" {
		t.Errorf("client-a: expected SecretAccessKey %q, got %q", "secret1", a.SecretAccessKey)
	}
	if a.Region != "eu-west-1" {
		t.Errorf("client-a: expected Region %q, got %q", "eu-west-1", a.Region)
	}
	if a.SessionToken != "" {
		t.Errorf("client-a: expected empty SessionToken, got %q", a.SessionToken)
	}

	b := profiles[1]
	if b.Name != "client-b" {
		t.Errorf("client-b: expected Name %q, got %q", "client-b", b.Name)
	}
	if b.AccessKeyID != "AKIA2222" {
		t.Errorf("client-b: expected AccessKeyID %q, got %q", "AKIA2222", b.AccessKeyID)
	}
	if b.SecretAccessKey != "secret2" {
		t.Errorf("client-b: expected SecretAccessKey %q, got %q", "secret2", b.SecretAccessKey)
	}
	if b.SessionToken != "token2" {
		t.Errorf("client-b: expected SessionToken %q, got %q", "token2", b.SessionToken)
	}
	if b.Output != "table" {
		t.Errorf("client-b: expected Output %q, got %q", "table", b.Output)
	}
}

func TestParseAWSProfilesFileComments(t *testing.T) {
	content := `# this is a comment
; this is also a comment

# another comment

`
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	profiles, err := parseAWSProfilesFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(profiles) != 0 {
		t.Fatalf("expected 0 profiles, got %d", len(profiles))
	}
}

func TestParseAWSProfilesFileSingleProfile(t *testing.T) {
	content := `[production]
aws_access_key_id = AKIAPROD1234
aws_secret_access_key = prodsecret/abc+xyz==
aws_session_token = prodtoken987
region = us-east-1
output = json
`
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	profiles, err := parseAWSProfilesFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(profiles) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(profiles))
	}

	p := profiles[0]
	if p.Name != "production" {
		t.Errorf("expected Name %q, got %q", "production", p.Name)
	}
	if p.AccessKeyID != "AKIAPROD1234" {
		t.Errorf("expected AccessKeyID %q, got %q", "AKIAPROD1234", p.AccessKeyID)
	}
	if p.SecretAccessKey != "prodsecret/abc+xyz==" {
		t.Errorf("expected SecretAccessKey %q, got %q", "prodsecret/abc+xyz==", p.SecretAccessKey)
	}
	if p.SessionToken != "prodtoken987" {
		t.Errorf("expected SessionToken %q, got %q", "prodtoken987", p.SessionToken)
	}
	if p.Region != "us-east-1" {
		t.Errorf("expected Region %q, got %q", "us-east-1", p.Region)
	}
	if p.Output != "json" {
		t.Errorf("expected Output %q, got %q", "json", p.Output)
	}
}
