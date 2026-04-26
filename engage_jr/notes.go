package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// redLessonsPlaceholder is the template heading used to detect an unfilled file.
const redLessonsPlaceholder = "## <Technique or pattern, named so it works as a transclusion target>"

// generalNotesTemplate is the raw template for general_notes.md.
// Placeholders: {{engage_id}}, {{start_date}}, {{date}}, {{today}}.
var generalNotesTemplate = `# Engagement: {{engage_id}}

Start: {{start_date}}
Type:
Scope:

## Scope notes

Environmental quirks, access oddities, credential gotchas, anything not in the formal scope doc that future-you needs to remember mid-engagement.

## Daily log

### {{date}}


## Outstanding for client


## Things to retest

`

// redLessonsTemplate is the raw template for red_lessons.md.
// Placeholders: {{date}}, {{year}}.
var redLessonsTemplate = "---\ntags:\n  - work\n  - \"{{year}}\"\n---\n\n" +
	"# Redacted Lessons: {{date}}\n\n" +
	"Sanitised at write time. No hostnames, no client identifiers, no payloads tied to specific parameters or apps. Each lesson is one `##` heading; the heading becomes the transclusion anchor in topic notes once this file lands in `~/Notes/Red Notes/`.\n\n" +
	redLessonsPlaceholder + "\n\n" +
	"Date: {{date}}\n\n" +
	"Short prose describing the technique, when it applies, and the mechanism. Generic enough to be useful on a different engagement against a different stack.\n"

// provisionEngagementNotes writes the notes vault skeleton for a work engagement:
//
//   - <engDir>/notes/<name>/general_notes.md   — substituted
//   - <engDir>/notes/<name>/red_lessons.md      — substituted
//   - <engDir>/notes/<name>/_templates/general_notes_template.md  — raw
//   - <engDir>/notes/<name>/_templates/red_lessons_template.md    — raw
//
// Existing files are never overwritten so repeated calls are idempotent.
func provisionEngagementNotes(engDir, name string) error {
	now := time.Now()
	date := now.Format("02-01-2006")
	year := now.Format("2006")
	notesDir := filepath.Join(engDir, "notes", name)
	templatesDir := filepath.Join(notesDir, "_templates")

	if err := os.MkdirAll(templatesDir, 0755); err != nil {
		return fmt.Errorf("creating _templates dir: %w", err)
	}

	// Raw template files — placeholders left unsubstituted.
	rawFiles := map[string]string{
		"general_notes_template.md": generalNotesTemplate,
		"red_lessons_template.md":   redLessonsTemplate,
	}
	for filename, content := range rawFiles {
		if err := writeNoteIfNotExists(filepath.Join(templatesDir, filename), content); err != nil {
			return fmt.Errorf("writing template %s: %w", filename, err)
		}
	}

	// Pre-filled notes — all placeholders substituted.
	r := strings.NewReplacer(
		"{{engage_id}}", name,
		"{{start_date}}", date,
		"{{date}}", date,
		"{{today}}", date,
		"{{year}}", year,
	)
	filledFiles := map[string]string{
		"general_notes.md": r.Replace(generalNotesTemplate),
		"red_lessons.md":   r.Replace(redLessonsTemplate),
	}
	for filename, content := range filledFiles {
		if err := writeNoteIfNotExists(filepath.Join(notesDir, filename), content); err != nil {
			return fmt.Errorf("writing note %s: %w", filename, err)
		}
	}

	return nil
}

// writeNoteIfNotExists writes content to path only when path does not already
// exist, so re-opening an engagement never clobbers in-progress notes.
func writeNoteIfNotExists(path, content string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	return os.WriteFile(path, []byte(content), 0644)
}

// promoteRedLessons copies <engDir>/notes/<name>/red_lessons.md into
// ~/notes/red_notes/red_lessons-<date>.md.
//
// It is a no-op when:
//   - the source file is absent
//   - the file contains no ## headings beyond the template placeholder
//
// A soft warning with a confirmation prompt is shown when the engage_id string
// appears in the file (case-insensitive), so Danny can verify sanitisation.
// reader must be a bufio.Reader wrapping os.Stdin.
//
// Returns the destination path on success (empty string if skipped).
func promoteRedLessons(engDir, name string, reader *bufio.Reader) (string, error) {
	srcPath := filepath.Join(engDir, "notes", name, "red_lessons.md")
	data, err := os.ReadFile(srcPath)
	if err != nil {
		if os.IsNotExist(err) {
			logInfo("no red_lessons.md found — skipping lessons promotion")
			return "", nil
		}
		return "", fmt.Errorf("reading red_lessons.md: %w", err)
	}

	if !hasSubstantiveLessons(string(data)) {
		logInfo("red_lessons.md has no lessons beyond the template placeholder — skipping promotion")
		return "", nil
	}

	// Soft sanitisation check: warn if the engagement name appears in the content.
	if strings.Contains(strings.ToLower(string(data)), strings.ToLower(name)) {
		fmt.Printf("\nWARNING: engagement name %q found in red_lessons.md — verify sanitisation.\n", name)
		fmt.Print("Promote to synced vault anyway? [y/N]: ")
		answer, _ := reader.ReadString('\n')
		if strings.ToLower(strings.TrimSpace(answer)) != "y" {
			logInfo("lessons promotion skipped by user")
			return "", nil
		}
	}

	destDir, err := redNotesDir()
	if err != nil {
		return "", err
	}

	date := time.Now().Format("02-01-2006")
	destPath := collisionSafePath(destDir, "red_lessons-"+date+".md")

	if err := os.WriteFile(destPath, data, 0644); err != nil {
		return "", fmt.Errorf("writing promoted lessons: %w", err)
	}
	return destPath, nil
}

// hasSubstantiveLessons returns true if content contains at least one ##
// heading that is not the raw template placeholder line.
func hasSubstantiveLessons(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "## ") && line != redLessonsPlaceholder {
			return true
		}
	}
	return false
}

// redNotesDir resolves the destination directory for promoted lessons files.
// It prefers ~/Notes/Red Notes (Obsidian-friendly casing) but falls back to
// ~/notes/Red Notes when ~/notes exists and ~/Notes does not, so both common
// vault root casings work without manual configuration. The directory is
// created if it does not already exist.
func redNotesDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving home directory: %w", err)
	}

	// Prefer ~/Notes; fall back to ~/notes if it exists and ~/Notes does not.
	root := filepath.Join(home, "Notes")
	if _, err := os.Stat(root); os.IsNotExist(err) {
		lower := filepath.Join(home, "notes")
		if _, err := os.Stat(lower); err == nil {
			root = lower
		}
	}

	dir := filepath.Join(root, "Red Notes")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("creating %s: %w", dir, err)
	}
	return dir, nil
}

// collisionSafePath returns filepath.Join(dir, filename) when that path does
// not exist, otherwise appends -2, -3, … (before the extension) until a free
// name is found.
func collisionSafePath(dir, filename string) string {
	candidate := filepath.Join(dir, filename)
	if _, err := os.Stat(candidate); os.IsNotExist(err) {
		return candidate
	}
	ext := filepath.Ext(filename)
	base := strings.TrimSuffix(filename, ext)
	for i := 2; ; i++ {
		candidate = filepath.Join(dir, fmt.Sprintf("%s-%d%s", base, i, ext))
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate
		}
	}
}
