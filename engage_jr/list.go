package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"text/tabwriter"
	"time"
)

// engagementEntry holds display data for a single engagement directory.
type engagementEntry struct {
	name      string
	createdAt time.Time
	hostCount int
}

// allModes is the ordered set of engagement modes shown by -list.
var allModes = []engagementMode{
	ModeWork, ModeInfra, ModeCloud, ModeTHM, ModeHTB, ModeExam, ModeSwigger,
}

// listEngagements prints engagement directories grouped by mode. Pass a non-nil
// filterSubDir to restrict output to a single subdirectory (e.g. "THM", "cloud");
// nil shows all modes. Within each group entries are sorted newest-first.
func listEngagements(cfg *Config, filterSubDir *string) {
	if filterSubDir != nil {
		dir := filepath.Join(cfg.BaseDir, *filterSubDir)
		if !listOneDir(*filterSubDir, dir) {
			logInfo("no engagements found under %s", dir)
		}
		return
	}

	found := false
	for _, mode := range allModes {
		tmpl, err := loadTemplate(string(mode))
		if err != nil {
			logDebug("skipping mode %s: %v", mode, err)
			continue
		}
		dir := filepath.Join(cfg.BaseDir, tmpl.SubDir)
		if listOneDir(string(mode), dir) {
			found = true
		}
	}

	if !found {
		logInfo("no engagements found under %s", cfg.BaseDir)
	}
}

// listOneDir prints engagements found in dir under the given label.
// Returns true if any engagements were found.
func listOneDir(label, dir string) bool {
	rawEntries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return false
	}
	if err != nil {
		logWarn("could not read %s: %v", dir, err)
		return false
	}

	var engagements []engagementEntry
	for _, e := range rawEntries {
		if !e.IsDir() {
			continue
		}
		t, count := dirInfo(dir, e)
		engagements = append(engagements, engagementEntry{e.Name(), t, count})
	}
	if len(engagements) == 0 {
		return false
	}

	// Sort newest-first; zero times (no metadata, failed mtime) go to the end.
	sort.Slice(engagements, func(i, j int) bool {
		ti, tj := engagements[i].createdAt, engagements[j].createdAt
		if ti.IsZero() {
			return false
		}
		if tj.IsZero() {
			return true
		}
		return ti.After(tj)
	})

	fmt.Printf("%s (%d):\n", label, len(engagements))
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, eng := range engagements {
		date := eng.createdAt.Format("2006-01-02")
		if eng.createdAt.IsZero() {
			date = "unknown"
		}
		hostStr := ""
		if eng.hostCount > 0 {
			hostStr = fmt.Sprintf("%d hosts", eng.hostCount)
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\n", eng.name, date, hostStr)
	}
	w.Flush()
	return true
}

// dirInfo returns the creation time and host count for an engagement directory.
// Prefers values from .engage.json; falls back to dir mtime with zero count.
func dirInfo(parent string, e os.DirEntry) (time.Time, int) {
	metaPath := filepath.Join(parent, e.Name(), metaFileName)
	if meta, err := readMeta(metaPath); err == nil {
		return meta.CreatedAt, meta.HostCount
	}
	info, err := e.Info()
	if err != nil {
		return time.Time{}, 0
	}
	return info.ModTime(), 0
}
