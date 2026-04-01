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

// listEngagements prints engagement directories grouped by mode. Pass a non-nil
// filterMode to restrict output to a single mode; nil shows all modes.
// Within each group entries are sorted newest-first by creation date.
func listEngagements(cfg *Config, filterMode *engagementMode) {
	modes := []engagementMode{ModeWork, ModeTHM, ModeHTB, ModeExam, ModeSwigger}
	if filterMode != nil {
		modes = []engagementMode{*filterMode}
	}

	found := false
	for _, mode := range modes {
		sub := modeSubDir[mode]
		dir := filepath.Join(cfg.BaseDir, sub)

		rawEntries, err := os.ReadDir(dir)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			logWarn("could not read %s: %v", dir, err)
			continue
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
			continue
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

		found = true
		fmt.Printf("%s (%d):\n", mode, len(engagements))

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
	}

	if !found {
		if filterMode != nil {
			logInfo("no %s engagements found under %s", *filterMode, cfg.BaseDir)
		} else {
			logInfo("no engagements found under %s", cfg.BaseDir)
		}
	}
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
