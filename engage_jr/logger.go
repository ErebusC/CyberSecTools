package main

import (
	"fmt"
	"os"
)

// verbose and dryRun are set by CLI flags in main and read by any function
// that needs to gate output or side effects.
var (
	verbose bool
	dryRun  bool
)

func logInfo(format string, args ...any) {
	fmt.Printf(format+"\n", args...)
}

func logWarn(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "warning: "+format+"\n", args...)
}

func logDebug(format string, args ...any) {
	if verbose {
		fmt.Fprintf(os.Stderr, "debug: "+format+"\n", args...)
	}
}

// fatal logs an error to stderr and exits with code 1.
func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}
