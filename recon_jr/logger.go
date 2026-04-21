package main

import (
	"bufio"
	"fmt"
	"os"
)

// verbose and dryRun are set by CLI flags in main and read by any function
// that needs to gate output or side effects.
var (
	verbose bool
	dryRun  bool

	// stdinScanner is a shared buffered reader for all interactive prompts.
	// Using a single instance prevents one prompt's bufio buffer from consuming
	// input that belongs to the next prompt.
	stdinScanner = bufio.NewScanner(os.Stdin)
)

// readLine reads one line from shared stdin, returning "" on EOF or error.
func readLine() string {
	if stdinScanner.Scan() {
		return stdinScanner.Text()
	}
	return ""
}

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
