package main

import (
	"bufio"
	"os"
	"os/exec"
	"strings"
)

type awsProfile struct {
	Name            string
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Region          string
	Output          string
}

// parseAWSProfilesFile reads an INI-format AWS credentials/profiles file and
// returns the profiles it contains. Comments (lines starting with # or ;) and
// blank lines are ignored. Unrecognised keys are silently skipped. Key-value
// pairs that appear before any section header are also skipped. An empty but
// valid file returns an empty slice with no error.
func parseAWSProfilesFile(path string) ([]awsProfile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	profiles := []awsProfile{}
	var current *awsProfile

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip blank lines and comments.
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Section header.
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			if current != nil {
				profiles = append(profiles, *current)
			}
			name := line[1 : len(line)-1]
			current = &awsProfile{Name: name}
			continue
		}

		// Key-value pair — skip if we have no current profile (malformed).
		if current == nil {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(strings.ToLower(parts[0]))
		val := strings.TrimSpace(parts[1])

		switch key {
		case "aws_access_key_id":
			current.AccessKeyID = val
		case "aws_secret_access_key":
			current.SecretAccessKey = val
		case "aws_session_token":
			current.SessionToken = val
		case "region":
			current.Region = val
		case "output":
			current.Output = val
			// Unrecognised keys are silently ignored.
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Append the last profile if present.
	if current != nil {
		profiles = append(profiles, *current)
	}

	return profiles, nil
}

// configureAWSProfiles configures each profile using the aws CLI. It returns
// an error immediately if aws is not found in PATH or if any aws command fails.
// The output format for each profile is determined by: profile.Output if set,
// else defaultOutput, else "json".
func configureAWSProfiles(profiles []awsProfile, defaultOutput string) error {
	awsBin, err := exec.LookPath("aws")
	if err != nil {
		return err
	}

	run := func(args ...string) error {
		cmd := exec.Command(awsBin, args...)
		return cmd.Run()
	}

	for _, p := range profiles {
		if err := run("configure", "set", "aws_access_key_id", p.AccessKeyID, "--profile", p.Name); err != nil {
			return err
		}
		if err := run("configure", "set", "aws_secret_access_key", p.SecretAccessKey, "--profile", p.Name); err != nil {
			return err
		}
		if p.SessionToken != "" {
			if err := run("configure", "set", "aws_session_token", p.SessionToken, "--profile", p.Name); err != nil {
				return err
			}
		}
		if p.Region != "" {
			if err := run("configure", "set", "region", p.Region, "--profile", p.Name); err != nil {
				return err
			}
		}

		out := p.Output
		if out == "" {
			out = defaultOutput
		}
		if out == "" {
			out = "json"
		}
		if err := run("configure", "set", "output", out, "--profile", p.Name); err != nil {
			return err
		}
	}

	return nil
}
