package main

import "testing"

func TestValidateName(t *testing.T) {
	valid := []string{
		"ClientName", "client-name", "client_name", "client.name",
		"Client123", "A", "abc", "123",
	}
	for _, name := range valid {
		if err := validateName(name); err != nil {
			t.Errorf("validateName(%q) returned error for valid name: %v", name, err)
		}
	}

	invalid := []string{
		"client/name", "../evil", "client name", "client@name",
		"", "-startwithdash", ".startwithDot",
	}
	for _, name := range invalid {
		if err := validateName(name); err == nil {
			t.Errorf("validateName(%q) returned nil for invalid name", name)
		}
	}
}

func TestResolveModeDefault(t *testing.T) {
	if got := resolveMode("", false, false, false, false); got != ModeWork {
		t.Errorf("resolveMode(all false) = %q, want ModeWork", got)
	}
}

func TestResolveModeWebApp(t *testing.T) {
	if got := resolveMode("web-app", false, false, false, false); got != ModeWork {
		t.Errorf(`resolveMode("web-app") = %q, want ModeWork`, got)
	}
}

func TestResolveModeExplicit(t *testing.T) {
	cases := []struct {
		workType                      string
		thm, htb, exam, swigger      bool
		want                          engagementMode
		desc                          string
	}{
		{"", false, false, false, false, ModeWork, "no flags = work"},
		{"web-app", false, false, false, false, ModeWork, "explicit web-app"},
		{"infra", false, false, false, false, ModeInfra, "-w infra"},
		{"cloud", false, false, false, false, ModeCloud, "-w cloud"},
		{"", true, false, false, false, ModeTHM, "-t"},
		{"", false, true, false, false, ModeHTB, "-b"},
		{"", false, false, true, false, ModeExam, "-e"},
		{"", false, false, false, true, ModeSwigger, "-p"},
		// -w infra takes priority over other mode flags
		{"infra", true, false, false, false, ModeInfra, "-w infra beats -t"},
		{"cloud", false, false, false, true, ModeCloud, "-w cloud beats -p"},
	}
	for _, c := range cases {
		got := resolveMode(c.workType, c.thm, c.htb, c.exam, c.swigger)
		if got != c.want {
			t.Errorf("%s: resolveMode got %q, want %q", c.desc, got, c.want)
		}
	}
}

func TestCountTrue(t *testing.T) {
	if countTrue(false, false, false) != 0 {
		t.Error("expected 0")
	}
	if countTrue(true, false, true) != 2 {
		t.Error("expected 2")
	}
	if countTrue(true, true, true, true) != 4 {
		t.Error("expected 4")
	}
}
