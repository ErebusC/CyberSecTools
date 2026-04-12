# engage_jr

Sets up directories, host files, and a Burp project so you can start a pentest without faffing around with folder structures every time.

Point it at a host file and it will create the engagement directory, split hosts into separate files by type, expand any CIDR/ranges, deduplicate everything, kick off a headless Burp project in the background, and drop you into a tmux session at the engagement directory — with panes already laid out and Obsidian open to the right vault.

## Build

```bash
make build
make install   # copies to /usr/local/bin
```

Requires Go 1.22+. Burp Suite Pro and `java` on PATH for project file creation (skipped gracefully if missing).

## Usage

```
engage_jr [mode] [options] <name> [hostfile]
```

### Modes

| Flag | Directory | Purpose |
|------|-----------|---------|
| `-w` | `<base_dir>/work/<name>` | Work engagement (default) |
| `-t` | `<base_dir>/THM/<name>` | TryHackMe |
| `-b` | `<base_dir>/HTB/<name>` | HackTheBox |
| `-e` | `<base_dir>/exam/<name>` | Exam |
| `-p` | `<base_dir>/swigger/<name>` | PortSwigger |

Work mode creates tool subdirectories (`nmap/`, `burp/`, `nessus/`, `other/` by default) and processes the host file. Other modes just create the engagement directory.

### Examples

```bash
engage_jr ClientName hosts.txt              # work engagement with host file
engage_jr -t Relevant                       # TryHackMe lab
engage_jr -b legacy-box -ssh vps           # HTB + open SSH to VPS in a pane
engage_jr -list                             # show all engagements
engage_jr -list -t                          # show only THM engagements
engage_jr -open -t Relevant                 # resume an existing engagement
engage_jr -finish ClientName                # GPG-encrypt and archive engagement
engage_jr -dry-run ClientName hosts.txt     # preview, don't create anything
ENGAGE_TMUX=0 engage_jr ClientName hosts.txt  # disable tmux for this run
```

### Host file

One entry per line. Comments with `#`. Supports:

```
app.target.com                  # hostname
10.10.10.50                     # IP
10.10.10.1-20                   # range (expanded)
192.168.1.0/24                  # CIDR (no nmap needed)
https://admin.target.com/login  # URL
```

Produces three output files in the engagement directory:

- `hosts` — every unique host, one per line
- `http_hosts` — original URLs preserved
- `nohttp_hosts` — URLs stripped to bare hostnames

Duplicates across ranges, CIDRs, and repeated entries are removed.

### All flags

```
-list              List engagements (combine with a mode flag to filter)
-open <name>       Resume an existing engagement
-finish <name>     GPG-encrypt and archive the engagement, kill tmux session
-ssh <alias>       SSH config alias — opens an SSH pane to your VPS
-burp-jar <path>   Override Burp jar location
-base-dir <path>   Override base directory
-config   <path>   Override config file path
-dry-run           Show what would happen without touching the filesystem
-verbose           Debug output
-v                 Version
```

---

## Config

Config is loaded in layers — CLI flags beat env vars, env vars beat the config file, config file beats defaults.

File: `~/.config/engage_jr/config.json`

### Full example

```json
{
  "burp_jar":              "~/BurpSuitePro/burpsuite_pro.jar",
  "base_dir":              "/Share",
  "burp_timeout_secs":     90,
  "work_dirs":             ["nmap", "burp", "nessus", "gobuster", "screenshots"],

  "tmux_enabled":          true,
  "tmux_prefix":           "",

  "obsidian_bin":          "obsidian",
  "obsidian_synced_vault": "~/Notes",

  "ssh_hosts": {
    "work":    "my-vps",
    "HTB":     "htb-vps",
    "THM":     "thm-vps"
  },

  "tmux_layouts": {
    "work": [
      {
        "name": "main", "focus_pane": 0,
        "panes": [
          {},
          {"split_direction": "v", "percent": 40},
          {"split_direction": "h", "split_from": 1,
           "command": "[ -n \"$ENGAGE_SSH_HOST\" ] && ssh $ENGAGE_SSH_HOST"}
        ]
      },
      {
        "name": "notes",
        "panes": [{"command": "cd \"$ENGAGE_NOTES_DIR\" && xdg-open \"obsidian://open?path=$ENGAGE_NOTES_DIR\" 2>/dev/null"}]
      }
    ]
  }
}
```

### Settings reference

| Setting | JSON key | Env var | Default |
|---------|----------|---------|---------|
| Burp jar path | `burp_jar` | `ENGAGE_BURP_JAR` | `~/BurpSuitePro/burpsuite_pro.jar` |
| Base directory | `base_dir` | `ENGAGE_BASE_DIR` | `/Share` |
| Burp timeout (s) | `burp_timeout_secs` | `ENGAGE_BURP_TIMEOUT` | `60` |
| Work subdirs | `work_dirs` | — | `nmap, burp, nessus, other` |
| tmux enabled | `tmux_enabled` | `ENGAGE_TMUX` (`1`/`true` or `0`/`false`) | **`true`** |
| tmux session prefix | `tmux_prefix` | `ENGAGE_TMUX_SESSION_PREFIX` | _(none — bare engagement name)_ |
| Obsidian binary | `obsidian_bin` | `ENGAGE_OBSIDIAN_BIN` | `obsidian` |
| Obsidian synced vault | `obsidian_synced_vault` | `ENGAGE_OBSIDIAN_VAULT` | `~/Notes` |
| VPS SSH host per mode | `ssh_hosts` | — | _(none)_ |
| Custom tmux layouts | `tmux_layouts` | — | _(built-in per-mode defaults)_ |

---

## tmux integration

tmux is **enabled by default**. Set `ENGAGE_TMUX=0` or `"tmux_enabled": false` in the config file to disable it. Falls back to a plain shell automatically if tmux is not installed.

### Session naming

Sessions are named `<name>` by default, or `<tmux_prefix>_<name>` if `tmux_prefix` is set. e.g. with prefix `pt` and name `acmecorp`, the session is `pt_acmecorp`.

### Pane layouts

Each mode has a built-in window/pane layout. Override any mode by adding a `tmux_layouts` entry to the config file (see full example above).

| Mode | Windows | Pane layout |
|------|---------|-------------|
| work | `main` + `notes` | main: top shell / bottom-left recon / bottom-right VPS SSH |
| HTB / THM | `attack` + `notes` | top shell / bottom enum |
| exam | `shell` + `notes` | top shell / bottom secondary |
| swigger | `main` | top shell / bottom Obsidian |

### Environment variables set in every session

| Variable | Value |
|----------|-------|
| `ENGAGE_NAME` | engagement name |
| `ENGAGE_MODE` | mode string (`work`, `HTB`, etc.) |
| `ENGAGE_DIR` | absolute engagement directory |
| `ENGAGE_HOST_FILE` | `<engDir>/hosts` |
| `ENGAGE_NMAP_DIR` | `<engDir>/nmap` |
| `ENGAGE_BURP_DIR` | `<engDir>/burp` |
| `ENGAGE_NOTES_DIR` | `<engDir>/notes` (work) or `obsidian_synced_vault` (others) |
| `ENGAGE_OBSIDIAN_BIN` | Obsidian binary |
| `ENGAGE_SSH_HOST` | VPS alias (from `-ssh` flag or `ssh_hosts[mode]`; unset if neither) |
| `TARGET_1`…`TARGET_N` | individual hosts from `hosts` file |
| `TARGETS` | space-separated all hosts |
| `HTTP_TARGETS` | space-separated HTTP/HTTPS hosts |

### SSH pane

The third pane in work mode runs `ssh $ENGAGE_SSH_HOST` automatically if the variable is set. Provide it via:

- CLI flag: `engage_jr ClientName hosts.txt -ssh my-vps`
- Config file: `"ssh_hosts": {"work": "my-vps"}`

The alias must exist in `~/.ssh/config` — engage_jr passes it directly to `ssh`.

---

## Obsidian integration

When a new engagement is created, engage_jr registers the vault in `~/.config/obsidian/obsidian.json` before the notes pane opens. This means Obsidian opens to the correct vault immediately without a manual vault-selection step.

- **Work mode:** a self-contained vault is created at `<engDir>/notes/.obsidian/` and GPG-archived with the engagement on `-finish`.
- **Other modes:** the configured `obsidian_synced_vault` (default `~/Notes`) is used. Set the path in config or via `ENGAGE_OBSIDIAN_VAULT`.

Requires Obsidian to be installed with its `obsidian://` URI handler registered (standard on all install methods).

---

## Finishing an engagement

```bash
engage_jr -finish ClientName
```

Kills the tmux session, prompts for GPG recipient and signing keys, then produces a `<name>_DR.tar.gpg` encrypted archive in the parent directory. Requires `gpg` on PATH with at least one key pair.
