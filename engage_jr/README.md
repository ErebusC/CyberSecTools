# engage_jr

Sets up directories, host files, and a Burp project so I can start a pentest without faffing around with folder structures every time.

Point it at a host file and it will create the engagement directory, split hosts into separate files by type, expand any CIDR/ranges, deduplicate everything, kick off a headless Burp project in the background, and drop you into a shell at the engagement directory.

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
| `-w` | `~/Share/work/<name>` | Work engagement (default) |
| `-t` | `~/Share/THM/<name>` | TryHackMe |
| `-b` | `~/Share/HTB/<name>` | HackTheBox |
| `-e` | `~/Share/exam/<name>` | Exam |
| `-p` | `~/Share/swigger/<name>` | PortSwigger |

Work mode creates tool subdirectories (`nmap/`, `burp/`, `nessus/`, `other/` by default) and processes the host file. Other modes just create the engagement directory.

### Examples

```bash
engage_jr ClientName hosts.txt          # work engagement with host file
engage_jr -t Relevant                   # TryHackMe lab
engage_jr -list                         # show all engagements
engage_jr -list -t                      # show only THM engagements
engage_jr -open -t Relevant             # resume an existing engagement
engage_jr -dry-run ClientName hosts.txt # preview, don't create anything
```

### Host file

One entry per line. Comments with `#`. Supports:

```
app.target.com                  # hostname
10.10.10.50                     # IP
10.10.10.1-20                   # range (expanded)
192.168.1.0/24                  # CIDR (expanded, no nmap needed)
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
-burp-jar <path>   Override Burp jar location
-base-dir <path>   Override base directory
-config   <path>   Override config file path
-dry-run           Show what would happen without touching the filesystem
-verbose           Debug output
-v                 Version
```

## Config

Config is loaded in layers — CLI flags beat env vars, env vars beat the config file, config file beats defaults.

File: `~/.config/engage_jr/config.json`

```json
{
  "burp_jar":          "/path/to/burpsuite_pro.jar",
  "base_dir":          "/home/user/Share",
  "burp_timeout_secs": 90,
  "work_dirs":         ["nmap", "burp", "nessus", "gobuster", "screenshots"]
}
```

| Setting | Env var | Default |
|---------|---------|---------|
| Burp jar path | `ENGAGE_BURP_JAR` | `~/BurpSuitePro/burpsuite_pro.jar` |
| Base directory | `ENGAGE_BASE_DIR` | `~/Share` |
| Burp timeout | `ENGAGE_BURP_TIMEOUT` | `60s` |
| Work subdirs | -- | `nmap, burp, nessus, other` |
