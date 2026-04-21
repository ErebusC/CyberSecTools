# recon_jr

Sequential web application reconnaissance tool that runs 7 phases of enumeration, scanning, and analysis against an [engage_jr](https://github.com) engagement directory. Produces a `recon_report.md` summarising all findings.

---

## Prerequisites

### Required
All tools must be in `PATH`. Install from [BlackArch](https://blackarch.org):

```
paru -S subfinder dnsx theharvester httpx-bin katana-bin waybackurls gau \
        feroxbuster nuclei nikto testssl gowitness whatweb wafw00f gitleaks \
        trufflehog subjs linkfinder wpscan nmap
```

> BlackArch note: `httpx` installs as `httpx-pd`, `katana` as `katana`. Verify with `which httpx-pd katana`.

### Optional
- **Nessus** — API credentials in config enable Nessus scanning in Phase 3
- **wpscan token** — `wpscan --api-token <tok>` or set in `~/.wpscan/scan.yml` for vuln database access
- **Arjun, joomscan, droopescan** — only run with `-allow-intrusive`

### engage_jr
recon_jr must be run inside (or pointed at) an engage_jr engagement directory containing `.engage.json`. It auto-discovers the directory by walking up from `cwd`.

---

## Usage

```
# Run all 7 phases from the engagement directory
cd ~/Documents/Engagements/work/client-name
recon_jr

# Or point at it explicitly
recon_jr -dir ~/Documents/Engagements/work/client-name

# Resume from a specific phase (skips phases already completed)
recon_jr -from-phase 4

# Re-run a single phase
recon_jr -phase 5

# Enable intrusive tools (nikto, arjun, wpscan, naabu)
recon_jr -allow-intrusive

# Route all tool traffic through Burp
recon_jr -burp

# Or a custom proxy
recon_jr -proxy http://127.0.0.1:8080

# Skip tools for this run
recon_jr -skip nuclei,wpscan

# Dry run — show commands without executing
recon_jr -dry-run

# Check all dependencies are installed
recon_jr -check-deps
```

---

## Phases

| # | Phase | Tools |
|---|---|---|
| 1 | DNS & Subdomain Enumeration | dig (AXFR + SPF/DMARC/CAA), subfinder (all sources), theHarvester, crt.sh, dnsx |
| 2 | Host Probing & Fingerprinting | httpx, whatweb, wafw00f, gowitness |
| 3 | Infrastructure Scanning | nmap TCP (full ports + NSE), nmap UDP (top 20), testssl, Nessus (optional) |
| 4 | Web Content Discovery | katana (depth 5), feroxbuster, waybackurls, gau, arjun* |
| 5 | Vulnerability Scanning | nuclei, nikto*, wpscan*, joomscan*, droopescan* |
| 6 | JavaScript & Secrets | subjs (from crawled endpoints), linkfinder, gitleaks/trufflehog |
| 7 | Security Headers | curl |

`*` = requires `-allow-intrusive`

---

## Configuration

Default config file: `~/.config/recon_jr/config.json`

```json
{
  "nessus_host":             "https://nessus.example.com:8834",
  "nessus_access_key":       "",
  "nessus_secret_key":       "",
  "nessus_template_uuid":    "",
  "nessus_insecure_tls":     false,
  "nessus_poll_secs":        60,
  "nessus_max_scan_minutes": 240,
  "wordlist":                "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
  "nuclei_templates":        "~/.local/nuclei-templates",
  "tools_timeout_secs":      300,
  "fuzz_timeout_secs":       1800,
  "tool_delay_secs":         5,
  "skip_tools":              [],
  "proxy_url":               ""
}
```

| Key | Default | Notes |
|---|---|---|
| `nessus_*` | — | Nessus is skipped silently if credentials are absent |
| `wordlist` | raft-medium-words.txt | Path to wordlist for feroxbuster |
| `nuclei_templates` | `~/.local/nuclei-templates` | Custom templates dir; falls back to nuclei defaults |
| `tools_timeout_secs` | 300 | Per-tool timeout for most tools |
| `fuzz_timeout_secs` | 1800 | Timeout for slow tools: feroxbuster, nuclei, testssl, nikto, nmap |
| `tool_delay_secs` | 5 | Delay between tool invocations (WAF evasion) |
| `skip_tools` | `[]` | Tool names to always skip |
| `proxy_url` | — | HTTP proxy; overridden by `-proxy`/`-burp` flags |
| `wpscan_api_token` | — | WPScan API token for vulnerability database lookups; also `RECON_WPSCAN_API_TOKEN` env var |

**Config precedence (highest to lowest):** CLI flags > env vars > config file > defaults

**Environment variables** (`RECON_` prefix): `RECON_NESSUS_HOST`, `RECON_NESSUS_ACCESS_KEY`, `RECON_NESSUS_SECRET_KEY`, `RECON_NESSUS_TEMPLATE_UUID`, `RECON_NESSUS_INSECURE_TLS`, `RECON_NESSUS_POLL_SECS`, `RECON_NESSUS_MAX_SCAN_MINUTES`, `RECON_WORDLIST`, `RECON_NUCLEI_TEMPLATES`, `RECON_TOOLS_TIMEOUT_SECS`, `RECON_TOOL_DELAY_SECS`, `RECON_PROXY`

---

## Output Layout

All output is written into the engagement directory:

```
<engagement>/
├── .recon.json               # Phase state, findings, resume info
├── recon_report.md           # Final summary report
├── hosts                     # All in-scope hosts (original + discovered)
├── http_hosts                # Live HTTP/HTTPS services
├── discovered_hosts          # Hosts found during enumeration
├── discovered_endpoints      # URLs found during crawling
├── nmap/
│   └── nmap_<host>.xml
├── nessus/
│   ├── <name>.nessus
│   ├── nessus_results.json   # Medium/High/Critical findings
│   └── nessus_low_info.json
└── other/
    ├── httpx.json
    ├── whatweb.json
    ├── wafw00f/
    ├── screenshots/
    ├── testssl/
    ├── subfinder_<domain>.txt
    ├── theharvester_<domain>.xml
    ├── theharvester_emails.txt
    ├── dnsx.txt
    ├── katana/
    ├── feroxbuster/
    ├── waybackurls_<domain>.txt
    ├── arjun/
    ├── nuclei/
    ├── nikto/
    ├── cms/
    ├── js_urls.txt
    ├── linkfinder_endpoints.txt
    ├── gitleaks.json
    ├── secrets_unverified.json
    └── headers/
```

---

## Resuming Interrupted Runs

recon_jr writes `.recon.json` after each phase. If a run is interrupted:

```
# Resume from where it left off
recon_jr -from-phase 3

# Or re-run a single phase only
recon_jr -phase 4
```

Phase status is tracked as `running`, `completed`, `interrupted`, or `skipped`. Completed phases are not re-run by `-from-phase`.

---

## Scope

On first run, recon_jr prompts to review/edit the scope (populated from `engage_jr`). Scope is stored in `scope.txt` and used to filter all discovered subdomains to in-scope hosts only. Out-of-scope hosts are written to `other/out_of_scope.txt`.

---

## Building

```
git clone <repo>
cd recon_jr
go build -o ~/.local/bin/recon_jr .
```

Requires Go 1.21+.
