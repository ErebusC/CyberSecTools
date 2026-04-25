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

# Explicit scope files (both auto-detected from engagement dir if absent)
recon_jr -scope /path/to/scope.txt -web-scope /path/to/web_scope.txt
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

## Scope

recon_jr uses a two-tier scope model to give precise control over what gets enumerated versus what gets actively web-tested.

### `scope.txt` — Enumeration & Infrastructure Scope

Controls what recon_jr is allowed to **discover and scan at the infrastructure level**:

- Subdomain enumeration (subfinder, theHarvester, crt.sh)
- DNS checks (AXFR, SPF, DMARC, CAA, MX)
- nmap port scanning
- Nessus

On first run, recon_jr prompts you to review and edit the derived scope before saving it. Out-of-scope hosts discovered during enumeration are written to `other/out_of_scope.txt` and never scanned.

Scope entries support the following formats:

```
example.com          # matches example.com and all subdomains
sub.example.com      # matches sub.example.com and deeper subdomains only
10.10.10.50          # single IP
10.10.10.0/24        # CIDR
10.10.10.1-20        # IP range
https://example.com  # URL — scheme is stripped, treated as domain
```

> **Subdomain enumeration scope:** recon_jr only runs subdomain tools (subfinder, crt.sh, etc.) against domains that are explicitly in scope. If your scope is `app.example.com`, subdomain tools will only query `app.example.com`, not the root `example.com`. Add `example.com` to scope if you want full root-domain enumeration.

### `web_scope.txt` — Web Application Test Scope

An optional second scope file that restricts which hosts receive **active web application testing**:

- httpx probing (builds the HTTP target list)
- whatweb, wafw00f, gowitness
- feroxbuster, katana, waybackurls, gau
- nuclei, nikto, CMS scanners
- testssl
- Security headers, CORS, HTTP method checks
- API surface, auth surface enumeration

If `web_scope.txt` is absent, web testing targets everything in `scope.txt`. On first run (full run only), recon_jr prompts you to optionally create one.

### Scope combinations

| `scope.txt` | `web_scope.txt` | Result |
|---|---|---|
| `erebus.cymru` | *(absent)* | Full infra scan + full web test on everything discovered |
| `erebus.cymru` | `app.erebus.cymru` | nmap scans all discovered hosts; nuclei/feroxbuster/etc. only target `app.erebus.cymru` |
| `app.erebus.cymru` | `app.erebus.cymru` | Everything locked to `app.erebus.cymru` only |

### Scope enforcement

Scope is enforced at every stage — not just on the initial host list:

- Hosts discovered by subfinder/crt.sh/theHarvester are filtered before being added to the scan queue
- Previously discovered hosts (from prior runs) are re-validated against the current scope on each run
- Endpoints from katana, waybackurls, gau, linkfinder, robots.txt, sitemaps, OpenAPI specs, and OIDC documents are filtered before being written to `discovered_endpoints`
- nmap deduplicates scan targets by resolved IP — if multiple hostnames resolve to the same address, only one scan is run

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
├── scope.txt                 # Enumeration & infra scope
├── web_scope.txt             # Web test scope (optional)
├── hosts                     # All in-scope hosts (original + discovered)
├── http_hosts                # Live HTTP/HTTPS services (web scope applied)
├── discovered_hosts          # Hosts found during enumeration
├── discovered_endpoints      # URLs found during crawling (scope filtered)
├── nmap/
│   ├── nmap_tcp-fullports_<host>.{xml,nmap,gnmap}   # pass 1: full TCP port sweep
│   ├── nmap_tcp-svc_<host>.{xml,nmap,gnmap}         # pass 2: service/version + NSE on open ports
│   └── nmap_udp-top20_<host>.{xml,nmap,gnmap}       # UDP top-20
├── nessus/
│   ├── <name>.nessus
│   ├── nessus_results.json   # Medium/High/Critical findings
│   └── nessus_low_info.json
└── other/
    ├── httpx.json
    ├── whatweb.json
    ├── screenshots/
    ├── subfinder_<domain>.txt
    ├── theharvester_<domain>.xml
    ├── theharvester_emails.txt
    ├── dnsx.txt
    ├── katana_<host>.json
    ├── feroxbuster_<host>.json
    ├── waybackurls_<domain>.txt
    ├── nuclei.json
    ├── nikto_<host>.txt
    ├── js_urls.txt
    ├── linkfinder_endpoints.txt
    ├── gitleaks.json
    ├── secrets_unverified.json
    ├── api_endpoints_<host>.txt
    ├── auth_endpoints_<host>.txt
    ├── ssrf_surface.txt
    ├── redirect_surface.txt
    ├── out_of_scope.txt
    └── headers_<host>.txt
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

## Building

```
git clone <repo>
cd recon_jr
go build -o ~/.local/bin/recon_jr .
```

Requires Go 1.21+.
