# recon_jr — Project Planning Document

## Overview

recon_jr is a sequential web application recon orchestration tool written in Go. It picks up where engage_jr leaves off: given an engagement directory, it runs a defined suite of recon tools in order, processes their output, makes decisions based on what it finds, and produces a final `recon_report.md` summarising all tool findings. The goal is to eliminate the manual, repetitive groundwork at the start of every web app test so that time is spent on the parts that actually require a human.

It does not run tools concurrently against the target. Tools run in sequence. This is intentional — it keeps traffic predictable, avoids tripping rate limiting or WAFs prematurely, makes output easier to correlate, and reduces the risk of causing service disruption on production systems. These tools will regularly run against live production infrastructure, which shapes every decision about how aggressively the tool operates.

---

## engage_jr Integration

recon_jr is designed to operate inside an existing engage_jr engagement directory. The integration points are:

**Discovery:** When invoked without an explicit path, recon_jr walks up from the current directory looking for `.engage.json`. If found, it reads engagement name, mode, host count, and creation date without requiring the user to re-specify them. An explicit `-dir` flag overrides this for cases where it is invoked from outside the engagement directory.

**Host files:** engage_jr already produces `hosts`, `http_hosts`, and `nohttp_hosts` in the engagement root. recon_jr reads these directly rather than re-parsing a host file. The `http_hosts` file feeds tools that expect URLs; `nohttp_hosts` feeds tools that expect bare hostnames or IPs; `hosts` feeds everything else.

**Directory structure:** recon_jr writes its output into the existing subdirectory layout. Tool output goes into named subdirs that map to what engage_jr created — nmap output to `nmap/`, Nessus-related output to `nessus/`. All other recon tool output (feroxbuster, nuclei, katana, subfinder, httpx, testssl, gowitness, etc.) is written into `other/` under tool-named subdirectories. This keeps the layout consistent with what engage_jr creates without requiring any changes to `work_dirs`. The `other/` directory becomes the primary recon output location.

**Metadata:** On completion, recon_jr writes `.recon.json` into the engagement root alongside `.engage.json`. This records which tools ran, when, what they found at a summary level, and whether the run completed successfully. This allows `-list` style functionality to be added later, and provides a record if recon_jr is run again on the same engagement.

**Config link:** recon_jr uses its own config file at `~/.config/recon_jr/config.json` but shares the same layered precedence pattern as engage_jr (defaults → config file → env vars → CLI flags). The Nessus host, port, and credentials live here. API keys are never written to the engagement directory.

---

## Tool Orchestration

Tools run in phases. Each phase feeds into the next. Conditional tools only run when the preceding phase surfaces evidence that justifies them.

### Phase 1 — DNS and Subdomain Enumeration

Runs against the root domains identified from the host file. Produces an expanded list of subdomains and IPs that feeds all subsequent phases.

| Tool | Purpose | Output |
|---|---|---|
| `dig` | DNS record enumeration (A, MX, TXT, NS, CNAME, SOA) | Per-host text, parsed |
| `dnsx` | Bulk resolution of discovered subdomains | Resolved host list |
| `subfinder` | Passive subdomain enumeration via public sources | Subdomain list |
| `theHarvester` | OSINT — emails, subdomains, hosts from search engines | Subdomain and email list |
| crt.sh API | Certificate transparency log query | Subdomain list |

All subdomain results are deduplicated and merged into a single `discovered_hosts` list. This list, combined with the original `hosts` file, forms the master host list for Phase 2.

**Decision logic:** If `dig` returns a successful AXFR (zone transfer), record it in `recon_report.md` as a notable finding — DNS Zone Transfer Permitted. If wildcard DNS is detected (`*.domain.com` resolving), flag it in the recon metadata; it affects how subdomain enumeration results should be interpreted and will suppress false positives in later phases.

`theHarvester` output: email addresses are written to `other/theharvester_emails.txt`. Discovered subdomains are merged into `discovered_hosts` alongside subfinder and crt.sh output.

### Phase 2 — Host Probing and Fingerprinting

Runs against the full master host list from Phase 1. Determines what is actually alive and what is running before any active scanning begins.

| Tool | Purpose | Output |
|---|---|---|
| `naabu` | Fast TCP port sweep across all hosts | Open port list per host |
| `httpx` | Probes HTTP/HTTPS on discovered ports; grabs title, status, tech stack, redirects, TLS info | JSON per host |
| `whatweb` | Deep technology fingerprinting | JSON per host |
| `wafw00f` | WAF detection | Per-host WAF name or none |
| `gowitness` | Screenshots of all live HTTP services | PNG per URL |

**Decision logic:**

- `httpx` status codes feed the crawling and discovery phase. `401`/`403` responses are noted but crawling is not attempted. `200` and `30x` chains are followed.
- `whatweb` and `httpx` combined determine which CMS-specific scanners run in Phase 4.
- If `wafw00f` detects a WAF, this is recorded in recon metadata and noted in `recon_report.md` — findings that a WAF might partially mitigate should note this.
- Software versions surfaced by `whatweb` are checked against a known-vulnerable version list. Outdated software with known CVEs is recorded in `recon_report.md` under the Outdated Software section.

### Phase 3 — Infrastructure Scanning

| Tool | Purpose | Output |
|---|---|---|
| `nmap` | Service and version detection on ports identified by naabu; NSE scripts for HTTP services | XML, parsed |
| `testssl.sh` | TLS configuration audit | JSON |
| Nessus API | Full credentialed or uncredentialed scan triggered via API; results polled and fetched | JSON |

**Decision logic — testssl:**

Record in `recon_report.md`: expired certificates, self-signed certificates, certificates with mismatched hostnames, SSLv2/SSLv3/TLS 1.0/TLS 1.1 enabled, weak cipher suites (RC4, DES, 3DES, EXPORT, NULL, anon), BEAST, POODLE, DROWN, ROBOT, HEARTBLEED, missing HSTS, HSTS max-age below 180 days, missing certificate transparency.

Do not include in report: informational notes about cipher order preference, minor TLS 1.2 configuration points that do not constitute a vulnerability.

**Decision logic — Nessus:**

All Critical and High findings are included in `recon_report.md`. Medium findings are filtered: include mediums that correspond to known impactful issues (default credentials, dangerous HTTP methods, outdated software with exploit code available). Suppress mediums that are informational re-statements of configuration (e.g. "SSL certificate cannot be trusted" when a testssl finding already covers it — dedup by CVE/plugin ID). Do not include Lows or Informationals in the report automatically; write them to `nessus/nessus_low_info.json` for manual review.

**Nessus is optional.** If `nessus_access_key` or `nessus_secret_key` are empty in config, the Nessus scan is skipped silently (logged: "Nessus skipped — no API credentials configured") and Phase 3 continues with nmap + testssl only. The `-no-nessus` CLI flag also skips it regardless of config. `.recon.json` records `"nessus_skipped": true` and `"nessus_skip_reason"` when skipped. The preflight check warns on missing Nessus credentials but does not fail.

**Decision logic — nmap:**

Record in `recon_report.md` any unexpected open port that is not in the defined scope ports (80, 443, and any ports explicitly listed in scope). Unexpected management interfaces (RDP, SSH, SNMP, Telnet, FTP, SMB) on internet-facing hosts are always noted.

### Phase 4 — Web Content Discovery and Crawling

Runs per live HTTP host identified in Phase 2.

| Tool | Purpose | Output |
|---|---|---|
| `katana` | Active crawl — follows links, discovers endpoints, parses JS for URLs | JSON endpoint list |
| `waybackurls` / `gau` | Historical URL harvesting from Wayback Machine and other sources | URL list |
| `feroxbuster` | Directory and content brute-force using wordlist | JSON |
| `arjun` | Hidden parameter discovery on crawled endpoints | JSON |

**Decision logic — feroxbuster:**

Record in `recon_report.md`: `.git` directory accessible (Directory Listing / Source Code Disclosure), `.env` files returning `200`, backup file extensions (`.bak`, `.old`, `.zip`, `.tar`, `.sql`) returning `200`, admin panel paths returning `200` or `302` to an authentication page (note location, do not flag as confirmed finding unless unauthenticated access is confirmed), configuration files (`web.config`, `phpinfo.php`, `server-status`, `server-info`) returning `200`.

Do not include in report: standard `404` paths, redirects to login pages without further context, directory listings on paths explicitly marked public.

**Decision logic — arjun:**

Output is written to `other/arjun/` for manual review. Arjun findings are not included in the automated report; they feed into manual testing. The endpoint list is appended to a master `discovered_endpoints` file that is used as a reference during the manual test.

### Phase 5 — Vulnerability Scanning

| Tool | Purpose | Output |
|---|---|---|
| `nuclei` | Template-based scanning across crawled URLs and discovered endpoints | JSON |
| `nikto` | Legacy web server scanner — noisy but occasionally finds things nuclei misses | Text, parsed |
| `wpscan` | WordPress-specific scanning (conditional on Phase 2 detection) | JSON |
| `joomscan` | Joomla-specific scanning (conditional) | Text, parsed |
| `droopescan` | Drupal/SilverStripe detection (conditional) | JSON |

**Decision logic — nuclei:**

Run with `critical`, `high`, and `medium` severity tags. Critical and High findings are included in `recon_report.md`. Medium findings are filtered — suppress findings that duplicate what Nessus or testssl already found. Do not run `info` or `low` templates automatically; these produce too much noise. The nuclei template list should be pinned to a specific version to avoid unexpected behaviour between engagements.

**Decision logic — nikto:**

nikto output is parsed for specific finding codes. Record in `recon_report.md`: exposed server version headers (if not already noted), dangerous HTTP methods (PUT, DELETE, TRACE — TRACE noted as XST risk), directory indexing enabled, server-side includes enabled, outdated software with version confirmed. Suppress: generic "the anti-clickjacking X-Frame-Options header is not present" (covered by security headers section instead), anything with a confidence qualifier of "may be interesting" without a confirmed status code.

**Decision logic — CMS scanners:**

wpscan, joomscan, droopescan only execute if the relevant CMS was identified in Phase 2. Their output is written to `other/cms/` and parsed for: known plugin/theme CVEs (record in report), outdated core version (record in report under Outdated Software), user enumeration confirmed (record in report), XML-RPC enabled (note if not needed per scope clarification).

### Phase 6 — JavaScript and Secrets Analysis

Runs against JS files discovered during crawling.

| Tool | Purpose | Output |
|---|---|---|
| `subjs` / `getJS` | Pulls all JS file URLs from crawled pages | URL list |
| `linkfinder` | Extracts endpoints and paths from JS source | Endpoint list |
| `trufflehog` / `gitleaks` | Scans JS content and any exposed `.git` repos for secrets | JSON |

**Decision logic:**

trufflehog/gitleaks findings that confirm a secret (API key, private key, password, token) are always recorded in `recon_report.md` as critical findings. Findings with `verified: false` are written to `other/secrets_unverified.json` for manual review and are not included in the automated report. Endpoints found by linkfinder are appended to the master `discovered_endpoints` file.

### Phase 7 — Security Headers and Exposure

| Tool | Purpose |
|---|---|
| `curl` with structured parsing | Captures response headers from all live HTTP hosts |

Parse for: missing `Strict-Transport-Security`, missing `Content-Security-Policy`, missing `X-Frame-Options` or `frame-ancestors` CSP directive, missing `X-Content-Type-Options`, `Referrer-Policy` absent or permissive, `Permissions-Policy` absent, `Server` header disclosing version, `X-Powered-By` present, cookies without `Secure`, `HttpOnly`, or `SameSite` attributes.

Security header findings are recorded as a single consolidated section per host in `recon_report.md` rather than one entry per missing header. Cookie attribute issues are recorded in a separate subsection. Version-disclosing headers are noted under Information Disclosure if not already covered by nikto.

---

## Report Output

recon_jr produces a single `recon_report.md` in the engagement root on completion. It contains one section per phase, with a subsection per tool. Each subsection summarises what the tool found — hosts discovered, ports open, TLS issues, headers missing, secrets detected, etc. — pulling from the tool output files already written to disk. It is generated at the end of the run; partial runs (e.g. resumed via `-from-phase`) produce a report covering completed phases only.

All raw tool output (JSON, txt, XML) is written to disk as specified in the file layout section. The markdown report is a derived summary, not a replacement for the raw files.

---

## API Integrations

### Nessus

recon_jr triggers a Nessus scan via the Nessus REST API. It does not rely on a manually pre-configured scan. The engagement domain is placed into a pre-designed scan template; recon_jr does not build scan configuration from scratch.

**Authentication:** All Nessus API requests use the `X-ApiKeys: accessKey=<key>;secretKey=<key>` header. Nessus runs with a self-signed TLS certificate by default; the HTTP client must support disabling certificate verification via `nessus_insecure_tls: true` in config. This flag must be set explicitly — it does not default to true.

**Scan naming and targeting:** The scan name is set to the engage_jr engagement directory name, which is always the project ID (e.g. `ACME-2024-001`). This ensures every Nessus scan is traceable back to a specific engagement in the Nessus console. The target field is populated with the root domain name(s) from the engagement host file. These are inserted into the pre-designed scan template identified by `nessus_template_uuid` in config — recon_jr does not define scan policy, credentials, or plugin selection. Those are the responsibility of the template.

**Full API workflow:**

1. `POST /scans` — create the scan. Body includes the template UUID, scan name (engagement folder name), and targets (domain names from host file). Response returns the new scan `id`.
2. `POST /scans/{id}/launch` — launch the scan. Response returns a `scan_uuid` for the running scan.
3. Poll `GET /scans/{id}` every 60 seconds. Check `info.status`. Continue polling while status is `running` or `pending`.
4. Terminal states: `completed` → proceed to export. `aborted`, `cancelled`, `stopped`, `paused` → log the state, write it to `.recon.json`, skip Nessus findings, and continue the recon_jr run without blocking.
5. If `nessus_max_scan_minutes` is exceeded before the scan reaches a terminal state, recon_jr logs a timeout warning, records the scan ID and current status in `.recon.json`, and continues the run without Nessus findings. On the next run, if an in-flight scan ID is present in `.recon.json`, recon_jr resumes polling from that scan rather than creating a new one.
6. `POST /scans/{id}/export` with body `{"format": "nessus"}` — initiates the file export. Response returns `{"file": <token>}`.
7. Poll `GET /scans/{id}/export/{token}/status` until response body is `{"status": "ready"}`.
8. `GET /scans/{id}/export/{token}/download` — download the binary `.nessus` file (XML format). Stream the response body directly to disk at `nessus/<engagement-name>.nessus`.
9. Parse the downloaded `.nessus` file for `ReportItem` elements. Filter findings as described in Phase 3 decision logic above. Write the filtered Critical/High/Medium JSON summary to `nessus/nessus_results.json` and all Low/Informational items to `nessus/nessus_low_info.json`. Filtered findings feed into `recon_report.md`.

The `.nessus` file is the authoritative record. `nessus_results.json` and `nessus_low_info.json` are derived from it and can be regenerated. Do not delete the `.nessus` file.

**Config keys relevant to Nessus:**

| Key | Purpose |
|---|---|
| `nessus_host` | Base URL including port, e.g. `https://nessus.example.com:8834` |
| `nessus_access_key` | API access key |
| `nessus_secret_key` | API secret key |
| `nessus_template_uuid` | UUID of the pre-designed scan template to use |
| `nessus_insecure_tls` | Set `true` to skip TLS certificate verification (required for self-signed certs) |
| `nessus_poll_secs` | Seconds between scan status polls (default `60`) |
| `nessus_max_scan_minutes` | Maximum minutes to wait for scan completion before timeout (default `240`) |

---

## Output and File Layout

After a full run, the engagement directory contains:

```
<engagement>/
├── .engage.json          # written by engage_jr
├── .recon.json           # written by recon_jr — run summary, tool status, phase completion
├── recon_report.md       # written by recon_jr — full summary of all tool findings
├── hosts                 # written by engage_jr
├── http_hosts            # written by engage_jr
├── nohttp_hosts          # written by engage_jr
├── discovered_hosts      # written by recon_jr — merged subdomains + originals
├── discovered_endpoints  # written by recon_jr — merged crawl + linkfinder + arjun output
├── nmap/
│   ├── nmap_<host>.xml
│   └── nmap_<host>.gnmap
├── nessus/
│   ├── <engagement-name>.nessus   # downloaded from Nessus server — authoritative
│   ├── nessus_results.json        # filtered Critical/High/Medium — derived from .nessus
│   └── nessus_low_info.json       # Low/Informational — derived from .nessus
└── other/
    ├── subfinder.txt
    ├── httpx.json
    ├── whatweb.json
    ├── wafw00f.json
    ├── screenshots/
    │   └── gowitness.db (+ PNG exports)
    ├── testssl/
    │   └── testssl_<host>.json
    ├── nuclei/
    │   └── nuclei_<host>.json
    ├── feroxbuster/
    │   └── ferox_<host>.json
    ├── katana/
    │   └── katana_<host>.json
    ├── cms/
    │   └── (wpscan/joomscan/droopescan output)
    ├── theharvester_emails.txt
    ├── secrets_unverified.json
    └── arjun/
```

---

## Configuration

`~/.config/recon_jr/config.json`:

```json
{
  "nessus_host":               "https://nessus.example.com:8834",
  "nessus_access_key":         "",
  "nessus_secret_key":         "",
  "nessus_template_uuid":      "",
  "nessus_insecure_tls":       false,
  "nessus_poll_secs":          60,
  "nessus_max_scan_minutes":   240,
  "wordlist":                  "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
  "nuclei_templates":          "~/.local/nuclei-templates",
  "tools_timeout_secs":        300,
  "tool_delay_secs":           5,
  "skip_tools":                []
}
```

`nessus_insecure_tls` must be set explicitly to `true` when connecting to a Nessus instance with a self-signed certificate. It is `false` by default and the tool will not silently bypass TLS verification.

Env var equivalents follow the same `RECON_` prefix pattern as engage_jr uses `ENGAGE_`. CLI flags override everything.

The `skip_tools` array allows named tools to be skipped without recompiling — useful when a tool is not installed, a scan type is out of scope, or a specific phase needs to be skipped on a re-run.

---

## CLI Interface

```
recon_jr [options]

Options:
  -dir <path>              Engagement directory (default: auto-discover from cwd)
  -phase <n>               Run only a specific phase (1-7)
  -from-phase <n>          Resume from a given phase (uses existing output)
  -skip <tool>             Skip a named tool for this run (repeatable)
  -no-nessus               Skip Nessus scan regardless of config credentials
  -dry-run                 Show what would run without executing anything
  -check-deps              Verify all required tools are installed and exit
  -verbose                 Debug output
  -config <path>           Config file override
  -v                       Version
```

`-from-phase` is important — if recon_jr fails mid-run or a tool produces bad output, the user should be able to resume from a specific phase rather than re-running everything from scratch. Output files from completed phases are left in place and reused.

---

## File Structure

Mirroring engage_jr's design:

| File | Owns |
|---|---|
| `main.go` | Flag parsing, phase orchestration, engage_jr meta discovery |
| `config.go` | Config struct, 3-layer loading |
| `runner.go` | Tool execution engine — runs a command, captures stdout/stderr, writes to output path, handles timeout |
| `meta.go` | Reads `.engage.json`, writes `.recon.json` |
| `hosts.go` | Reads host files, builds master host list, deduplication |
| `phases.go` | Phase definitions — maps phase number to tool list and execution logic |
| `nessus.go` | Nessus API client — create scan, launch, poll, fetch, parse |
| `parsers.go` | Per-tool output parsers — extracts structured findings from tool JSON/txt output |
| `report.go` | Generates `recon_report.md` from parsed tool output, applying include/suppress rules |
| `logger.go` | Identical pattern to engage_jr |

---

## Production Safety

recon_jr will routinely run against production systems. A misconfiguration or an overly aggressive tool invocation has real consequences — a knocked-over web server mid-engagement is a client relationship problem as much as a technical one. The following controls are non-negotiable and must be implemented before the tool is used on any live engagement.

### Target Scope Enforcement

Before any tool executes, recon_jr validates every host in the master host list against a scope file. The scope file is either specified explicitly via `-scope` or discovered automatically as `scope.txt` in the engagement root. If no scope file exists and `-scope` is not provided, recon_jr refuses to run and exits with an error — it does not fall back to trusting the host file alone.

The scope file uses the same format as the engage_jr host file (CIDRs, ranges, bare hostnames, URLs). Any host discovered during Phase 1 subdomain enumeration that does not fall within scope is removed from the master host list before Phase 2 begins and logged to `recon/out_of_scope.txt` for reference. recon_jr never makes an active connection to an out-of-scope host.

### Tool Safety Classification

Every tool in the orchestration pipeline is classified as either **passive**, **active-safe**, or **active-intrusive**. The classification governs when and how it runs.

**Passive** tools make no direct connection to the target. They query third-party sources (certificate transparency logs, search engines, DNS). These always run without restriction.

**Active-safe** tools make direct connections to the target but are not expected to cause service disruption under normal conditions: `httpx`, `dig`, `dnsx`, `wafw00f`, `whatweb`, `gowitness`, `testssl`, `katana` (with rate limiting applied), `feroxbuster` (with rate limiting applied), `nmap` (service detection, no aggressive scripts).

**Active-intrusive** tools carry a meaningful risk of service disruption, resource exhaustion, or triggering security controls in a way that could cause collateral impact: `nikto`, `nuclei` (fuzzing templates), `naabu`/`masscan` at high rates, `wpscan` with aggressive enumeration flags, `arjun`. These tools require explicit opt-in via a `-allow-intrusive` flag. Without this flag, recon_jr skips them entirely, logs that they were skipped, and notes in `recon_report.md` that intrusive scanning was not performed.

The Nessus scan policy used must also be reviewed before use on production. A credentialed scan against a production database server is outside the intended use of this tool. The default Nessus policy ID in config should be a web-optimised, non-destructive policy. The config documentation must make this explicit.

### Rate Limiting

All active tools that accept rate limiting or concurrency flags are invoked with conservative defaults. These defaults are configurable but the config keys are named to make their purpose clear (`max_requests_per_second`, `max_concurrent_connections`). There is no "go fast" shortcut flag — if a user wants to increase rates they edit the config explicitly and accept the responsibility.

Default limits:
- `feroxbuster`: `--rate-limit 50` (requests per second)
- `katana`: `-rate-limit 20`
- `naabu`: `-rate 300` (packets per second — conservative; masscan defaults are orders of magnitude higher)
- `nuclei`: `-rate-limit 50`
- `nikto`: `-Pause 1` (1 second between requests)

### Inter-Tool Delays

A configurable inter-tool delay (`tool_delay_secs`, default `5`) is inserted between each tool execution. This prevents back-to-back tools from creating a burst that looks like an attack and gives any WAF or rate limiting on the target side time to reset between tools. The delay can be set to `0` explicitly but doing so logs a warning.

### No Exploitation

recon_jr is a recon tool. No tool in the pipeline executes payloads, attempts exploitation, or uses nuclei templates classified as `exploit` or `dos`. The nuclei invocation explicitly excludes these tags regardless of what is installed in the local template directory:

```
nuclei -exclude-tags exploit,dos,fuzz
```

The `fuzz` tag exclusion is also applied by default. Fuzzing templates can generate high request volumes and unexpected behaviour server-side. They are only included if `-allow-intrusive` is set and the user has explicitly added `-nuclei-fuzz` on top of that.

### Pre-Run Confirmation

When run against a `ModeWork` engagement (i.e. a real client), recon_jr displays a summary of what it is about to do — host count, tool list, intrusive flag status, Nessus status — and requires explicit confirmation before proceeding. If `nessus_insecure_tls: true` is set, a visible warning is displayed at this point: "WARNING: TLS verification disabled for Nessus — ensure you are on a trusted network". This is not a `--yes` bypass; it is a deliberate pause to review scope before anything touches the target. The confirmation prompt shows the first five hosts in scope and the total count so there is no ambiguity about what is being targeted.

This confirmation step is skipped only in `-dry-run` mode.

### Dependency Preflight Check

Before Phase 1 begins — and before the pre-run confirmation prompt — recon_jr verifies that every binary it intends to invoke is present on `$PATH`. Tools listed in `skip_tools` (config or `-skip` flag) are excluded from the check. If any required binary is missing, recon_jr prints a complete list of missing tools and exits with a non-zero status. It does not attempt to run partial phases or silently skip missing tools unless they are explicitly in `skip_tools`.

The preflight check is also available as a standalone command via `-check-deps`. This allows users to verify their environment is correctly configured without initiating a scan.

Config validation (required keys present and non-empty, Nessus URL reachable if credentials provided, scope file exists) runs as part of the same preflight sequence, in order: config validation → dependency check → scope file verification → pre-run confirmation.

### Graceful Interrupt Handling

On receipt of `SIGINT` or `SIGTERM`, recon_jr:

1. Sends a termination signal to the currently running child process.
2. Waits up to 10 seconds for the child process to exit. If it does not, sends `SIGKILL`.
3. Flushes `.recon.json` to disk with the current run state: which phases completed cleanly, which tool was running at interrupt time, and all findings raised up to that point.
4. Logs the interruption clearly, including the interrupted tool name and phase number.
5. Exits with a non-zero status code.

This ensures that `-from-phase` has accurate state to resume from. A run interrupted mid-Phase 3 will leave `.recon.json` recording Phase 1 and Phase 2 as complete and Phase 3 as interrupted — the user can resume from Phase 3 without re-running earlier phases.

If recon_jr is interrupted while a Nessus scan is in progress (i.e. the scan has been launched but has not yet reached a terminal state), the scan ID and current status are written to `.recon.json`. On a subsequent run, recon_jr checks for an existing in-flight scan ID in `.recon.json` and resumes polling from that scan rather than creating a new one.

---

## What recon_jr Does Not Do

These are out of scope by design, not oversight:

- It does not run tools concurrently against the target.
- It does not perform any authenticated scanning (authenticated Burp scans, credentialed Nessus aside, remain manual).
- It does not make decisions about CVSS scores or risk ratings — finding severity in `recon_report.md` reflects the tool's own severity classification.
- It does not replace the manual test. The `recon_report.md` it produces is a starting point. Findings noted automatically should be verified before the report goes out.
- It does not modify or overwrite engage_jr's output files.

---

## MVP Scope

The full tool list is the end state. The MVP is the subset that delivers the most time saving with the least implementation risk:

1. engage_jr meta discovery and host file reading
2. Phase 1: subfinder + crt.sh + dnsx
3. Phase 2: httpx + whatweb + wafw00f + gowitness
4. Phase 3: nmap + testssl
5. Phase 5: nuclei (critical/high only)
6. Phase 7: curl header parsing
7. `recon_report.md` generation from completed phase outputs
8. `.recon.json` output

Nessus API integration, feroxbuster, katana, arjun, the secrets analysis phase, and CMS scanners come in the next iteration once the core orchestration and report generation pipeline are solid.
