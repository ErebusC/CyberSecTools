# recon_jr — Project Planning Document

## Overview

recon_jr is a sequential recon orchestration tool written in Go. It operates in two distinct modes:

- **Web mode** (default): web application penetration test recon — subdomain enumeration, HTTP probing, infrastructure scanning, content discovery, vulnerability scanning, secrets analysis, and security headers. Seven phases, producing `recon_report.md` and `recon_overview.md`.
- **Infra mode** (`-mode infra`): broad internal/external infrastructure enumeration — ASN and IP range discovery, host sweep, full-port service scanning, service-specific protocol enumeration (SMB, LDAP, SNMP, RPC, Kerberos), and vulnerability assessment across whatever is alive. Built for network and infrastructure assessments where the scope is an IP range, ASN, or org name rather than a specific web application.

Both modes integrate with engage_jr engagement directories and share the same config, scope enforcement, production safety controls, and reporting pipeline. The mode is set at runtime; the engagement directory structure is the same in both cases.

Tools run sequentially within each phase. This is intentional — it keeps traffic predictable, avoids tripping rate limiting or IDS/IPS prematurely, makes output easier to correlate, and reduces the risk of causing service disruption on production systems.

---

## Recon Boundary

recon_jr is a reconnaissance tool. Its job is to identify and document the attack surface so that the operator can make informed decisions about what to test manually. It does not cross the line into exploitation under any circumstances, in either mode, with any combination of flags.

Concretely, this means:

- **No exploit execution.** Tools are invoked with flags that perform detection and enumeration only. nuclei excludes `exploit`, `dos`, and `fuzz` tags regardless of what templates are installed locally. nmap NSE scripts are limited to those that probe and identify — not those that manipulate or exploit.
- **No credential brute forcing.** kerbrute is run in `userenum` mode only — it determines whether a username is valid, it does not try passwords. SNMP community string checks are limited to the two most common defaults (`public`, `private`). nuclei `default-logins` templates check a single known default credential pair per service (e.g., `admin:admin` on Tomcat manager) — they are not iterating a password list.
- **No data extraction.** Tools that read from services (SNMP walk, anonymous LDAP bind, SMB share listing) record what is *accessible* and *what that implies about security posture*. They do not copy files, read database contents, or retrieve data beyond what is needed to confirm the finding.
- **No write operations.** Nothing is written to, modified on, or sent to target systems beyond the network probes required to enumerate them. Cloud storage probes use HEAD requests only. No files are uploaded. No registrations are made.
- **Findings are surface maps, not attack chains.** The output of this tool tells the operator: "this exists, this is accessible, this looks misconfigured." What happens next is a human decision made deliberately, with authorisation confirmed, outside this tool.

---

---

## engage_jr Integration

recon_jr is designed to operate inside an existing engage_jr engagement directory. The integration points are:

**Discovery:** When invoked without an explicit path, recon_jr walks up from the current directory looking for `.engage.json`. If found, it reads engagement name, mode, host count, and creation date without requiring the user to re-specify them. An explicit `-dir` flag overrides this for cases where it is invoked from outside the engagement directory.

**Host files:** engage_jr already produces `hosts`, `http_hosts`, and `nohttp_hosts` in the engagement root. recon_jr reads these directly. In infra mode the `hosts` file may contain CIDR ranges, IP ranges, and ASNs in addition to hostnames; the host expansion logic handles this before scanning begins.

**Directory structure:** recon_jr writes its output into the existing subdirectory layout. Tool output goes into named subdirs — nmap output to `nmap/`, Nessus-related output to `nessus/`. All other tool output is written into `other/`. In infra mode, additional subdirectories are created: `smb/`, `ldap/`, `snmp/`, `services/`. This keeps the layout consistent with what engage_jr creates.

**Metadata:** On completion, recon_jr writes `.recon.json` into the engagement root alongside `.engage.json`. This records the mode that was run, which phases completed, what was found at a summary level, and whether the run completed. Interrupted runs are resumable via `-from-phase`.

**Config link:** recon_jr uses its own config file at `~/.config/recon_jr/config.json`. The Nessus host, port, and credentials live here. API keys are never written to the engagement directory.

---

## Web Mode — Tool Orchestration

Tools run in phases. Each phase feeds into the next. Conditional tools only run when the preceding phase surfaces evidence that justifies them.

### Phase 1 — DNS and Subdomain Enumeration

Runs against the root domains identified from the host file. Produces an expanded list of subdomains and IPs that feeds all subsequent phases.

| Tool | Purpose | Output |
|---|---|---|
| `dig` | DNS record enumeration (A, MX, TXT, NS, CNAME, SOA, AXFR attempt) + SPF/DMARC/CAA | Per-domain findings |
| `subfinder` | Passive subdomain enumeration via public sources | Subdomain list |
| `theHarvester` | OSINT — emails, subdomains from search engines | Subdomain + email list |
| crt.sh API | Certificate transparency log query | Subdomain list |
| `dnsx` | Bulk resolution of discovered subdomains | Resolved host list |

All subdomain results are deduplicated and merged into a single `discovered_hosts` list. This list, combined with the original `hosts` file, forms the master host list for Phase 2.

**Decision logic:** If `dig` returns a successful AXFR, record it in `recon_report.md` as a notable finding — DNS Zone Transfer Permitted. If wildcard DNS is detected, flag it in recon metadata.

### Phase 2 — Host Probing and Fingerprinting

| Tool | Purpose | Output |
|---|---|---|
| `httpx` | Probes HTTP/HTTPS; grabs title, status, tech stack, redirects, TLS info | JSON per host |
| `whatweb` | Deep technology fingerprinting | JSON per host |
| `wafw00f` | WAF detection | Per-host WAF name or none |
| `gowitness` | Screenshots of all live HTTP services | PNG per URL |
| `ffuf` | Virtual host discovery per root domain | JSON per domain |

**Decision logic:** `whatweb` and `httpx` combined determine which CMS-specific scanners run in Phase 5. If `wafw00f` detects a WAF, this is recorded in recon metadata. Virtual hosts discovered by ffuf are added to the master host list.

### Phase 3 — Infrastructure Scanning

| Tool | Purpose | Output |
|---|---|---|
| `nmap` | Two-pass TCP: fast full-port sweep → service/version + NSE on open ports | XML + nmap + gnmap |
| `nmap` (UDP) | Top-20 UDP ports | XML + nmap + gnmap |
| `testssl.sh` | TLS configuration audit | JSON per HTTPS host |
| Nessus API | Full scan triggered via API; results polled and fetched | JSON |

**nmap output naming:** `nmap_tcp-fullports_<host>.*`, `nmap_tcp-svc_<host>.*`, `nmap_udp-top20_<host>.*`

**Decision logic — nmap:** Record in `recon_report.md` any unexpected open port not in the defined scope ports. Unexpected management interfaces (RDP, SSH, SNMP, Telnet, FTP, SMB) on internet-facing hosts are always noted.

**Decision logic — testssl:** Record expired/self-signed certs, TLS 1.0/1.1, SSLv2/3, weak ciphers, BEAST/POODLE/DROWN/HEARTBLEED/ROBOT. Suppress informational notes.

**Decision logic — Nessus:** All Critical and High findings in the report. Mediums filtered — include if they correspond to default credentials, dangerous HTTP methods, or exploitable outdated software. Lows/Infos written to `nessus_low_info.json` for manual review. Nessus is optional; skipped silently if credentials absent.

### Phase 4 — Web Content Discovery and Crawling

| Tool | Purpose | Output |
|---|---|---|
| `katana` | Active crawl — follows links, parses JS for URLs | URL list per host |
| `waybackurls` / `gau` | Historical URL harvesting | URL list per domain |
| `feroxbuster` | Directory and content brute-force | JSON per host |
| `arjun`* | Hidden parameter discovery on crawled endpoints | JSON per host |

`*` = requires `-allow-intrusive`

**Decision logic — feroxbuster:** Record `.git` directory, `.env` files, backup extensions (`.bak`, `.old`, `.zip`, `.tar`, `.sql`), `phpinfo.php`, `server-status`, `server-info`, `web.config`.

### Phase 5 — Known Vulnerability Identification

| Tool | Purpose | Output |
|---|---|---|
| `nuclei` | Template-based detection across crawled URLs — identifies known misconfigurations and CVEs | JSON |
| `nikto`* | Web server misconfiguration and version detection | Text per host |
| `wpscan`* | WordPress plugin/theme/core version identification (conditional on Phase 2 detection) | JSON |
| `joomscan`* | Joomla version and component identification (conditional) | Text |
| `droopescan`* | Drupal/SilverStripe version identification (conditional) | JSON |

`*` = requires `-allow-intrusive`

nuclei is invoked with `--exclude-tags exploit,dos,fuzz` in all cases. Templates identify whether a vulnerability condition is present — they do not deliver payloads or trigger code execution on the target.

### Phase 6 — JavaScript and Secrets Analysis

| Tool | Purpose | Output |
|---|---|---|
| `subjs` | Extracts JS file URLs from crawled pages | URL list |
| `linkfinder` | Extracts endpoints from JS source | Endpoint list |
| `gitleaks` | Secrets scanning on filesystem and JS content | JSON |
| `trufflehog` | Secrets scanner — filesystem + GitHub org scan | JSON |
| `gh search` | GitHub code search for target domain + sensitive keywords | JSON |

Source map detection (`.map` files alongside `.js` URLs) runs as part of this phase.

**Decision logic:** Verified secrets → `recon_report.md` as Critical. Unverified → `secrets_unverified.json` for manual review. linkfinder endpoints appended to `discovered_endpoints`.

### Phase 7 — Security Headers and HTTP Exposure

| Tool | Purpose |
|---|---|
| `curl` | Captures response headers from all live HTTP hosts |
| HTTP OPTIONS | Detects dangerous methods (PUT, DELETE, TRACE, CONNECT, TRACK) |
| CORS probe | Tests arbitrary origin reflection + credentials header |

Parse for: missing HSTS/CSP/X-Frame-Options/X-Content-Type-Options/Referrer-Policy/Permissions-Policy, HSTS max-age below 180 days, Server/X-Powered-By headers, cookies without Secure/HttpOnly/SameSite.

**CORS testing:** Tests `Origin: https://evil.example.com` reflection with credentials. Extended tests (null origin, subdomain origin, protocol-swap) are a planned enhancement.

---

## Web Mode — Planned Enhancements

These are features identified as high-value gaps that will be added in subsequent iterations, in rough priority order.

### API Surface Enumeration (Phase 4 extension)

No automated discovery of API surfaces exists beyond generic crawling. Add:

- Probe common API root paths (`/api`, `/api/v1`, `/api/v2`, `/rest`, `/graphql`, `/v1`, `/v2`) on each live host using httpx with status code filtering.
- Fetch and parse OpenAPI/Swagger documentation if present (`/swagger`, `/swagger.json`, `/api-docs`, `/openapi.json`, `/swagger-ui.html`). Extract endpoint list and parameter names and append to `discovered_endpoints`.
- GraphQL detection: send a `POST /graphql` with a minimal introspection query. If the endpoint returns a `data` key, record it as a discovered GraphQL endpoint and attempt schema introspection. Log schema to `other/graphql_<host>.json`. Record as a finding if introspection is enabled in production — it shouldn't be.
- Record API endpoints in their own `other/api_endpoints_<host>.txt` so they can feed arjun parameter discovery and manual testing.

### Authentication and OAuth Surface (Phase 4 extension)

- Probe common auth endpoint paths per host (`/login`, `/signin`, `/auth`, `/sso`, `/oauth`, `/oauth/token`, `/oauth/authorize`, `/saml/sso`). Record any that return 200 or redirect to auth forms.
- Fetch `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server`. Parse and record: authorization endpoint, token endpoint, userinfo endpoint, JWKS URI. These feed OAuth misconfiguration testing.
- Record discovered auth endpoints in `other/auth_endpoints_<host>.txt`.

### Cloud Storage Enumeration (Phase 1 extension)

After subdomain enumeration, derive candidate cloud storage names from the engagement domain and org name and probe them:

- **S3:** check `<org>.s3.amazonaws.com`, `<org>-assets.s3.amazonaws.com`, `<org>-backup.s3.amazonaws.com`, `<org>-static.s3.amazonaws.com` and common variations. A 200 or 403 response indicates the bucket exists; a 200 with XML listing indicates public read. Record bucket names and access status in `other/cloud_storage.json`.
- **Azure Blob:** probe `<org>.blob.core.windows.net`, `<org>-assets.blob.core.windows.net`.
- **Google Cloud Storage:** probe `storage.googleapis.com/<org>`, `<org>.storage.googleapis.com`.
- This runs passively (HTTP HEAD requests only) and does not attempt any write operations.

### Robots.txt and Sitemap Parsing (Phase 4 addition)

For each live HTTP host, fetch `/robots.txt`, `/sitemap.xml`, `/sitemap_index.xml`, `/.well-known/security.txt`, and `/.well-known/change-password`. Parse:

- `robots.txt`: extract all `Disallow` and `Allow` paths — these are often the most interesting endpoints and are deliberately not crawled by default. Append to `discovered_endpoints`.
- `sitemap.xml`: extract all `<loc>` URLs. Append to `discovered_endpoints`.
- `security.txt`: record contact and policy URLs if present.
- All parsed content written to `other/wellknown_<host>.txt`.

### Subdomain Takeover Surface (Phase 1 extension)

After subdomain enumeration and resolution, probe each discovered subdomain for takeover indicators:

- For CNAME records pointing to external services (GitHub Pages, Heroku, Netlify, Fastly, AWS S3, Azure, etc.), check whether the pointed-to resource returns a 404 or "not found" page characteristic of an unclaimed service.
- Maintain a static fingerprint list of known takeover indicators per service (e.g., GitHub Pages: "There isn't a GitHub Pages site here", Heroku: "No such app").
- Record confirmed or likely takeover candidates in `recon_report.md` as High findings.
- Record as Medium if CNAME points to an external service but the page content is not a known takeover indicator (manual review needed).

**Scope boundary:** This feature performs detection only — DNS resolution and a GET request to check the response body. It does not register domains, claim S3 buckets, create GitHub Pages sites, or take any action that would constitute performing the takeover. Actually claiming a resource requires explicit written authorisation beyond standard pentest scope and is handled manually if permitted.

### SSRF and Open Redirect Surface Mapping (Phase 4 extension)

After parameter discovery (arjun output), scan the `discovered_endpoints` list for parameters whose names suggest SSRF or redirect attack surface:

- SSRF candidates: parameters named `url`, `uri`, `path`, `dest`, `destination`, `target`, `proxy`, `host`, `endpoint`, `redirect_to`, `callback`, `webhook`, `fetch`, `load`, `source`, `src`, `img`, `image`.
- Open redirect candidates: parameters named `redirect`, `return`, `next`, `continue`, `goto`, `back`, `redir`, `returnUrl`, `returnTo`, `successUrl`, `failUrl`.
- Write candidate endpoints and parameter names to `other/ssrf_surface.txt` and `other/redirect_surface.txt`. These are surface maps, not exploitation — no payloads are sent.

### Rate Limiting Surface (Phase 7 extension)

For each live HTTP host, record rate limiting header presence and configuration:

- Capture `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, `RateLimit-Limit`, `RateLimit-Policy`, `Retry-After` headers from normal responses.
- Record which hosts have rate limiting headers (and their values) vs. which have none.
- Write to `other/ratelimit_<host>.txt`. Hosts with no rate limiting headers are noted in `recon_report.md` as Info findings — absence of rate limiting headers is worth verifying manually.

---

## Infra Mode — Overview

Infra mode is designed for network and infrastructure assessments where the engagement scope is expressed as IP ranges, CIDRs, ASNs, or an organisation name rather than a single web application. The goal is the same as web mode — eliminate the manual groundwork so that time is spent on what requires a human — but the attack surface is fundamentally different.

Key differences from web mode:

- Input is CIDR blocks and IP ranges, not domain names. Host expansion happens before scanning.
- No assumption that port 80/443 is the primary service. Everything that's alive gets identified.
- Web layer scanning (httpx, feroxbuster, nuclei) is secondary — it runs on discovered web services, but is not the primary objective.
- Service-specific protocol enumeration replaces web-specific enumeration: SMB, LDAP/Active Directory, SNMP, RPC, Kerberos, database ports, VPN gateways, management interfaces.
- Output is oriented around services and hosts rather than web endpoints and findings.
- Nessus is the primary vulnerability assessment mechanism — nmap NSE alone is not enough at infrastructure scale.

Invocation:

```
recon_jr -mode infra
recon_jr -mode infra -dir ~/Documents/Engagements/work/client-name
recon_jr -mode infra -from-phase 3
recon_jr -mode infra -allow-intrusive
```

All CLI flags from web mode carry over. `-allow-intrusive` gates the more aggressive enumeration tools (enum4linux, kerbrute, Nessus authenticated scan).

---

## Infra Mode — Phases

### Phase 1 — Asset Discovery

Establishes the full scope before any active scanning. Combines passive OSINT with the provided host file.

| Tool | Purpose | Output |
|---|---|---|
| `asnmap` / `bgpview` API | Expand ASN to IP ranges | CIDR list |
| `whois` | Confirm ownership of IP ranges | Text per range |
| Shodan API (optional) | Passive service discovery for IP ranges — ports open, banners, CVEs | JSON per IP |
| `amass intel` | Reverse WHOIS, ASN, and certificate-based asset discovery | Host + IP list |
| crt.sh API | Certificate transparency for IP-associated domains | Domain list |

**Decision logic:** Any IP range returned by ASN expansion that is not covered by the provided scope file is flagged and excluded before scanning begins — the operator must explicitly add it to scope. This prevents scope creep when an ASN contains ranges belonging to multiple legal entities.

If Shodan credentials are configured, Shodan data is used to pre-populate a list of known-open ports per host. This reduces the cold-start nmap scan time significantly on large ranges, but nmap is still run to confirm — Shodan data can be stale.

Output: `other/asn_ranges.txt`, `other/shodan_<ip>.json`, `other/amass_assets.txt`

### Phase 2 — Host Discovery

Determines which hosts in scope are alive before any port scanning begins. On large ranges, scanning dead IPs is the largest time cost.

| Tool | Purpose | Output |
|---|---|---|
| `nmap -sn` (ping sweep) | ICMP echo, TCP SYN to 80/443, TCP ACK to 80, UDP to 40125 | Alive host list |
| `masscan -p 80,443,22` | Fast TCP SYN sweep for confirmation on large ranges | Alive host list |
| `nmap -sn --send-eth` | ARP sweep for local network segments | Alive host list (LAN) |

Results are deduplicated and merged into `infra_alive_hosts` in the engagement root. This list feeds all subsequent phases.

**Decision logic:** Hosts that do not respond to the sweep are written to `infra_dead_hosts`. These are not scanned further unless `-scan-dead` is explicitly set, which forces nmap to scan them even without ping response (useful when ICMP is blocked by firewalls).

**Rate limiting:** masscan rate defaults to `--rate 1000` (packets per second). This is conservative — masscan's default is orders of magnitude higher. Configurable via `infra_masscan_rate` in config. Always lower than what production networks will notice; stealth is not the goal but availability impact prevention is.

Output: `infra_alive_hosts`, `infra_dead_hosts`

### Phase 3 — Port and Service Scanning

Full-port scan of all alive hosts with service and version detection. This is the most time-consuming phase and drives everything that follows.

| Tool | Purpose | Output |
|---|---|---|
| `nmap -p- --min-rate 500 -T3` | Full TCP port sweep per host | Per-host XML/nmap/gnmap |
| `nmap -sV -sC -p <open>` | Service/version + default NSE on open ports | Per-host XML/nmap/gnmap |
| `nmap -sU --top-ports 100` | UDP top-100 (extended from web mode top-20) | Per-host XML/nmap/gnmap |

nmap output naming follows the same convention as web mode: `nmap_tcp-fullports_<host>.*`, `nmap_tcp-svc_<host>.*`, `nmap_udp-top100_<host>.*`.

nmap is run with a lower rate (`--min-rate 500`) than web mode (`--min-rate 2000`) because infrastructure targets may include switches, routers, and OT-adjacent systems that are sensitive to traffic spikes. This is configurable via `infra_nmap_min_rate` in config.

**NSE script selection in infra mode:** Rather than the default `-sC`, infra mode uses a curated script list appropriate to the discovered services. This is determined dynamically based on which ports are open:

- Port 21 (FTP): `ftp-anon`, `ftp-bounce`, `ftp-syst`
- Port 22 (SSH): `ssh-auth-methods`, `ssh-hostkey`, `ssh2-enum-algos`
- Port 25/465/587 (SMTP): `smtp-commands`, `smtp-open-relay`, `smtp-enum-users`
- Port 53 (DNS): `dns-zone-transfer`, `dns-recursion`, `dns-srv-enum`
- Port 88 (Kerberos): `krb5-enum-users`
- Port 139/445 (SMB): `smb-security-mode`, `smb-os-discovery`, `smb2-security-mode`, `smb-vuln-ms17-010`, `smb-vuln-cve2009-3103` — these are detection scripts that probe for the vulnerability condition, they do not exploit it
- Port 389/636 (LDAP): `ldap-rootdse`, `ldap-search`
- Port 443/8443 (HTTPS): `ssl-cert`, `ssl-enum-ciphers`, `http-title`
- Port 161 (SNMP): `snmp-info`, `snmp-interfaces`, `snmp-sysdescr`
- Port 3306 (MySQL): `mysql-info`, `mysql-empty-password`
- Port 3389 (RDP): `rdp-enum-encryption`
- Port 5900 (VNC): `vnc-info`, `vnc-brute` (intrusive only — tries a small fixed list of well-known default passwords such as blank, `password`, `vnc` to detect unconfigured instances; not a brute force loop)

This produces targeted, relevant NSE output rather than running every default script against every service.

**Decision logic:** Every open port is recorded in the overview. Unexpected services are reported — not just management interfaces as in web mode, but anything that does not match the engagement's stated service profile. A database port open to the internet is always High regardless of context. An SNMP port with community string `public` readable is always noted.

Output: `nmap/nmap_tcp-fullports_<host>.*`, `nmap/nmap_tcp-svc_<host>.*`, `nmap/nmap_udp-top100_<host>.*`

### Phase 4 — Service Enumeration

Runs targeted protocol-specific enumeration tools against each service identified in Phase 3. Only runs for services that are actually present — no shotgun approach. The tool list here is driven by what nmap found, not a static list.

#### SMB (ports 139, 445)

| Tool | Purpose | Output |
|---|---|---|
| `enum4linux-ng` | SMB: null session enumeration, shares, users, OS, domain info | JSON per host |
| `smbclient -L` | Share listing via null or guest session | Text per host |
| `crackmapexec smb` / `netexec smb` | SMB signing, OS, domain membership, null session | JSON per host |

**Decision logic:** Record in report: null session authentication permitted, SMB signing disabled (relay risk), anonymous share listing, shares accessible without authentication, SMB1 enabled (if detected by nmap NSE or smb-security-mode). Guest access to shares is always High. Null session is Medium (information disclosure). SMB signing disabled alone is Medium; combined with relay-permitting configuration it becomes High.

Output: `smb/<host>_enum4linux.json`, `smb/<host>_shares.txt`

#### LDAP / Active Directory (ports 389, 636, 3268, 3269)

| Tool | Purpose | Output |
|---|---|---|
| `ldapsearch -x` | Anonymous LDAP bind — enumerate base DN, naming contexts | Text per host |
| `ldapdomaindump`* | Authenticated LDAP dump of AD objects (users, groups, GPOs) | JSON per domain |
| `enum4linux-ng -A` | AD user and group enumeration via RPC | JSON per host |

`*` = requires `-allow-intrusive` and credentials in config

**Decision logic:** Anonymous LDAP bind permitted is always reported — even read-only LDAP access leaks user accounts, group memberships, and domain structure. Record: base DN, detected domain name, whether anonymous bind returns results. If `-allow-intrusive` is set and credentials exist, a full ldapdomaindump is attempted and the results (user list, enabled/disabled accounts, admin groups, password policy) are written to `ldap/` for manual review.

Output: `ldap/<host>_rootdse.txt`, `ldap/<host>_anonymous.txt`, `ldap/domaindump/` (if authenticated)

#### SNMP (port 161)

| Tool | Purpose | Output |
|---|---|---|
| `onesixtyone` | Community string bruteforce (common strings only) | Text per host |
| `snmpwalk -v1/v2c -c public` | Walk OID tree with community string `public` | Text per host |
| `snmpwalk -v1/v2c -c private` | Walk with `private` | Text per host |

**Decision logic:** `public` or `private` community strings responding is always reported as High — these expose full system configuration, interface lists, routing tables, and often credentials. Record: responding community strings, system description OID (reveals OS and version), interface list. Full walk output written to `snmp/<host>_walk.txt`. Key OIDs parsed and summarised in the report: sysDescr, sysContact, sysName, sysLocation, hrSWRunName (running processes).

Output: `snmp/<host>_communities.txt`, `snmp/<host>_walk.txt`

#### RPC / Windows Services (ports 135, 593)

| Tool | Purpose | Output |
|---|---|---|
| `rpcclient -U ""` | Null session RPC — enumerate users, groups, password policy | Text per host |
| `impacket-rpcdump` | List RPC endpoints | Text per host |

**Decision logic:** Null session RPC access is Medium-High depending on what it exposes. Record: accessible RPC endpoints, whether user enumeration is possible via null session.

Output: `services/<host>_rpc.txt`

#### Kerberos (port 88)

| Tool | Purpose | Output |
|---|---|---|
| `nmap --script krb5-enum-users` | Username enumeration via Kerberos pre-authentication error differentiation | Text per host |
| `kerbrute userenum`* | Kerberos user enumeration using a wordlist | Text per host |

`*` = requires `-allow-intrusive`

**Decision logic:** Valid usernames confirmed via Kerberos enumeration are recorded as a Medium finding (information disclosure feeding brute-force/spray attacks). Write confirmed valid usernames to `other/valid_users.txt` — this file is referenced in the report as a deliverable for the manual test phase.

Output: `services/<host>_kerberos_users.txt`, `other/valid_users.txt`

#### Database Services (ports 1433, 3306, 5432, 1521, 27017, 6379)

| Tool | Purpose | Output |
|---|---|---|
| `nmap --script` (service-specific) | Version detection, auth check, empty password check | Text per host |

**Decision logic:** Any database port reachable from the assessment network is reported as High if authentication is not required, Medium if it is. The nmap `mysql-empty-password` NSE checks whether the root account accepts an empty password — it does not read data from the database. Unauthenticated MongoDB, unauthenticated Redis, and anonymous SQL Server connections are detected by checking whether the service accepts a connection without credentials. Record: port, version, whether authentication is required. No data is read from any database service.

#### Email Infrastructure (ports 25, 465, 587, 110, 143, 993, 995)

| Tool | Purpose | Output |
|---|---|---|
| `nmap --script smtp-*` | SMTP open relay check, user enumeration via VRFY/EXPN/RCPT | Text per host |
| `testssl.sh` | TLS configuration on SMTPS/IMAPS/POP3S | JSON per host |
| `swaks`* | SMTP relay detection — attempts a relay transaction to a non-existent address to determine if the server will accept it | Text per host |

`*` = requires `-allow-intrusive`

**Decision logic:** Open SMTP relay is Critical. SMTP user enumeration via VRFY/EXPN is Medium. STARTTLS not enforced on port 587 is Medium. Record TLS configuration issues consistent with the web mode testssl decision logic.

**Scope boundary for swaks:** swaks sends an SMTP transaction to a non-deliverable address to test whether the server accepts relay. It does not send email to real recipients, does not deliver any content, and does not attempt authentication bypass. The test is purely "will this server accept a relay request" — the transaction is rejected by the destination or never routed.

Output: `services/<host>_smtp.txt`, `other/testssl/<host>.json`

#### VPN and Remote Access (ports 500, 4500, 1194, 1701, 1723)

| Tool | Purpose | Output |
|---|---|---|
| `ike-scan` | IKEv1/IKEv2 VPN gateway detection and proposal enumeration | Text per host |
| `nmap --script` | OpenVPN, WireGuard, PPTP detection | Text per host |

**Decision logic:** Record: VPN gateway presence, IKE vendor ID (reveals VPN product and version), aggressive mode enabled (IKEv1 — allows offline PSK cracking), supported encryption/hash proposals. Weak proposals (DES, MD5) are always reported as High.

Output: `services/<host>_vpn.txt`

#### Web Services on Non-Standard Ports

Any HTTP/HTTPS service found on a non-standard port by nmap is enumerated in the same way as web mode Phase 3 onwards — but as a sub-workflow within infra mode rather than the primary objective. This includes:

- Management interfaces (Tomcat manager, JBoss, WebLogic console, Jenkins, Kibana, Grafana, Prometheus, Portainer, etc.)
- Web-based configuration UIs (router admin pages, IPMI/BMC web interfaces, printer management, etc.)
- Internal applications inadvertently exposed

`httpx` runs against all discovered web services to probe status codes, titles, and technology. `testssl` runs against all HTTPS services. `nuclei` runs with infra-appropriate templates (default credentials, exposed management panels, CVE templates). `gowitness` takes screenshots.

### Phase 5 — Known Vulnerability Identification

| Tool | Purpose | Output |
|---|---|---|
| Nessus API | Full credentialed or uncredentialed infrastructure scan | JSON |
| `nuclei -t technologies/ -t network/ -t default-logins/` | Template-based detection for default credentials and known CVEs | JSON |
| `searchsploit` (offline) | Match discovered service versions against ExploitDB — reference only | Text |

**Nessus in infra mode:** The same Nessus API integration as web mode, but using an infrastructure-appropriate policy (full port scan, network checks, not just HTTP plugins). A separate `nessus_infra_template_uuid` config key is used so infra and web policies are not confused. Nessus performs detection — it identifies vulnerability conditions, it does not exploit them.

**nuclei in infra mode:** Runs with templates from `technologies/`, `network/`, and `default-logins/` only — not web application templates, not exploit templates. `default-logins` templates check whether a service responds positively to a single known default credential pair (e.g., `admin:admin` on a Tomcat manager page). This is checking for a misconfiguration, not iterating a password list. `--exclude-tags exploit,dos,fuzz` is set unconditionally.

**searchsploit:** Runs entirely offline — it queries a local copy of the ExploitDB database against the service version strings nmap identified. No network requests are made. No exploits are run. The output is a list of known public exploits for the detected versions, written to `other/searchsploit/` as a reference for the operator to review and decide what to test manually.

**Decision logic:** All Critical and High Nessus findings in the report. Infra-specific mediums to include: default credentials confirmed present (by nuclei detection), clear-text authentication protocols, SSL/TLS on vulnerable versions, anonymous access to management interfaces. Searchsploit matches are advisory only — they identify known-exploitable versions for the operator to follow up on, they do not confirm exploitability.

Output: `nessus/`, `other/nuclei_infra.json`, `other/searchsploit/`

### Phase 6 — Web Layer (Discovered Web Services Only)

Runs a reduced version of web mode phases 2-5 against HTTP/HTTPS services discovered on non-standard ports during infra scanning. Standard ports (80, 443) from the scope are also included if the engagement contains web hosts.

This is not a full web test — it is a surface scan to identify low-hanging fruit on management interfaces and to ensure the report covers the web layer of discovered infrastructure.

Tools run per discovered web service:
- `whatweb` — technology fingerprinting
- `nuclei` (default-logins, exposed-panels, CVE templates) — default credential and known-vuln checks
- `testssl` — TLS audit on HTTPS services
- Security headers via `curl -I`
- HTTP method check via `OPTIONS`

Full web mode phases (feroxbuster, katana, arjun, wpscan, gitleaks) are **not** run in infra mode unless `-web-full` is explicitly passed. The rationale: infra mode is for understanding what's running, not for comprehensive web testing. Web application testing should be a separate engagement with its own recon_jr web mode run.

Output: same as web mode phases 2/3/7 — `other/httpx.json`, `other/whatweb.json`, `other/testssl/`, `other/headers_*.txt`

---

## Infra Mode — Output Layout

```
<engagement>/
├── .engage.json
├── .recon.json                         — run summary, mode, phase status
├── recon_report.md                     — security findings
├── recon_overview.md                   — full enumeration data (all hosts, ports, services)
├── infra_alive_hosts                   — hosts confirmed alive in Phase 2
├── infra_dead_hosts                    — hosts that did not respond to sweep
├── other/valid_users.txt               — confirmed valid usernames (Kerberos, RPC)
├── nmap/
│   ├── nmap_tcp-fullports_<host>.*
│   ├── nmap_tcp-svc_<host>.*
│   └── nmap_udp-top100_<host>.*
├── nessus/
│   ├── <name>.nessus
│   ├── nessus_results.json
│   └── nessus_low_info.json
├── smb/
│   ├── <host>_enum4linux.json
│   └── <host>_shares.txt
├── ldap/
│   ├── <host>_rootdse.txt
│   ├── <host>_anonymous.txt
│   └── domaindump/                     — only with -allow-intrusive + credentials
├── snmp/
│   ├── <host>_communities.txt
│   └── <host>_walk.txt
├── services/
│   ├── <host>_rpc.txt
│   ├── <host>_kerberos_users.txt
│   ├── <host>_smtp.txt
│   └── <host>_vpn.txt
└── other/
    ├── asn_ranges.txt
    ├── amass_assets.txt
    ├── shodan_<ip>.json
    ├── httpx.json
    ├── whatweb.json
    ├── testssl/
    ├── nuclei_infra.json
    ├── searchsploit/
    ├── screenshots/
    └── headers_<host>.txt
```

---

## Infra Mode — Configuration

Additional config keys for infra mode (added to `~/.config/recon_jr/config.json`):

```json
{
  "nessus_infra_template_uuid":  "",
  "shodan_api_key":              "",
  "infra_masscan_rate":          1000,
  "infra_nmap_min_rate":         500,
  "infra_udp_top_ports":         100,
  "infra_scan_dead_hosts":       false,
  "smb_username":                "",
  "smb_password":                "",
  "ldap_username":               "",
  "ldap_password":               "",
  "kerberos_domain":             "",
  "kerbrute_wordlist":           "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt"
}
```

`smb_username`, `smb_password`, `ldap_username`, `ldap_password` are only used when `-allow-intrusive` is set. They are never written to the engagement directory.

---

## Infra Mode — Production Safety

All the production safety controls from web mode apply without exception. Additional infra-specific controls:

**Rate limiting on port sweeps:** masscan defaults are dangerous on production networks. The `infra_masscan_rate` config key is intentionally named and documented to make its consequence clear. The default of 1000 pps is conservative. Any value above 5000 pps logs a warning before scanning.

**UDP scanning caution:** UDP top-100 is significantly more intrusive than top-20. Some UDP services (SNMP trap receivers, syslog servers, older VoIP) can behave unexpectedly when hit with a scan probe. The scan rate for UDP is capped at `-T3` (no override) and includes a 50ms inter-probe delay.

**No exploitation, no credential spray:** infra mode identifies surfaces and confirms anonymous/default access only. It does not perform credential spraying (kerbrute is user enumeration only, not password spray), does not attempt exploit execution, and does not chain findings into attack paths. That is manual work.

**Scope enforcement is mandatory in infra mode:** IP ranges must be present in the scope file before any active scanning begins. Any host discovered via ASN expansion or amass that is not covered by the scope file is excluded and logged. This is not negotiable — the blast radius of an accidental out-of-scope nmap scan on a corporate network is orders of magnitude higher than an accidental web request.

**Pre-run confirmation in infra mode:** Shows the full CIDR list, total IP count, alive host estimate (from Shodan if available, otherwise IP count), tool list, masscan rate, and Nessus status before any scanning begins. Requires explicit confirmation. This confirmation is not bypassable in infra mode — not even with `-dry-run` substituting for it.

---

## Infra Mode — CLI

```
recon_jr -mode infra [options]

Additional options in infra mode:
  -allow-intrusive         Enable enum4linux, kerbrute, ldapdomaindump, swaks
  -scan-dead               Scan hosts that did not respond to ping sweep
  -no-masscan              Skip masscan, use nmap ping sweep only
  -no-nessus               Skip Nessus scan
  -web-full                Run full web mode phases on discovered web services
  -smb-creds               Prompt for SMB credentials (overrides config)
  -ldap-creds              Prompt for LDAP credentials (overrides config)
```

---

## File Structure

| File | Owns |
|---|---|
| `main.go` | Flag parsing, mode dispatch, phase orchestration, engage_jr discovery |
| `config.go` | Config struct, 3-layer loading (web + infra keys) |
| `runner.go` | Tool execution engine |
| `meta.go` | Reads `.engage.json`, writes `.recon.json` |
| `hosts.go` | Reads host files, CIDR expansion, deduplication |
| `phases.go` | Web mode phase definitions |
| `phases_infra.go` | Infra mode phase definitions (new file) |
| `nessus.go` | Nessus API client |
| `parsers.go` | Per-tool output parsers (web tools) |
| `parsers_infra.go` | Per-tool output parsers for infra tools (enum4linux, snmpwalk, ldapsearch, etc.) |
| `report.go` | Generates `recon_report.md` |
| `overview.go` | Generates `recon_overview.md` |
| `scope.go` | Scope enforcement (host + CIDR) |
| `scope_init.go` | Interactive scope setup |
| `logger.go` | Logging |

---

## MVP Scope — Infra Mode

The full infra tool list above is the end state. The MVP that delivers the most value with the least implementation risk:

1. Phase 1: asnmap IP range expansion + WHOIS confirmation
2. Phase 2: nmap ping sweep for host discovery
3. Phase 3: nmap full TCP port scan + service detection + targeted NSE
4. Phase 4: enum4linux-ng (SMB), snmpwalk (SNMP), ldapsearch (LDAP anonymous)
5. Phase 5: Nessus API (infra template) + nuclei (default-logins templates)
6. Phase 6: httpx + testssl + nuclei on discovered web services
7. `recon_report.md` and `recon_overview.md` generation with infra-appropriate sections

Kerbrute, crackmapexec/netexec, impacket tooling, ike-scan, swaks, and searchsploit come in the next iteration once the core infra scanning pipeline is solid and has been tested on lab infrastructure.

---

## What recon_jr Does Not Do (Either Mode)

- **Does not exploit anything.** No tool is invoked in a mode that executes code on the target, modifies system state, escalates privileges, or causes a vulnerability to be triggered. nuclei `exploit` and `dos` tags are excluded unconditionally. nmap NSE scripts are limited to enumeration and detection categories.
- **Does not brute force credentials.** kerbrute runs in username enumeration mode only. SNMP checks two community strings. nuclei `default-logins` templates check one known default pair per service. There is no credential list iteration, no password spraying, no dictionary attack.
- **Does not read or copy data from target systems.** SNMP walk, anonymous LDAP bind, and SMB share listing confirm what is *accessible* — they do not retrieve files, read database records, or exfiltrate data. The distinction is: "this share is readable without authentication" is a finding; reading the contents of that share is not what this tool does.
- **Does not write to target systems.** No files are uploaded. No service configurations are changed. No S3 buckets, domains, or GitHub Pages sites are registered or claimed. Cloud storage probes are read-only HEAD requests.
- **Does not chain findings into attack paths.** The report describes what exists and what that implies — it does not describe how to combine findings into a working attack. That analysis is the operator's job, done deliberately and with appropriate authorisation.
- **Does not replace the manual test.** The output of recon_jr is a structured starting point. Every finding marked High or Critical should be verified by the operator before it goes into a client report. Automated tools produce false positives; the operator's judgement is the final check.
- **Does not run tools concurrently against the target.**
- **Does not modify or overwrite engage_jr output files.**
- **Does not make CVSS scores or risk ratings** — severity labels reflect the originating tool's own classification and are a guide for triage, not a final risk rating.
