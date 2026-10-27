# Leadline Threat Model

This document describes what Leadline actually is today, what it stores, and
which threats are mitigated, accepted, or out of scope. It is written for the
default deployment: one operator, one machine, `localhost` only, no
authentication.

It is not a claim that Leadline is a hardened multi-user service.

## 1. System model

```
┌──────────────────────────── operator's machine ────────────────────────────┐
│                                                                            │
│   Browser (React UI) ──HTTP──► FastAPI API ──► SQLite (leadline.db)         │
│                                    │                                       │
│                                    ├──► target host (DNS/TCP/TLS/HTTP)     │
│                                    ├──► NVD, crt.sh, ip-api.com (default)  │
│                                    └──► target WHOIS / DNSBL (default)     │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

The API and UI are separate processes in development and separate containers
in Docker Compose. Both published ports bind to `127.0.0.1` by default.

## 2. Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Target list and notes | SQLite | Reveals what the operator is assessing and when |
| Scan results | SQLite | Endpoints, banners, certificates, headers, findings, evidence |
| Custom request headers | SQLite (`targets.custom_headers`) | May contain cookies, bearer tokens, or API keys |
| Exported reports | Filesystem (operator-chosen) | Same data as the database, often shared more widely |
| NVD API key | Environment / `.env` | Free but rate-limited; low impact if leaked |
| Proxy URL and credentials | Environment | May expose engagement infrastructure |
| Scan traffic metadata | Network path to target | Can disclose the operator's IP and scan timing |

There are no user accounts, password hashes, session tokens, or billing data.

## 3. Trust boundaries

1. **Browser → API.** The browser is not trusted to be free of malicious
   content: the operator may browse the web while Leadline is open. The API
   has no authentication, so the boundary is the loopback interface plus the
   `Host` header allow-list.
2. **API → target.** Target responses are fully untrusted. Banners, headers,
   HTML, JavaScript, certificate fields, and API responses can all contain
   attacker-controlled text.
3. **API → third parties.** External lookups send target identifiers to
   NVD, crt.sh, ip-api.com, Spamhaus, and WHOIS servers. They are enabled by
   default and can be disabled per scan.
4. **Process → filesystem.** The database and exports are plaintext. Any
   process running as the same user can read them.

## 4. Threat actors

| Actor | Capability | Primary concern |
|---|---|---|
| Malicious website in the operator's browser | Send cross-origin requests to `localhost`, attempt DNS rebinding | Reading or modifying scan data |
| Other local user or process | Connect to loopback, read files owned by the operator if permissions allow | Data theft, scan manipulation |
| Malicious or compromised target | Return arbitrary text, huge responses, slow responses, redirects | Stored XSS, resource exhaustion, misleading results |
| Third-party lookup service | Receive target identifiers, return malicious or wrong data | Data disclosure, bad CVE correlation |
| Supply-chain attacker | Compromise a Python or npm dependency | Code execution as the operator |
| Operator error | Scan an out-of-scope system, expose the API, share a report | Legal and reputational harm |

## 5. Threats and treatment

| ID | Threat | Impact | Likelihood | Treatment |
|---|---|---|---|---|
| T1 | Another local process calls the unauthenticated API | High | Medium | Accepted: loopback-only default, documented |
| T2 | Malicious website reaches the API via DNS rebinding | High | Low | `Host` allow-list; CORS restricted to the UI origins |
| T3 | Stored XSS from a target response in the UI or an export | High | Low | React escaping; HTML export escapes and sets CSP; PDF escapes |
| T4 | API used as an internal-network proxy (SSRF-like) | High | Low | Accepted by design; localhost-only, no auth, Host allow-list |
| T5 | Database or report read from disk | High | Medium | Accepted: plaintext SQLite; file permissions and FDE are operator controls |
| T6 | Secrets in custom headers leak through the database or exports | Medium | Medium | Header values are not rendered in reports; database still stores them |
| T7 | Resource exhaustion from a large or slow target response | Medium | Medium | 2 MB body cap, request timeouts, bounded port list, NVD candidate caps |
| T8 | Scan runs beyond authorization | High | Medium | Accepted: no scope enforcement by design; authorization is the operator's job |
| T9 | Target identifiers sent to third-party lookups | Medium | Medium | Opt-in per scan; documented destinations; disable for sensitive work |
| T10 | Scanner is fingerprinted by the target | Medium | High | Request pacing and UA rotation; explicitly not invisibility |
| T11 | Malicious dependency executes code | High | Low | Small dependency set, pins/ranges; no lockfile or audit yet |
| T12 | Scan left `running` after a crash | Low | Medium | Startup recovery marks interrupted scans failed |
| T13 | Report link points somewhere malicious | Low | Low | CVE links restricted to `https://` in HTML exports |
| T14 | Interrupted write corrupts SQLite | Medium | Low | SQLite journaling; single-writer local use; no backup automation |

## 6. Detailed analysis

### 6.1 Unauthenticated local API (T1, T4)

Leadline has no login, no API token, and no RBAC. Anyone who can connect to
`127.0.0.1:8000` can create targets, start scans, read every stored result,
and delete data. This is intentional for a single-operator local tool.

The same design means the API can be used to reach hosts the operator's
machine can reach, including private ranges, loopback services, and cloud
metadata endpoints. The API is therefore a powerful local proxy. It must not
be exposed to an untrusted network without authentication and network
controls.

**Mitigations**

- Default bind is `127.0.0.1` for both API and UI.
- `ALLOWED_HOSTS` rejects requests whose `Host` header is not explicitly
  allowed.
- CORS is limited to the documented UI origins.
- Docker Compose publishes both ports on loopback only.

**Residual risk**

- Any local process or local user with network access can use the API.
- A reverse proxy that forwards arbitrary `Host` values must add its own
  hostname to `ALLOWED_HOSTS`; doing so broadens the allow-list.

### 6.2 Browser-based attacks (T2, T3, T13)

A malicious page cannot normally read cross-origin responses, but it can
still attempt requests. JSON bodies trigger a CORS preflight, which the
configured origins reject. DNS rebinding is blocked by validating the `Host`
header rather than trusting the network origin.

Target-controlled strings are stored in findings, banners, headers, and
reports. The React UI escapes text by default. The HTML export escapes every
dynamic value and sets `Content-Security-Policy: default-src 'none'`, so an
exported report is inert even if a target returned markup. PDF text is
escaped before it is passed to ReportLab. CVE links in HTML exports are
restricted to `https://`.

**Residual risk**

- Markdown exports are plain text; rendering them in a tool that executes raw
  HTML could execute target-supplied markup. Treat exported Markdown as
  untrusted content.
- A compromised dependency in the UI could bypass framework escaping.

### 6.3 Target-driven resource exhaustion (T7)

A target can return very large bodies, stream forever, or respond slowly.

**Mitigations**

- Response bodies read by HTTP fingerprinting, JavaScript analysis, parameter
  discovery, and API discovery are capped at 2 MB.
- Requests have a timeout.
- Port scanning uses a curated list, not a full 1–65535 sweep.
- CVE lookups cap the number of products and results per product.
- Full non-GET response bodies are not stored.

**Residual risk**

- A scan is not a sandbox. It runs as the operator's user and can consume
  CPU, memory, disk, and network until it finishes or the process is stopped.
- Deeply nested or pathological HTML/JSON can still be expensive to parse
  within the size cap.

### 6.4 Data at rest and secret handling (T5, T6)

The SQLite database is unencrypted. It contains target URLs, notes, response
headers, banners, findings, and triage state. Custom request headers are
stored as part of the target configuration and may contain credentials.

Reports (JSON, Markdown, HTML, PDF) contain the same information and are
written wherever the operator saves them. PDFs are visibly marked
`CONFIDENTIAL`; other formats are not, and the marking does not change the
underlying file protection. Export filenames include the target hostname.

**Mitigations**

- No telemetry and no call-home behavior.
- Reports do not render custom header values; the history API exposes only
  custom header *names*.
- The default User-Agent identifies Leadline.

**Residual risk**

- Anyone with filesystem access can read the database and exports.
- Secrets placed in custom headers remain in the database until the target is
  deleted; deleting a scan does not remove target-level headers.
- No encryption, key management, or secure deletion. A `CONFIDENTIAL` PDF
  banner does not prevent copying or indexing, and target-based filenames can
  disclose the assessed hostname.

### 6.5 External lookups (T9)

When external lookups are enabled, Leadline may contact:

| Destination | Data sent | Purpose |
|---|---|---|
| `services.nvd.nist.gov` | Product and version strings | CPE/CVE correlation |
| `crt.sh` | Target hostname | Certificate-transparency subdomains |
| `ip-api.com` | Target IP address | Geolocation / ASN |
| Spamhaus DNSBL | Target IP address as a DNS query | IP reputation |
| Target's WHOIS/RDAP service | Target hostname | Registration data |

External lookups are enabled by default for new scans but can be disabled per
scan. For sensitive engagements, disable them before starting the scan.

**Residual risk**

- Third parties may log the queries and infer which targets are being
  assessed.
- NVD and other services can return wrong, stale, or malicious data. CVE
  results are correlation data, not an assessment.

### 6.6 Reporting accuracy (T3, T9, T10)

The CVE phase has two modes:

- **CPE version-range match.** The observed product is resolved to a CPE name
  and checked against NVD `cpeMatch` ranges. Marked
  `applicability_verified: true` and included in the risk score.
- **NVD keyword fallback.** Used only when no CPE can be resolved. Marked
  `applicability_verified: false` and excluded from the risk score.

Both modes can be wrong if the detected product or version is wrong. Banner
and header detection is heuristic. Security header findings are hardening
gaps, not vulnerabilities. The report labels these limitations, but the
operator must verify before reporting.

### 6.7 Scanner fingerprinting (T10)

Request pacing rotates the User-Agent and adds delay/jitter; an optional
proxy can change the source IP. This is traffic shaping, not stealth.
Determined defenders can still fingerprint timing, TLS behavior, request
order, and the set of probes. Do not treat pacing as a guarantee of
anonymity.

### 6.8 Supply chain (T11)

Python dependencies are listed in `requirements.txt`; the UI uses npm. There
is no Python lockfile, no dependency audit in CI, and no signed release. Any
dependency compromise runs with the operator's privileges.

**Mitigations**

- Small, conventional dependency set.

**Residual risk**

- Version ranges can resolve to a compromised or broken release.
- The project has not been security-audited.

## 7. Accepted risks

The following are deliberate and documented, not bugs:

1. No authentication, RBAC, TLS, or audit log.
2. Unrestricted target selection, including private, loopback, and internal
   addresses.
3. Plaintext SQLite and plaintext exports.
4. In-process scans with no resume after restart.
5. Request pacing that does not guarantee stealth.
6. CVE correlation that can be wrong when product detection is wrong.

## 8. Out of scope

- Multi-user hosting, SaaS operation, and tenant isolation.
- Exploitation, payload delivery, or post-exploitation.
- Malware analysis or sandboxing of target content.
- Compliance certification (SOC 2, ISO 27001, etc.).
- Protecting the operator from their own authorized-testing decisions.

## 9. Hardening checklist if you expose Leadline

At minimum:

1. Put it behind a reverse proxy with TLS and strong authentication.
2. Restrict network access to the operator's device (VPN or allow-list).
3. Add the proxy hostname to `ALLOWED_HOSTS` explicitly; do not wildcard it.
4. Run as an unprivileged user in a container with a read-only root
   filesystem where possible.
5. Keep the database and exports on an encrypted volume with restrictive
   permissions.
6. Add an audit trail and a retention policy for scan data.
7. Disable external lookups for sensitive engagements.
8. Pin and audit dependencies; add CI that runs tests and a dependency scan.
9. Review the code yourself. This project has no security audit.

## 10. Reporting a vulnerability

Report security issues privately through GitHub Security Advisories on
`luel-4013/Leadline`, or open a minimal issue asking for a private contact
channel. Do not include exploit details, live credentials, or third-party scan
data in a public issue.

Include the version or commit, reproduction steps, and impact. There is no
bug bounty.
