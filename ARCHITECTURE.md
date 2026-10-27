# Leadline Architecture

## High-level design

Leadline is a local-first reconnaissance workspace: a React UI, a FastAPI
backend, an in-process scan pipeline, and a single SQLite database. There is no
message broker, worker fleet, cloud service, or authentication layer in the
default deployment.

```
┌──────────────────────────────────────────────────────────────────┐
│                        Browser (React + Vite)                    │
│  Dashboard │ Targets │ Target history │ Scans │ Reports          │
└───────────────────────────────┬──────────────────────────────────┘
                                │ HTTP /api (loopback by default)
┌───────────────────────────────▼──────────────────────────────────┐
│                         FastAPI backend                          │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ Routers: targets, scans, reports, findings                 │  │
│  └────────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ ReconPipeline: 12 phases, run as a background task         │  │
│  │ DNS → host intel → ports → HTTP → tech → JS → params →     │  │
│  │ headers → API → classification → CVE → graph               │  │
│  └────────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ history.py (snapshots + diffs) │ risk.py (severity/risk)   │  │
│  └────────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ Exporters: JSON, Markdown, HTML, PDF                       │  │
│  └────────────────────────────────────────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────┘
                                │ SQLAlchemy async
┌───────────────────────────────▼──────────────────────────────────┐
│                     SQLite (leadline.db)                         │
│ Targets │ Scans │ ScanEvents │ Findings │ GraphNodes             │
└──────────────────────────────────────────────────────────────────┘
```

The scanner also makes outbound DNS, TCP, TLS, HTTP, and (when enabled) NVD,
crt.sh, ip-api.com, Spamhaus, and WHOIS queries.

## Components

### Frontend

**Location:** `ui/src/`

| Component | Responsibility |
|---|---|
| `TargetsList` | Target list, edit/delete, links to history |
| `TargetForm` | Create/update target, notes, custom headers |
| `TargetHistory` | Scan timeline, scan-to-scan diff, finding triage |
| `ScansList` | Start/stop/delete scans, request-pacing options |
| `ScanView` | Phase-by-phase progress and raw results |
| `ReportsList` / `ReportView` | Report summary, highlights, exports |

React Query handles fetching and polling. The UI talks to the API through the
Vite dev proxy (or the Docker service name) at `/api`.

### API routers

**Location:** `app/api/`

| Router | Prefix | Responsibility |
|---|---|---|
| `targets.py` | `/api/targets` | Target CRUD, history, diff |
| `scans.py` | `/api/scans` | Create/start/stop/delete scans, phase events |
| `reports.py` | `/api/reports` | Report summary, JSON/Markdown/HTML/PDF export |
| `findings.py` | `/api/findings` | Finding reads, triage updates |

The attack-surface graph is not a separate router. `graph_builder` stores
nodes/edges in `graph_nodes`, and the full report embeds a `graph_tree`.

### Reconnaissance engine

**Location:** `app/recon/`

Each phase subclasses `BaseReconPhase`, shares one context dict, and writes a
`ScanEvent` plus any `Finding` rows. `ReconPipeline` runs phases in order and
checks for a stop request between them.

| # | Module | Responsibility |
|---|---|---|
| 1 | `dns_discovery.py` | Resolve the target and record addresses |
| 2 | `host_intel.py` | DNS records, reverse DNS, WHOIS, CT subdomains, DNSSEC, geo/ASN, DNSBL |
| 3 | `port_scan.py` | Curated common-port TCP connect scan, banners, TLS certificates |
| 4 | `http_fingerprinting.py` | Methods, status codes, redirects, response headers |
| 5 | `tech_detection.py` | Server/framework/CMS/CDN/WAF signatures and endpoint probes |
| 6 | `js_analysis.py` | Fetch JavaScript, extract endpoints and API calls |
| 7 | `param_discovery.py` | URL parameters and form fields |
| 8 | `security_headers.py` | Present/missing/misconfigured browser security headers |
| 9 | `api_discovery.py` | REST, GraphQL, Swagger/OpenAPI paths |
| 10 | `vuln_classification.py` | Pattern-based candidates requiring manual review |
| 11 | `cve_lookup.py` | CPE resolution and NVD version-range checks; labeled keyword fallback |
| 12 | `graph_builder.py` | NetworkX graph and tree of discovered endpoints |

### History and risk

**Location:** `app/history.py`, `app/risk.py`

`history.py` builds a normalized snapshot per scan from its findings and phase
events, then compares two snapshots. Snapshot contents:

- findings (keyed by CVE id or type/location/title), triage state
- endpoints, open ports, resolved IPs, subdomains
- DNS records, WHOIS fields, DNSSEC state
- technologies, CDN/WAF, security headers

Diffs are computed on request rather than stored, so changing the diff logic
does not require a migration. `risk.py` is shared by reports and history so
both compute the same score.

### Exports

**Location:** `app/api/reports.py`, `app/pdf_export.py`

| Format | Notes |
|---|---|
| JSON | Structured report, phase data, and serialized findings |
| Markdown | Escaped, human-readable report with fenced evidence |
| HTML | Escaped, self-contained, restrictive CSP |
| PDF | ReportLab, escaped findings/evidence, confidentiality markings |

Findings in every format include severity, location, description, evidence,
remediation, and triage state. Export filenames follow
`<host>[_port]-scan-<id>.<ext>`; filenames are sanitized so target-controlled
text cannot inject a path or header value. All export formats contain
target-controlled data and should be treated as sensitive. The PDF's
`CONFIDENTIAL` banner and footer are handling instructions, not encryption.

## Data flow

### Scan execution

```
1. UI POSTs /api/scans with target and pacing options.
2. UI POSTs /api/scans/{id}/start.
3. API marks the scan running and schedules run_scan_pipeline().
4. The background task opens its own async DB session.
5. For each phase: execute, store ScanEvent, store findings, update progress,
   check the stop flag.
6. graph_builder stores nodes/edges.
7. Scan status becomes completed (or stopped/failed).
8. UI polls /api/scans and /api/targets/{id}/history.
```

A scan runs inside the API process. If the process restarts, interrupted scans
are marked failed on the next startup; they are not resumed.

### History and diff

```
1. UI GETs /api/targets/{id}/history.
2. load_target_history() loads scans, findings, and events in batched queries.
3. Each scan is reduced to a snapshot.
4. Terminal scans are compared pairwise for timeline changes.
5. The latest two terminal scans produce latest_diff.
6. GET /api/targets/{id}/history/diff?from_scan_id=&to_scan_id= computes an
   arbitrary comparison for the same target.
```

### Report generation

```
1. UI GETs /api/reports/{id}.
2. The router loads the scan, target, events, findings, and graph nodes.
3. build_report_summary() computes counts and risk.
4. build_report_highlights() extracts human-readable findings from phase data.
5. Export routes serialize the report and findings, escape target-controlled
   values, and set a target-based download filename.
```

## Security boundaries

- **Browser ↔ API:** loopback bind, `Host` allow-list, restricted CORS. No
  authentication.
- **API ↔ target:** target responses are untrusted; bodies are capped, text is
  escaped on export, and links are restricted.
- **API ↔ third parties:** NVD, crt.sh, ip-api.com, Spamhaus, and WHOIS are
  enabled by default and can be disabled per scan.
- **Process ↔ filesystem:** SQLite and exports are plaintext; filesystem
  permissions and full-disk encryption are operator controls.

See [SECURITY.md](SECURITY.md) and [THREAT_MODEL.md](THREAT_MODEL.md).

## Configuration

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `sqlite+aiosqlite:///./leadline.db` | Database connection |
| `DEFAULT_USER_AGENT` | `Leadline/0.2 (+https://github.com/luel-4013/Leadline)` | Default HTTP User-Agent |
| `REQUEST_DELAY` | `0.5` | Base delay between requests (seconds) |
| `MAX_CONCURRENT` | `5` | Maximum concurrent requests |
| `PROXY_URL` | `None` | Optional proxy for scan traffic |
| `ALLOWED_HOSTS` | localhost, 127.0.0.1, ::1, backend, testserver | Host-header allow-list |
| `NVD_API_KEY` | `None` | Optional NVD key; raises rate limit from 5 to 50 requests/30s |
| `MAX_RESPONSE_BYTES` | `2000000` | Response-body read cap |
| `CVE_LOOKUP_MAX_CANDIDATES` | `8` | Maximum products checked per scan |

Copy `.env.example` to `.env` and set only what you need.

## Extensibility

### Adding a recon phase

1. Create a module in `app/recon/`.
2. Subclass `BaseReconPhase`, set `name`, `order`, and `description`.
3. Implement `execute()` and call `self.add_finding()` for results.
4. Register the phase in `app/recon/pipeline.py` in execution order.
5. Add a test with a controlled target.

### Adding a detection pattern

1. Update signatures in `tech_detection.py` or `vuln_classification.py`.
2. Keep matches labeled as candidates unless independently verified.
3. Add a regression test for the pattern.

### Adding an export format

1. Add a formatter/route in `app/api/reports.py`.
2. Escape all target-controlled values and set appropriate headers.
3. Add a UI button and a test for the new format.

## Known constraints

- Single-process, single-user design. No job queue, distributed workers, or
  multi-tenancy.
- SQLite with no migration framework; startup adds missing columns on a
  best-effort basis.
- Scans are not resumed after a restart.
- `history.py` computes snapshots on request; very large histories will make
  the history endpoint slower before they make it incorrect.
