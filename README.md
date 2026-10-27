# Leadline

[![CI](https://github.com/luel-4013/Leadline/actions/workflows/ci.yml/badge.svg)](https://github.com/luel-4013/Leadline/actions/workflows/ci.yml)

**A local-first attack surface mapper with memory.**

Leadline is a single-user reconnaissance workspace for authorized security
testing. It runs a 12-phase pipeline against a target you own or have written
permission to test, stores every scan in SQLite, and keeps the results together
so you can see what changed since last time.

It is not a SaaS. It does not phone home. It binds to localhost by default.
You bring the authorization; Leadline brings the timeline.

> **Status:** v0.2.0. The full scan path works end to end, including history,
> diffs, triage, and exports. Read [Limitations](#limitations) before pointing
> it at anything important.

## Why Leadline?

Most recon tools are one-shot pipelines: run them, get a dump, lose the
context. Leadline is built around a different question:

> **What changed since the last scan?**

- Every scan is stored with its target, configuration, phase results, and
  findings.
- A target history page shows the scan timeline, scan-to-scan diffs, port and
  DNS drift, technology changes, endpoint churn, and finding triage.
- Results stay attached to the target instead of disappearing into a terminal
  scrollback.
- Native collectors cover DNS, WHOIS, TLS, ports, HTTP, technology, JavaScript,
  parameters, APIs, and security headers.
- Everything is local: SQLite, no account, no cloud, no telemetry.
- Reports are evidence-oriented: JSON, Markdown, HTML, and PDF.

The long-term direction is a lightweight local alternative to heavy recon
platforms: less setup than reNgine, more memory than reconFTW, and no need to
assemble the entire ProjectDiscovery pipeline by hand for a quick first pass.

## What it does

Twelve phases, in execution order:

1. **DNS discovery** — resolve the target and record addresses.
2. **Host intelligence** — A/AAAA/MX/NS/TXT/CNAME/SOA records, reverse DNS,
   WHOIS, certificate-transparency subdomains, DNSSEC presence, geolocation/ASN,
   and a Spamhaus DNSBL check.
3. **Port scan** — TCP connect scan of common ports, banner grabbing, and TLS
   certificate inspection (SANs, issuer, expiry, self-signed detection).
4. **HTTP fingerprinting** — methods, status codes, redirects, response headers.
5. **Technology detection** — server/framework/CMS/CDN/WAF signatures.
6. **JavaScript analysis** — fetch referenced scripts and extract endpoints,
   API calls, and parameter names.
7. **Parameter discovery** — query parameters and form fields from HTML/JS.
8. **Security headers** — present/missing/misconfigured browser security headers.
9. **API discovery** — common REST/GraphQL/Swagger/OpenAPI paths and references.
10. **Vulnerability classification** — pattern-based candidates that need manual
    review, not confirmed vulnerabilities.
11. **CVE correlation** — resolves detected products to CPE names and checks
    NVD version ranges. Unresolved products fall back to NVD keyword candidates
    and are labeled unverified.
12. **Attack-surface graph** — a path tree of discovered endpoints.

## Safety model

Leadline is designed for a single operator on a local machine.

- **Localhost by default.** The API and UI bind to `127.0.0.1`. Do not expose
  them directly to the internet.
- **No authentication.** This is a local tool, not a multi-user service. If you
  need remote access, put it behind a reverse proxy with TLS and authentication,
  or use an SSH tunnel.
- **Any target you are authorized to scan.** Leadline intentionally does not
  block private, internal, or loopback targets. That is useful for labs and
  internal engagements. Authorization remains your responsibility.
- **External lookups are on by default and can be disabled per scan.** When
  enabled, host intelligence may send the target IP to `ip-api.com`, query
  `crt.sh`, query Spamhaus via DNS, query WHOIS/RDAP, and query NVD (CPE and CVE
  APIs). Disable it for sensitive engagements.
- **Host header allow-list.** The API rejects requests whose `Host` header is
  not loopback (or an explicitly allowed proxy host), which blocks the common
  DNS-rebinding path against localhost services.
- **No telemetry.** Leadline does not call home.

If you deploy this beyond your own machine, you are responsible for adding
authentication, TLS, network controls, and an audit trail.

### Stealth and pacing

For pentest work, Leadline can rotate User-Agents, add randomized delays, and
send requests through a proxy. This is **request pacing and traffic shaping,
not invisibility**: determined defenders can still fingerprint scanners. Use
it to avoid obvious noise and to stay inside engagement rules, not as a
guarantee of stealth.

## Quick start

### Docker

```bash
docker compose up --build
```

The UI is available at `http://127.0.0.1:3000` and the API at
`http://127.0.0.1:8000`. Both ports are bound to loopback only.

### Manual setup

#### Backend

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # optional: add an NVD API key for faster CVE lookups
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

#### Frontend

```bash
cd ui
npm install
npm run dev
```

The Vite dev server proxies `/api` to `http://127.0.0.1:8000`.

## Usage

1. Add a target under **Targets**.
2. Open the target to see its history.
3. Start a scan under **Scans**.
4. Watch the phase progress.
5. Open the report for findings, highlights, and exports.
6. Re-scan the target and use the history diff to see what changed.

You can also use the API:

```bash
# Create a target
curl -X POST http://127.0.0.1:8000/api/targets \
  -H 'Content-Type: application/json' \
  -d '{"url": "lab.local", "name": "Lab environment"}'

# Create and start a scan
curl -X POST http://127.0.0.1:8000/api/scans \
  -H 'Content-Type: application/json' \
  -d '{"target_id": 1}'
curl -X POST http://127.0.0.1:8000/api/scans/1/start

# Export the report
curl http://127.0.0.1:8000/api/reports/1/export/json
```

## Development

```bash
# Backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pytest -q

# Frontend
cd ui
npm install
npm run typecheck
npm run build
```

CI runs the same backend checks (pytest, pyflakes, compileall) and the frontend
typecheck/build on every push and pull request.

## Project structure

```
Leadline/
├── app/                 # FastAPI backend and recon engine
│   ├── api/             # targets, scans, reports, findings
│   ├── recon/           # 12-phase reconnaissance pipeline
│   ├── history.py       # target timeline and scan-to-scan diffs
│   ├── risk.py          # shared severity/risk calculations
│   ├── config.py
│   ├── db.py
│   ├── models.py
│   └── schemas.py
├── ui/                  # React + Vite frontend
├── tests/               # pytest suite
├── docs/                # API and usage docs
├── Dockerfile
└── docker-compose.yml
```

## Limitations

- **Not autonomous.** It runs a fixed phase sequence. It does not plan, pivot,
  or exploit anything.
- **No authentication.** Keep it on localhost.
- **CVE matching is a correlation, not an assessment.** CPE version-range
  matches are much stronger than keyword hits, but product detection from a
  banner can still be wrong. Keyword-only candidates are always labeled.
- **No distributed job queue.** Long scans run in-process. A server restart marks
  interrupted scans as failed instead of resuming them.
- **Native collectors are a baseline.** They are convenient when ProjectDiscovery
  tools are not installed, not a replacement for them.
- **Header scoring is indicative.** A missing header is not automatically a
  vulnerability, and a present header is not automatically correct.
- **Single-user SQLite.** No concurrency controls, RBAC, or multi-tenancy.
- **History is local and unencrypted.** Keep until you delete it; protect the
  database and exports accordingly.

## Roadmap

- Optional API token for deliberate remote access
- Import/export adapters for ProjectDiscovery tools
- Evidence snapshots and reproducible scan configuration
- Traffic profiles (cautious / standard / fast) with jitter and header shaping
- Broader safety and regression tests

## Responsible use

Leadline is for legitimate security research and authorized penetration testing
only. Always obtain written authorization before scanning a system you do not
own. See [SECURITY.md](SECURITY.md) for the current security model and reporting
process.

## License

MIT. See [LICENSE](LICENSE).
