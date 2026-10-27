# Leadline Usage Guide

## Running Scans

### Via UI

1. **Add a target**
   - Open **Targets** and click **Add Target**.
   - Enter a name and any URL, hostname, IP, or private/internal address.
     Leadline does not block target types; only scan what you are authorized
     to test.
   - Optionally add notes and custom request headers (for example a cookie or
     bearer token for an authenticated target).

2. **Start a scan**
   - Open **Scans**, pick the target, and click **Start Scan**.
   - **Request pacing** rotates the User-Agent and adds timing jitter. It is
     traffic shaping, not invisibility.
   - **External lookups** is enabled by default and can be disabled per scan.
     Disable it for sensitive engagements; it sends target identifiers to NVD,
     crt.sh, ip-api.com, Spamhaus, and WHOIS services.

3. **Watch progress**
   - The scan page shows each phase and its findings.
   - A scan left in `running` by a process restart is marked failed on the
     next startup; it is not resumed.

4. **Read the report**
   - Open **Reports** or click **Report** on a completed scan.
   - Review findings, raw phase data, and CVE correlations.
   - Export as JSON, Markdown, HTML, or PDF.

### Via API

```bash
# Create target
curl -X POST http://localhost:8000/api/targets \
  -H "Content-Type: application/json" \
  -d '{"name": "Lab", "url": "192.168.1.10"}'

# Create scan (request pacing on, external lookups off)
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target_id": 1, "evasion_enabled": true, "enable_external_lookups": false}'

# Start scan
curl -X POST http://localhost:8000/api/scans/1/start

# Check status
curl http://localhost:8000/api/scans/1

# Stop a scan
curl -X POST http://localhost:8000/api/scans/1/stop

# Delete a scan and its results (cannot be undone)
curl -X DELETE http://localhost:8000/api/scans/1
```

## Target History

Open a target from **Targets** to see its timeline.

- Every scan is listed with status, duration, risk score, finding counts, and
  change counts versus the previous terminal scan.
- **Diff** compares two scans. It covers new/removed/changed findings,
  endpoints added/removed, ports opened/closed/changed, resolved IPs,
  subdomains, technologies, CDN/WAF, DNS records, WHOIS fields, DNSSEC state,
  and security headers added/removed.
- Findings can be marked **acknowledged**, **false positive**, or reopened.
  Triage state is stored in SQLite and shown in subsequent diffs.
- History is kept until you delete a scan or the target. There is no automatic
  retention window.

### Diff API

```bash
curl "http://localhost:8000/api/targets/1/history"
curl "http://localhost:8000/api/targets/1/history/diff?from_scan_id=4&to_scan_id=7"
```

## Interpreting Reports

### Summary metrics

| Metric | Description |
|--------|-------------|
| Endpoints | Discovered URLs and paths |
| API routes | REST/GraphQL endpoints |
| Auth mechanisms | Login/auth systems found |
| Debug interfaces | Admin/debug panels |
| Suspicious params | Potentially dangerous parameters |
| Possible vulns | Pattern-based candidates needing review |
| Missing controls | Security header hardening gaps |
| Open ports | Open TCP ports from the curated list |
| CVE candidates | All CVE correlations |
| Verified CVEs | CVE matches that passed a CPE version-range check |
| Critical CVE candidates | CVEs scored critical by NVD (verify applicability) |

Overall risk is derived from the highest-severity finding present, not the
total count. Findings marked false positive are excluded from the risk score,
as are unverified CVE candidates; CPE version-range matches are included.

### Phase results

Leadline runs 12 phases:

1. **DNS discovery** — resolve the target and record addresses.
2. **Host intelligence** — DNS records, reverse DNS, WHOIS, certificate
   transparency subdomains, DNSSEC, geolocation/ASN, and IP reputation.
3. **Port scan** — curated common-port TCP connect scan, banners, TLS
   certificates.
4. **HTTP fingerprinting** — methods, status codes, redirects, headers.
5. **Technology detection** — server, framework, CMS, CDN/WAF signatures.
6. **JavaScript analysis** — fetch scripts and extract endpoints and API
   calls.
7. **Parameter discovery** — URL parameters and form fields.
8. **Security headers** — present, missing, and misconfigured browser headers.
9. **API discovery** — REST, GraphQL, Swagger/OpenAPI paths.
10. **Vulnerability classification** — pattern-based candidates for manual
    review.
11. **CVE correlation** — resolve products to CPE names and check NVD version
    ranges; unresolved products fall back to labeled keyword candidates.
12. **Attack-surface graph** — path tree of discovered endpoints.

## Exporting Data

```bash
curl http://localhost:8000/api/reports/1/export/json -o report.json
curl http://localhost:8000/api/reports/1/export/markdown -o report.md
curl http://localhost:8000/api/reports/1/export/html -o report.html
curl http://localhost:8000/api/reports/1/export/pdf -o report.pdf
```

HTML exports escape target-controlled values and set a restrictive CSP. Treat
all exports as sensitive: they contain the same data as the local database,
including discovered endpoints and findings.

## Using the Attack Surface Graph

The graph shows:

- **Root node** — target domain/IP.
- **Endpoint nodes** — discovered paths.
- **API nodes** — API routes.
- **Parameter nodes** — input vectors.

Click nodes to expand or collapse branches.

## Configuration

Copy `.env.example` to `.env` and set only what you need:

```bash
REQUEST_DELAY=0.5        # Seconds between requests
MAX_CONCURRENT=5         # Parallel requests
DEFAULT_USER_AGENT=...   # HTTP User-Agent
PROXY_URL=http://...     # Optional outbound proxy
NVD_API_KEY=...          # Optional; raises NVD rate limit
ALLOWED_HOSTS=["localhost","127.0.0.1","::1"]
```

## Best Practices

1. **Always obtain authorization** before scanning.
2. **Start with low concurrency** for fragile targets.
3. **Review findings manually.** CVE correlation and header analysis are
   indicative, not proof of exploitability.
4. **Disable external lookups** when target identifiers must not leave the
   machine.
5. **Protect the database and exports.** They are plaintext and contain
   sensitive engagement data.
6. **Delete scans or targets deliberately.** History has no automatic expiry.
