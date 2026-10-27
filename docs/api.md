# Leadline API Reference

## Base URL

```
http://localhost:8000/api
```

## Endpoints

### Targets

#### GET /targets
List all targets.

**Response:** `Target[]`

#### POST /targets
Create a new target.

**Body:**
```json
{
  "name": "string",
  "url": "string",
  "notes": "string (optional)",
  "custom_headers": { "Authorization": "Bearer ... (optional)" }
}
```

**Response:** `Target`

#### GET /targets/{id}
Get a specific target.

**Response:** `Target`

#### PUT /targets/{id}
Update a target.

**Body:** Partial `Target` object

**Response:** `Target`

#### DELETE /targets/{id}
Delete a target and its scans (cascade).

**Response:** `204 No Content`

#### GET /targets/{id}/history
Target timeline, latest scan-to-scan diff, and totals. History is retained
until the target is deleted.

**Response:**
```json
{
  "target": { "id": 1, "name": "...", "url": "..." },
  "scans": [
    {
      "scan_id": 1,
      "status": "completed",
      "risk_score": 35,
      "risk_level": "medium",
      "severity_counts": { "critical": 0, "high": 0, "medium": 1, "low": 2, "info": 5 },
      "finding_count": 8,
      "verified_cves": 0,
      "unverified_cves": 1,
      "changes": null
    }
  ],
  "latest_diff": { "from_scan": {}, "to_scan": {}, "summary": {}, "findings": {} },
  "totals": { "scans": 1, "completed": 1, "failed": 0 }
}
```

#### GET /targets/{id}/history/diff?from_scan_id=1&to_scan_id=2
Full diff between two scans that belong to the same target. Includes
new/removed/changed findings, endpoints, open ports, resolved IPs, subdomains,
technologies, DNS records, WHOIS fields, security headers, and DNSSEC state.

### Scans

#### GET /scans
List all scans.

**Response:** `Scan[]`

#### POST /scans
Create a new scan.

**Body:**
```json
{
  "target_id": 1,
  "evasion_enabled": true,
  "request_delay": 0.5,
  "enable_external_lookups": true
}
```

`evasion_enabled` is the API-compatible name for request pacing: it rotates
the User-Agent and adds timing jitter. It does not guarantee stealth.

**Response:** `Scan`

#### GET /scans/{id}
Get scan status.

**Response:** `Scan`

#### POST /scans/{id}/start
Start a scan execution. Only `pending` scans can be started; create a new scan
to run a target again. Re-running a terminal scan would append duplicate events
and findings.

**Response:** `Scan`

#### POST /scans/{id}/stop
Stop a running scan.

**Response:** `Scan`

#### DELETE /scans/{id}
Delete a scan and its events, findings, and graph nodes. Running or stopping
scans must be stopped first. History is kept until it is deleted; there is no
automatic retention window.

**Response:** `204 No Content`

### Findings

#### GET /findings?scan_id={id}
List findings, optionally filtered to one scan.

**Response:** `Finding[]`

#### GET /findings/{id}
Get one finding.

**Response:** `Finding`

#### PATCH /findings/{id}
Update triage state. `is_false_positive` and `triage_status` are kept in sync.

**Body:**
```json
{
  "triage_status": "acknowledged",
  "triage_note": "Confirmed in change window"
}
```

`triage_status` is one of `open`, `acknowledged`, or `false_positive`.

**Response:** `Finding`

### Reports

#### GET /reports/{id}
Get full report.

**Response:** `FullReport`

#### GET /reports/{id}/export/json
Export as JSON.

**Response:** JSON file download

#### GET /reports/{id}/export/markdown
Export as Markdown.

**Response:** MD file download

#### GET /reports/{id}/export/html
Export as HTML.

**Response:** HTML file download (all target-controlled values escaped)

#### GET /reports/{id}/export/pdf
Export as a formatted PDF.

**Response:** PDF file download

## Data Models

### Target
```typescript
{
  id: number
  name: string
  url: string
  notes: string | null
  custom_headers: Record<string, string> | null
  is_active: boolean
  created_at: datetime
  updated_at: datetime | null
}
```

### Scan
```typescript
{
  id: number
  target_id: number
  status: "pending" | "running" | "completed" | "failed" | "stopped"
  progress: number (0-100)
  current_phase: string | null
  started_at: datetime | null
  completed_at: datetime | null
  error_message: string | null
  evasion_enabled: boolean
  request_delay: number | null
  enable_external_lookups: boolean
  created_at: datetime
}
```

### FullReport
```typescript
{
  scan_id: number
  target_name: string
  target_url: string
  status: string
  summary: {
    total_endpoints: number
    api_routes: number
    authentication_mechanisms: number
    debug_interfaces: number
    suspicious_parameters: number
    possible_vulns: number
    missing_controls: number
    cves_found: number
    verified_cves: number
    critical_cves: number
    risk_score: number
    risk_level: string
  }
  phases: Array<{
    phase_name: string
    phase_order: number
    status: string
    findings_count: number
    data: object | null
  }>
  endpoints: string[]
  graph_tree: object | null
  created_at: datetime
  completed_at: datetime | null
}
```
