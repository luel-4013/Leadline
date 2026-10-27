# Changelog

All notable changes to Leadline will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-10-27

Leadline is the renamed and hardened continuation of BlackBox Recon. The
project is still a prototype; this release focuses on honest reporting,
target memory, and removing ways the tool could become a liability.

### Added
- Target history: a timeline of scans with status, duration, risk score,
  finding counts, and a compact change summary against the previous scan.
- Scan-to-scan diffs for new/removed/changed findings, endpoints, open ports,
  resolved IPs, subdomains, technologies, CDN/WAF, DNS records, WHOIS fields,
  DNSSEC state, and security headers.
- Finding triage (`open`, `acknowledged`, `false_positive`) with an optional
  note, exposed through `PATCH /api/findings/{id}` and the target history UI.
- Per-scan and per-target deletion. History has no automatic retention window;
  it is kept until the operator deletes it.
- CPE-based CVE correlation: product aliases, NVD CPE lookup, CPE version-range
  evaluation, pagination, optional `NVD_API_KEY`, and a labeled keyword
  fallback when no CPE can be resolved.
- `.env.example` and documented configuration for NVD and Host allow-listing.
- Unit tests for scan diffing, version comparison, and CPE range matching.

### Changed
- Renamed the project, package names, UI, database defaults, Docker setup, and
  documentation from BlackBox Recon to Leadline.
- Repositioned as a local-first attack surface mapper with memory, not an
  "autonomous" scanner.
- Rewrote the README, SECURITY.md, THREAT_MODEL.md, and usage docs around the
  actual deployment model: single operator, localhost by default, no
  authentication, unrestricted targets by design.
- Docker Compose now binds both published ports to `127.0.0.1` and disables
  debug mode by default.
- Renamed the UI "Detection evasion" label to "Request pacing" and documented
  it as traffic shaping, not guaranteed stealth.
- Security header analysis no longer recommends the obsolete
  `X-XSS-Protection` header, treats `frame-ancestors` as satisfying
  `X-Frame-Options`, skips HSTS on plain-HTTP targets, and reports missing
  headers as low/info hardening gaps with an indicative score.
- CVE results record `applicability_verified`. CPE version-range matches are
  included in the risk score; keyword-only candidates are excluded and labeled
  unverified in the API, UI, and every export.
- Bare hostnames and IP addresses are normalized once at pipeline start, so
  the same target works across every phase.
- Cleaned `requirements.txt`: removed unused auth, templating, and retry
  dependencies. Removed unused UI dependencies (`axios`, `@xyflow/react`,
  ESLint) and added a `typecheck` script.
- Added a GitHub Actions workflow that runs the backend test suite and the
  frontend typecheck/build.

### Fixed
- Stored XSS in exported HTML and Markdown reports: target-controlled values
  are escaped, CVE links are restricted to HTTPS, and HTML exports set a
  restrictive Content-Security-Policy.
- Unbounded response-body reads in HTTP fingerprinting, JavaScript analysis,
  parameter discovery, and API discovery. Bodies are capped at 2 MB by
  default and full non-GET bodies are no longer stored in scan events.
- Scans interrupted by a process restart stayed `running` forever; they are
  now marked failed on startup.
- Repaired `.gitignore`, which contained literal triple backticks and did not
  ignore local databases correctly.

### Known issues
- No authentication, RBAC, TLS, or audit log. Localhost only.
- CPE matching is only as good as the detected product/version, and the CPE
  alias list is deliberately small. Keyword-only results require manual review.
- Scans run in-process and are not resumed after a restart.
- No Python lockfile or dependency audit in CI.

## [v0.1.1] - 2026-08-23

### Fixed
- **Scan Events API**: Added missing `/api/scans/{scan_id}/events` endpoint for retrieving scan events (P1)
- **Frontend dependency**: Replaced deprecated `react-flow-renderer` with `@xyflow/react` v12 (P1)
- **TypeScript build error**: Removed unused `refetch` variable in ScansList component (P3)

### Verified
- Full end-to-end scan lifecycle: target creation → scan execution → 9-phase pipeline → report generation
- All export formats working: JSON, Markdown, HTML
- Frontend production build succeeds
- All existing tests pass (10/10)

## [v0.1.0] - 2024-01-01

### Added

#### Core Features
- Initial release as BlackBox Recon (later renamed Leadline)
- Multi-phase reconnaissance pipeline (9 phases)
- Target management (CRUD operations)
- Scan management with live status tracking
- Attack surface graph visualization
- Report generation with multiple export formats (JSON, Markdown, HTML)

#### Backend (FastAPI)
- RESTful API for targets, scans, reports, and graph data
- Async SQLAlchemy database layer with SQLite
- Modular recon engine with phase-based architecture
- Detection evasion capabilities (User-Agent, delays, proxy)
- Pydantic schemas for request/response validation

#### Reconnaissance Phases
1. DNS Discovery - Subdomain enumeration
2. HTTP Fingerprinting - Method detection, status codes
3. Technology Detection - Stack identification
4. JavaScript Analysis - Endpoint extraction from JS files
5. Parameter Discovery - URL and form parameter detection
6. Security Header Analysis - Missing security headers
7. API Discovery - REST/GraphQL endpoint detection
8. Vulnerability Classification - Pattern-based detection
9. Graph Builder - NetworkX-based attack surface construction

#### Frontend (React + Vite)
- Modern, responsive UI with Tailwind CSS
- Target management interface
- Scan viewer with real-time progress
- Interactive attack surface graph/tree
- Detailed report view with expandable sections
- Export functionality (JSON, Markdown, HTML)
- Dark/light theme support
- Toast notifications for user feedback

#### Database
- SQLite backend with async support
- Models: Target, Scan, ScanEvent, Finding, GraphNode
- Event storage for per-phase results

#### Documentation
- README.md - Overview and quickstart
- ARCHITECTURE.md - System design and data flow
- SECURITY.md - Security guidelines and best practices
- THREAT_MODEL.md - Comprehensive threat analysis
- docs/usage.md - How to run scans and interpret results
- docs/api.md - API endpoint reference

#### Infrastructure
- Dockerfile for containerized deployment
- docker-compose.yml for single-command setup
- requirements.txt for Python dependencies
- package.json for frontend dependencies
- Basic pytest test suite

### Technical Details

**Backend Stack:**
- Python 3.11+
- FastAPI 0.109+
- SQLAlchemy 2.0+ (async)
- Pydantic 2.0+
- NetworkX 3.0+
- aiohttp for async HTTP
- uvicorn as ASGI server

**Frontend Stack:**
- React 18+
- TypeScript 5+
- Vite 5+
- Tailwind CSS 3+
- React Flow for graph visualization
- Axios for API calls

**Development Tools:**
- pytest for backend testing
- ESLint/Prettier for frontend linting
- Docker for containerization

### Note
This entry describes the original BlackBox Recon prototype. It is superseded
by 0.2.0 for the security model, dependency list, UI, and phase count. The
current limitations and roadmap live in the README.
