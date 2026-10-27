# Security

## Status

Leadline is a **v0.2.x prototype** intended for a single operator on a local
machine. It is not a hardened multi-user service, and it is not audited.

The security model below describes what the tool actually does today. Read it
before exposing Leadline to anything other than `localhost`.

## Intended deployment

- One operator, one machine.
- The API and UI bind to `127.0.0.1` in the documented setup and Docker
  Compose file.
- Keep it there. For remote access, use an SSH tunnel or put it behind a
  reverse proxy that terminates TLS and enforces authentication.
- Do not bind the API to `0.0.0.0` on a shared or untrusted network.

## What is intentionally not restricted

**Leadline will scan any target you give it, including private, loopback, and
internal addresses.** This is deliberate: internal ranges, lab hosts, and
`127.0.0.1` services are exactly what a local recon tool needs to reach.
There is no deny-list and no scope enforcement.

That means the authorization boundary is you. Only scan systems you own or
have explicit written permission to test. The tool cannot tell whether a
target is in scope.

## Authentication and access control

- There is **no authentication** and no user model. Anyone who can reach the
  listening port can create targets, start scans, and read every stored result.
- There is **no RBAC**, no API token, and no audit log of who did what.
- There is **no TLS** in the default setup; traffic between the browser and
  the local API is plain HTTP.

If you need any of these, add them before exposing the service.

## Data at rest

Scan data is stored in a local SQLite database (`leadline.db` by default).
This includes target names and URLs, response headers, banners, discovered
endpoints, findings, and any custom headers you configured.

- The database is **not encrypted**. Protect it with filesystem permissions,
  full-disk encryption, or both.
- Exported reports (JSON, Markdown, HTML, PDF) contain the same information.
  Treat them as sensitive.
- Custom request headers may contain credentials or API tokens. They are
  stored as part of the target configuration.

## Network behavior

### Requests sent to targets

A scan sends ordinary HTTP requests, TCP connect probes, DNS queries, and TLS
handshakes to the target. The default User-Agent identifies Leadline. Enabling
request pacing changes the User-Agent to browser-like values and adds timing
jitter; it does not make the scan invisible.

### External lookups (on by default, opt-out per scan)

When external lookups are enabled, Leadline may contact third parties:

| Destination | Data sent | Purpose |
|---|---|---|
| `services.nvd.nist.gov` | Product and version strings | CPE/CVE correlation |
| `crt.sh` | Target hostname | Certificate-transparency subdomains |
| `ip-api.com` | Target IP address | Geolocation / ASN |
| Spamhaus DNSBL | Target IP address (as a DNS query) | IP reputation check |
| Target's WHOIS/RDAP service | Target hostname | Registration data |

Disable external lookups for sensitive engagements. There is no telemetry and
no call-home behavior otherwise.

## Built-in limits

These reduce accidental load and resource exhaustion; they are not a security
boundary.

- Request delay and concurrency caps are configurable per scan.
- HTTP requests have a timeout.
- Response bodies read into memory are capped (2 MB by default).
- The CVE phase bounds the number of NVD lookups per scan.
- Port scanning uses a curated common-port list, not a full 1–65535 sweep.
- On startup, scans left in `running`/`stopping` by a crashed process are
  marked failed rather than shown as live forever.

## Known limitations

- **CVE results can still be wrong.** CPE version-range matches are stronger
  than keyword hits, but they depend on correctly detecting the product and
  version from a banner or header. Keyword-only results are labeled unverified
  and are excluded from the overall risk score on purpose.
- **Header findings are hardening gaps**, not proof of exploitability. The
  header score is indicative.
- **No sandboxing.** The scanner runs as your user and can reach anything that
  user can reach.
- **No secret scanning or credential storage protections.** Do not put
  long-lived production credentials in custom headers.
- **Single SQLite database.** No concurrency controls or backup automation.
  Scan history is kept until you delete a scan or target.
- **In-process scans.** A restart interrupts running scans.

## Hardening if you must expose it

At minimum:

1. Put it behind a reverse proxy with TLS and strong authentication.
2. Restrict network access to the operator's device (VPN or allow-list).
3. Run it as an unprivileged user in a container with a read-only root
   filesystem where possible.
4. Keep the database and exports on an encrypted volume with restrictive
   permissions.
5. Add an audit trail and a retention policy for scan data.
6. Review the code and dependencies yourself. This project has no security
   audit.

## Reporting a vulnerability

Please report security issues privately through GitHub Security Advisories on
the repository, or by opening a minimal issue that asks for a private contact
channel. Do not include exploit details, live credentials, or third-party scan
data in a public issue.

Include the version or commit, reproduction steps, and impact. There is no
bug bounty.
