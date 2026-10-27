# Development Notes

This file is a historical development note, not a security audit or a
verification report.

## Current state (0.2.0)

The project was renamed from BlackBox Recon to Leadline and hardened in the
following areas:

- Localhost-only defaults and a Host-header allow-list.
- Escaped HTML report exports and a restrictive CSP on exported reports.
- Capped HTTP response-body reads (2 MB default).
- Interrupted-scan recovery on startup.
- CVE correlation via CPE version ranges, with keyword-only results labeled
  unverified.
- Target history: scan timeline, finding triage, and scan-to-scan diffs for
  findings, endpoints, ports, DNS, WHOIS, technologies, and security headers.

## Verification status

Checked in the development environment on 2026-10-27:

- `python -m pytest -q`: **41 passed**.
- `pyflakes app tests`: clean.
- `python -m compileall app tests`: clean.
- `npm ci` from the committed lockfile: 141 packages installed.
- `npm run typecheck` with the lockfile toolchain (TypeScript 5.9.3): clean.
- `npm run build` with the lockfile toolchain: 1458 modules transformed, build
  succeeds.
- End-to-end scan against `tests/controlled_target.py`
  (`http://127.0.0.1:8765`) with external lookups disabled:
  - all 12 phases emitted events and the scan finished `completed`;
  - report generation worked;
  - JSON, Markdown, HTML, and PDF exports worked;
  - exports were named after the target (`<host>[_port]-scan-<id>.<ext>`);
  - Markdown, HTML, and PDF exports listed findings with evidence and
    remediation, and the PDF evidence boxes no longer overlap their labels;
  - PDF exports carry a cover confidentiality banner, a `CONFIDENTIAL` marker
    in every footer, and a closing authorized-use disclosure;
  - the HTML export carried a restrictive CSP;
  - deleting a scan removed it from target history.

Tests cover API basics, the Host-header allow-list, scan diffing, CPE version
comparison and range matching, risk scoring/triage behavior, history/diff
endpoints, triage updates, per-scan deletion, and the terminal-scan restart
guard.

What was **not** verified here:

- Live NVD responses. No live response was captured during development, so
  the CPE and CVE query shapes follow the documented NVD API and are covered by
  unit tests, not a production traffic sample.
- A manual browser click-through of every UI state. The production build and
  TypeScript checks pass, but visual/interaction testing is still manual.
- The GitHub Actions workflow. It is new and will be validated by the first
  public push.

Do not treat this file as evidence that the application was runtime
tested on your machine. Run the test suite and a local scan before relying on
the results.

### Reproduce

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python -m pytest -q
python -m compileall -q app tests

cd ui
npm install
npx tsc -p tsconfig.json --noEmit
npm run build
```

## Historical note

The original v0.1.1 debug report referenced `/workspace`, a 9-phase pipeline,
and stub recon modules. Those details are obsolete: the pipeline now has 12
phases and the collectors are implemented. The old report was replaced rather
than left in place because it described a state that no longer exists.
