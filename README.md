# VulnTrack Sentinel
**Prioritize Exposure. Verify Remediation.**

An intelligent vulnerability prioritisation and remediation platform (Flask + SQLite). Upgraded from `vuln-tracker-lab`; all earlier features (Nmap XML and OpenVAS/GVM CSV/XML parsing, severity, OWASP mapping, status updates, filtering, CSV export) are preserved. It is **not** a DLP tool.

Differentiators: explainable evidence-based priority; scan-to-scan lifecycle tracking; **verified** (not just claimed) remediation; asset-centric risk; SLA remediation queue; evidence-backed audit trail.

> Only scan and import reports for systems you are authorised to assess. Imported data is treated as inert text: never executed.

## Run locally (Windows PowerShell)
```powershell
cd vuln-tracker-lab
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt -r requirements-dev.txt

# Option A: interview demo (synthetic data, random one-time passwords printed to console)
$env:DB_PATH = "demo.db"; $env:VULNTRACK_DEMO = "1"
python manage.py seed-demo
python app.py                      # http://127.0.0.1:8000

# Option B: real start (empty DB, you create the admin; password is prompted, never stored in code)
$env:DB_PATH = "tracker.db"
python manage.py create-admin
python app.py
```
Production-style: `gunicorn -w 2 -b 0.0.0.0:8000 app:app` (Linux/Render/Docker; Gunicorn does not run on native Windows).

## Tests
```powershell
python -m pytest -q          # 81 tests
pip-audit -r requirements.txt
```

## Existing project -> migration
Startup runs idempotent, additive migrations; nothing is dropped or reset. Before the first upgrade of an existing DB a copy `tracker.db.bak-<timestamp>` is written. Legacy rows keep their IDs and timestamps and gain assets, fingerprints, SLA deadlines. Deliberate semantic corrections:
* legacy **Fixed -> "Fixed - Pending Verification"** (never auto-verified)
* legacy **Accepted Risk -> Reopened + exception "Re-review required"** (no justification/approver/expiry was recorded)
* legacy Nmap port-guess scores are labelled **"Heuristic estimate (not CVSS)"** and excluded from scoring.
Legacy endpoints still work (`GET /api/findings` array, `POST /api/upload`, `PATCH /api/findings/<id>`, `GET /api/export.csv`) but now require login.

## Roles
| Role | Can |
|---|---|
| Admin | everything, users, weights/SLA policy, KEV import, bulk delete (typed confirmation) |
| Security Analyst | import scans, triage/assign, verify fixes, approve exceptions (not their own), edit assets/relationships, exports |
| Remediation Owner | update **assigned** findings to In Progress / Fixed-Pending Verification, notes, request exceptions |
| Read-only Auditor | read everything incl. audit logs, exports |

## Verified remediation model
A manual fix only reaches *Fixed - Pending Verification*. It becomes *Verified Resolved* when (a) a **later Complete scan of the same scanner family that covered the asset** no longer shows it, or (b) an analyst *other than the person who marked it fixed* records evidence. Partial/failed scans and different scanners never close findings. A finding detected again is **Reopened**. Risk acceptance requires an approved, expiring exception and is never counted as a fix.
CSV exports only list hosts that had findings; use the upload form's "extra hosts covered" so a clean host can be verified.

## Configuration (environment variables)
See `.env.example`. Key: `DB_PATH`, `SECRET_KEY` (required in production), `VULNTRACK_ENV=production`, `INITIAL_ADMIN_USERNAME/PASSWORD` (one-time bootstrap), `MAX_UPLOAD_MB`, `SESSION_HOURS`, `VULNTRACK_DEMO`.

## Deploy on Render (steps; **not yet tested on Render by the author**)
1. Push to GitHub (`.gitignore` excludes DBs/secrets). 2. New **Web Service**, Environment *Docker* (uses the Dockerfile) or Python with start command `gunicorn -w 2 -b 0.0.0.0:$PORT app:app`.
3. Add a **Persistent Disk** (paid plan) mounted at `/data`; set `DB_PATH=/data/tracker.db`. Without a disk, SQLite resets on each deploy.
4. Env vars: `VULNTRACK_ENV=production`, `SECRET_KEY=<64 hex chars>`, `INITIAL_ADMIN_USERNAME`, `INITIAL_ADMIN_PASSWORD` (>=12 chars). Deploy, sign in, then **delete `INITIAL_ADMIN_PASSWORD`**.
5. Health check path: `/health`. Keep one instance (SQLite is single-writer; in-memory rate limits are per worker).
**Backup:** `python manage.py backup /data/backups/tracker-$(date +%F).db` (Render Shell; consistent online backup). **Restore:** stop traffic, `python manage.py restore <file>` (integrity-checked; old DB kept as `.pre-restore`).

## Demo vs production
Demo: synthetic fixtures in `samples/demo/`, `VULNTRACK_DEMO=1`, DEMO DATA badge, random printed passwords. Production needs: `VULNTRACK_ENV=production`, strong `SECRET_KEY`, HTTPS (Render provides), persistent disk, backups, admin bootstrap removed, audit events exported externally.

## Repeatable interview demo (5-7 min)
1. `seed-demo`, sign in as **analyst**. Overview: metrics are computed from SQLite; click the severity donut to drill in.
2. Vulnerabilities -> open the vsftpd finding -> **Risk** tab: score, factors, *missing evidence*, next action. Note CVSS source vs internal priority, and the "est. 7.5 not CVSS" rows.
3. Assets -> set an asset Internet-facing (must cite a source) and Critical; return to the finding: confidence rises.
4. Scan History: scan #3 is **Partial** (closed nothing); scan #4 is Complete (3 verified by re-scan; the "fixed" Samba finding was **Reopened**). Open **Time Machine** compare.
5. Sign in as **owner1**: mark a finding fixed -> still "pending verification"; try to verify -> refused.
6. Risk Exceptions: approve the pending one as analyst (self-approval is blocked); the expiring one needs re-review.
7. Attack Path Explorer: observed vs manual vs inferred edges; path labelled *Unverified hypothesis*.
8. Reports (CSV/PDF) and Audit Logs (admin/auditor), **Verify hash chain**.

## Feature checklist
**Implemented:** redesigned SOC UI + 3D cards/animated background; Overview with real metrics, charts, queue, empty/error/loading states; explainable risk engine (+docs/SCORING.md); findings table (search/sort/pagination/filters) + detail drawer; asset explorer + audited edits; attack-path graph (observed/manual/inferred); scan runs, comparison, partial-scan safety, recurring/reopened; 7-state remediation workflow with verification; SLA policies + remediation queue; risk exceptions with expiry/re-review; RBAC (4 roles), scrypt hashing, CSRF, lockout, rate limits, security headers; hash-chained append-only audit; 7 CSV+PDF reports with formula-injection protection; migrations with backup; `/health`, Gunicorn, Dockerfile; 81 automated tests.
**Partially implemented:** attack paths use only manual/observed edges (no network-topology import); Remediation "board" is view-only (changes via the finding drawer); KEV import is manual (no live feeds); CVE metadata = lookup links only (no NVD fetch); PDF reports are tabular; rate limiting is per worker; dark mode not implemented.
**Not implemented:** Render deployment verification; external SIEM/WORM audit export; MFA/SSO; EPSS or predictive modelling; Postgres; Docker image build was not run in the author's sandbox.

## Known limitations / production hardening
SQLite audit log is tamper-*evident*, not immutable. Single-instance only. Owners can *read* all findings (write access is restricted). CSP allows inline *styles* (scripts are strict). Add MFA/SSO, centralised logging, secrets manager, periodic dependency audits, and a pen-test before any real use.
