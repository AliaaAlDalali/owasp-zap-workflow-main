# Himaak (حِماك) Platform API

The backend of the Himaak SaaS. Organizations add their sites, prove they own them, run OWASP ZAP baseline scans, and read findings with Himaak's release decision. Each scan is compared with the previous one.

Built to the ASAAS backend standard:
- FastAPI, with modules split into router, schemas, service and repository.
- SQLite through `aiosqlite`, with ordered migrations.
- Errors are returned as `{"message": ...}`.

## Run

Run from the **repository root**, so the shared `himaak_core` package (ZAP parsing and release policy) is importable:

```bash
pip install -r backend/requirements.txt
cp backend/.env.example backend/.env    # set COOKIE_SECURE=false for local http
python -m uvicorn main:app --app-dir backend --port 8000
```

API docs: `http://localhost:8000/docs`. The database is created at `backend/data/app.db` on first start.

Scans need **Docker** on the server. The worker runs `ghcr.io/zaproxy/zaproxy:stable` per scan. Without Docker, scans fail with a clear message.

## Layout

```text
backend/
├── main.py           app, lifespan (database + scan worker), error handlers, routers
├── config.py         settings from environment / backend/.env
├── database.py       connections, query helpers, transactions
├── migrations/       ordered schema changes (PRAGMA user_version)
├── utils/
│   ├── errors.py     business errors → HTTP status in main.py
│   └── network.py    URL normalisation and public-address checks (used by targets and scans)
└── modules/
    ├── auth/           register, login, logout, me (HttpOnly session cookie)
    ├── organizations/  organizations, members, roles (owner / member)
    ├── targets/        sites and ownership verification (DNS TXT or file)
    ├── scans/          queue, worker, ZAP runner (runner.py), results ingestion
    └── findings/       findings, details, comparison between scans
```

`scans/runner.py` is the one file beyond the standard four. It keeps Docker process handling (limits, timeout, cleanup) separate from the scan workflow.

## API

All routes except `/auth/*` and `/health` need the session cookie. Organization routes return 404 to non-members.

| Method | Path | Purpose |
|---|---|---|
| POST | `/auth/register` | Create a user and their first organization (owner), sign in |
| POST | `/auth/login` · `/auth/logout` | Sign in / out |
| GET | `/auth/me` | Current user |
| GET, POST | `/organizations` | My organizations / create one |
| GET, POST | `/organizations/{id}/members` | List members / add an existing user (owner only) |
| GET, POST | `/organizations/{id}/targets` | List / add sites |
| GET, DELETE | `/organizations/{id}/targets/{tid}` | Site details with verification instructions / delete (owner only) |
| POST | `/organizations/{id}/targets/{tid}/verify` | Check the DNS record or file |
| POST | `/organizations/{id}/targets/{tid}/scans` | Queue a baseline scan (site must be verified) |
| GET | `/organizations/{id}/scans` · `/scans/{sid}` | Scan list (optional `target_id`) / one scan |
| GET | `/organizations/{id}/scans/{sid}/findings` | Findings, highest risk first (optional `risk_code`) |
| GET | `/organizations/{id}/scans/{sid}/findings/{fid}` | Finding details and instances |
| GET | `/organizations/{id}/scans/{sid}/compare` | New / fixed / persisting vs the previous scan (or `base_scan_id`) |

## Security decisions

- **No scan without proof of ownership.** The site must show one of these:
  - a TXT record `_himaak-verify.<host>` = `himaak-verify=<token>`, or
  - the same token in `/.well-known/himaak-verify.txt`.
- **No internal targets.**
  - URLs must be http(s), and must not contain credentials or internal names.
  - Every resolved address must be public. This is checked when the site is added, when a scan is queued, and again just before it runs.
  - The ownership file is fetched from the resolved IP itself (SNI kept), with no redirects. This prevents DNS rebinding during verification.
- **ZAP containers** run with memory, CPU and process limits, `no-new-privileges` and a timeout. Arguments are passed as a list (no shell). Each container is removed after its scan.
- **The checked address is pinned inside the ZAP container** (`--add-host`), so the site's domain cannot be re-pointed at an internal address between the check and the scan. Other hosts the site links to or redirects to are still resolved by ZAP, so in production the scan host's firewall must also block outbound traffic from containers to private ranges and the cloud metadata address. See "Before production".
- **Scan data is plain text.** The HTML in ZAP reports is converted to text by `himaak_core` before it is stored, so the front end never has to render scanner HTML.
- **Passwords and sessions:**
  - Passwords are hashed with `scrypt`.
  - Sessions are random tokens; only their SHA-256 is stored.
  - Cookies are `HttpOnly` and `SameSite=Lax`, plus `Secure` in production.
  - Sign-in locks for 15 minutes after 5 failures per email. Wrong emails and wrong passwords take the same time to answer.
- The database enforces **at most one queued or running scan per site**.

## Verified

Checked by running the server and sending real HTTP requests (45 checks, all passing):
- registration, validation messages, duplicate email, wrong password, lockout, logout
- organization isolation: a non-member gets 404, and a member cannot delete sites or add members
- rejection of internal targets: `127.0.0.1`, `localhost`, `169.254.169.254`, `ftp:`, credentials in the URL, single-label hosts
- real DNS and file verification attempts
- scan before verification, duplicate active scan
- the worker picking up a scan and failing it with a clear message when Docker is missing
- storing real ZAP JSON (score 52, blocked); findings list, filter and details; plain-text storage of injected HTML
- comparison: new, fixed and persisting findings

**Real ZAP runs** (Docker 29 in WSL Ubuntu, ZAP 2.17.0, against Google's public scanner test bed `public-firing-range.appspot.com`):
- scans complete in about two minutes: 30 alert types, 110 locations, score 0, blocked
- the container runs with the memory and CPU limits and the pinned address, and is removed with its work folder afterwards
- an unreachable site fails the scan with a clear message
- a second scan of the same site compares as 30 still open, 0 new, 0 fixed (stable fingerprints)
- all 30 alert types get Arabic titles (matched by ZAP plugin ID, see `himaak_core/knowledge.py`)

The API ran in a `python:3.12-slim` container with the host's Docker socket mounted. The scan work folder must be the same path inside and outside that container, because ZAP containers are started by the host's Docker.

## Before production

- Host firewall rules: block outbound traffic from scan containers to RFC 1918 ranges, link-local and metadata addresses.
- HTTPS in front of the API with `COOKIE_SECURE=true`, and `CORS_ORIGINS` set to the front-end origin.
- Back up `backend/data/app.db`. SQLite fits a single API instance; move to PostgreSQL only if several API instances must write at once.
- A full security review (the `security-review` skill) before the first customer.
