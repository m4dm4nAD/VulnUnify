# VulnUnify

A lightweight platform that **unifies vulnerability, cloud-posture, and SAST findings**
from many security tools into one normalized model — so a Tenable host vuln, a Wiz
cloud misconfig, and a Semgrep code finding are all queryable the same way.

VulnUnify does **no scanning of its own**. It pulls from tools that expose an API,
a PowerShell command, or an MCP server, normalizes what comes back, and serves it
through one API + dashboard.

## Architecture

```
                 ┌─────────── connectors ───────────┐
  Tenable  ─REST─┤                                   │
  Rapid7   ─REST─┤   each maps its native data into  │     ┌──────────┐     ┌───────────┐
  Wiz   ─GraphQL─┤   a single NormalizedFinding      ├──▶  │  ingest  │──▶  │ Postgres  │
  Defender ─PWSH─┤   (dedup via fingerprint)         │     │ (upsert) │     │  findings │
  Semgrep  ─REST─┤                                   │     └──────────┘     │  assets   │
  …             ─┤                                   │                      └─────┬─────┘
                 └───────────────────────────────────┘                            │
                                                                       FastAPI + dashboard
```

- **Normalized model** (`backend/app/connectors/base.py`) — `NormalizedFinding` /
  `NormalizedAsset`. Every connector produces these; nothing downstream cares which
  tool it came from. Severities are mapped onto one scale in `normalize/severity.py`.
- **Connectors** (`backend/app/connectors/`) — subclass `BaseConnector`, implement
  `is_configured()` + `fetch()`, and register in `registry.py`. Three integration
  modalities are demonstrated:
  - **REST/GraphQL** — `tenable.py` (full reference), `semgrep.py` (full reference)
  - **PowerShell subprocess** — `defender.py` (full reference; runs `pwsh` + `Az`)
  - **MCP** — any tool with an MCP server is just another `BaseConnector` whose
    `fetch()` calls the MCP tool and maps the result.
- **Ingestion** (`services/ingest.py`) — upserts assets + findings by natural key,
  so repeated syncs never duplicate. Records every run in `connector_runs`.
- **API + dashboard** (`api/`, `frontend/index.html`) — filterable findings, per-
  connector status, and one-click sync.

## Connector status

| Connector            | Category        | Modality   | Status      |
|----------------------|-----------------|------------|-------------|
| Tenable.io           | vulnerability   | REST       | ✅ reference |
| Rapid7 InsightVM     | vulnerability   | REST       | ✅ reference |
| Wiz                  | cloud_posture   | GraphQL    | ✅ reference |
| Defender for Cloud   | cloud_posture   | PowerShell | ✅ reference |
| Semgrep              | sast            | REST       | ✅ reference |
| SonarQube            | sast            | REST       | ✅ reference |
| Trend Vision One     | cloud_posture   | REST       | ✅ reference |
| Aikido               | sast/sca/secret | REST       | ✅ reference |
| OSV.dev              | sca/supply_chain| REST       | ✅ reference |
| Snyk                 | container       | REST       | ✅ reference |

All ten connectors are implemented. Each is verified against representative API
response shapes (normalization + ingest), but not yet against a live tenant — add
credentials in `.env` and run `POST /api/sync/{name}` for the first real pull.
OSV needs no credentials (public API). Aikido picks its category per issue
(`sast`/`sca`/`secret`/`iac`/`cloud`); the others use a fixed category.

## Run it

```bash
cp .env.example .env        # then edit it (see below)
docker compose up --build   # runs migrations, starts Postgres + API
```

Before the first run, set in `.env`:

- **`INITIAL_ADMIN_PASSWORD`** — the password for the `admin` account created on first
  startup, so you can log in. If you leave it blank, a random one is generated and
  printed once in the logs: `docker compose logs api | grep seeded_admin`.
- **Connector credentials** — only for the tools you use; blank ones are skipped. You
  can start with none and still explore the (empty) dashboard.

Then open the dashboard and **log in as `admin`**:

- Dashboard: http://localhost:8000 (the API serves the static `frontend/` at `/`)
- API docs (OpenAPI): http://localhost:8000/docs

A connector with no credentials is reported as **unconfigured** and skipped — so you
can start with just one tool (or none) and add the rest later.

> **Picking up code changes.** The image bakes in `backend/` and `frontend/` (no
> source bind-mount / live reload in the container), so after editing either, rebuild:
> `docker compose up -d --build`. For live reload while iterating, run the API
> outside Docker instead — see [Local dev (without Docker)](#local-dev-without-docker).

### Scheduled syncing

Set `SYNC_INTERVAL_MINUTES` in `.env` to run every configured connector on a timer
(e.g. `360` = every 6 hours; `0` disables it, leaving sync manual-only). The
threaded APScheduler job runs `sync_all` in its own DB session and never overlaps
itself. Check it at `GET /api/sync/schedule`:

```bash
curl -b cookies.txt http://localhost:8000/api/sync/schedule
# {"enabled": true, "interval_minutes": 360, "running": true, "next_run_at": "..."}
```

### Notifications

Point `NOTIFY_SLACK_WEBHOOK_URL` at a Slack-compatible incoming webhook (or set it
from the Connectors & Settings page — stored encrypted) and each scheduler tick
posts one digest covering, per finding at most once each:

- **high risk** — open findings with risk score ≥ `NOTIFY_RISK_THRESHOLD` (default 80)
- **KEV** — open findings matching a CISA known-exploited CVE
- **SLA breach** — open findings past their SLA deadline

`POST /api/notifications/test` verifies the webhook; `POST /api/notifications/run`
evaluates the rules immediately instead of waiting for the next sync.

### Posture trends

The Overview page (security roles) charts posture history: open findings and
KEV/SLA exposure over time come from hourly-throttled snapshots written on each
scheduler tick and at startup (`posture_snapshots` — history accrues from the
first snapshot; manual `POST /api/sync` deliberately doesn't snapshot, since new
findings aren't KEV/risk-scored until intel refresh runs), while new-vs-resolved
velocity and mean-time-to-remediate are computed retroactively from finding
timestamps, so they have history immediately. MTTR counts only genuinely
resolved findings (not false-positive/accepted-risk triage) and measures from
the latest reopen when a finding came back. `GET /api/posture/trends?days=90`
serves the series; `POST /api/posture/snapshot` takes one on demand.

### Trigger a sync

The API requires an authenticated session, so log in once and reuse the cookie:

```bash
# log in (uses INITIAL_ADMIN_PASSWORD from your .env)
curl -c cookies.txt -X POST http://localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<your admin password>"}'

curl -b cookies.txt -X POST http://localhost:8000/api/sync         # all configured connectors
curl -b cookies.txt -X POST http://localhost:8000/api/sync/tenable # just one
curl -b cookies.txt "http://localhost:8000/api/findings?severity=critical"
curl -b cookies.txt http://localhost:8000/api/stats
```

## Adding a connector

1. Create `backend/app/connectors/<tool>.py`, subclass `BaseConnector`.
2. Implement `is_configured()` (reads its keys from `config.py`) and `fetch()`
   (returns `list[NormalizedFinding]`).
3. Add its credentials to `config.py` + `.env.example`.
4. Register the class in `registry.py`.

No other code changes — ingestion, API, and the dashboard pick it up automatically.

## Local dev (without Docker)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
# point DATABASE_URL at a local Postgres, then:
alembic upgrade head
uvicorn backend.app.main:app --reload
```
