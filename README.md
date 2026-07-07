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

All eight connectors are implemented. Each is verified against representative API
response shapes (normalization + ingest), but not yet against a live tenant — add
credentials in `.env` and run `POST /api/sync/{name}` for the first real pull.
Aikido picks its category per issue (`sast`/`sca`/`secret`/`iac`/`cloud`); the
others use a fixed category.

## Run it

```bash
cp .env.example .env        # fill in credentials for the tools you use
docker compose up --build   # runs migrations, starts Postgres + API
```

- Dashboard: http://localhost:8000 (the API serves the static `frontend/` at `/`)
- API docs (OpenAPI): http://localhost:8000/docs

A connector with no credentials is reported as **unconfigured** and skipped — so you
can start with just one tool and add the rest later.

> **Picking up code changes.** The image bakes in `backend/` and `frontend/` (no
> source bind-mount / live reload in the container), so after editing either, rebuild:
> `docker compose up -d --build`. For live reload while iterating, run the API
> outside Docker instead — see [Local dev (without Docker)](#local-dev-without-docker).
> (A host bind-mount can't be used when the project path contains a `:`, which Docker
> rejects in volume specs.)

### Scheduled syncing

Set `SYNC_INTERVAL_MINUTES` in `.env` to run every configured connector on a timer
(e.g. `360` = every 6 hours; `0` disables it, leaving sync manual-only). The
threaded APScheduler job runs `sync_all` in its own DB session and never overlaps
itself. Check it at `GET /api/sync/schedule`:

```bash
curl http://localhost:8000/api/sync/schedule
# {"enabled": true, "interval_minutes": 360, "running": true, "next_run_at": "..."}
```

### Trigger a sync

```bash
curl -X POST http://localhost:8000/api/sync            # all configured connectors
curl -X POST http://localhost:8000/api/sync/tenable    # just one
curl http://localhost:8000/api/findings?severity=critical
curl http://localhost:8000/api/stats
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
