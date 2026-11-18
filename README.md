# AI-SIEM — Real-time Security Information & Event Management

A lightweight, functional SIEM: it ingests security logs in real time, runs a
rule-based detection engine, raises deduplicated alerts, and provides
**advisory** AI triage (True/False positive suggestions) that an analyst
confirms. Built for a 16 GB Windows 11 host with Docker Desktop.

> **Safety by design:** the AI never *confirms* a verdict. It only suggests
> ("Likely True/False Positive" / "Needs Investigation"); the final
> classification is always set by a human analyst, and every analyst action is
> written to an audit log.

---

## Architecture

```
 Collectors / Simulator          Backend (FastAPI)                 Frontend
 ──────────────────────          ─────────────────────             ────────
 Windows Event Log  ─┐           ┌───────────────┐   WebSocket     React + TS
 Simulated events   ─┼─ HTTP ──▶ │ Ingest API    │ ───────────────▶ SOC dash
 Syslog/Firewall/…  ─┘           │ Detection eng │                 (nginx)
                                 │ AI triage     │                   :8080
                                 │ Auth (JWT/RBAC)│
                                 └──────┬────────┘
                                        │ async SQLAlchemy
                                   ┌────▼────┐
                                   │ Postgres│  (durable events, alerts, audit)
                                   └─────────┘
```

| Layer     | Tech                                             |
|-----------|--------------------------------------------------|
| Backend   | Python 3.12, FastAPI, SQLAlchemy 2 (async), JWT  |
| Database  | PostgreSQL 16                                    |
| Frontend  | React 18 + TypeScript, Vite, Recharts, nginx     |
| Realtime  | WebSocket (`/ws`)                                |
| Deploy    | Docker Compose (3 light services, mem-capped)    |

---

## Quick start (Windows PowerShell)

```powershell
cd C:\Users\ayoube\Downloads\siem-platform

# 1. Create your secrets file and edit the passwords
Copy-Item .env.example .env
notepad .env        # set strong POSTGRES_PASSWORD, SECRET_KEY, FIRST_ADMIN_PASSWORD
                    #  (keep DATABASE_URL's password in sync with POSTGRES_PASSWORD)

# 2. Build & start everything
docker compose up -d --build

# 3. Check health
docker compose ps
curl http://localhost:8000/api/health

# 4. Open the dashboard
Start-Process http://localhost:8080
#   sign in with FIRST_ADMIN_USERNAME / FIRST_ADMIN_PASSWORD from .env
```

Generate a strong secret key:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

---

## See alerts appear in real time

With the stack running, generate realistic attacks and watch the dashboard
light up (Dashboard → *Live alerts* / *Live event stream*):

```powershell
cd backend
python tools\simulate_events.py --scenario all
# or a single scenario:
python tools\simulate_events.py --scenario bruteforce
python tools\simulate_events.py --scenario takeover
# continuous traffic:
python tools\simulate_events.py --scenario all --loop 0 --interval 5
```

Scenarios: `bruteforce`, `spray`, `takeover`, `portscan`, `powershell`,
`sensitive`, `normal`, `all`.

---

## Forward real Windows events

Run the lightweight collector in an **elevated** PowerShell (to read the
Security log). It needs only a standard Python 3 install — no extra packages:

```powershell
cd backend
python collector\windows_collector.py --api http://localhost:8000 `
    --user admin --password <your-admin-password> --interval 15
```

It forwards logon success/failure (4624/4625), privilege use (4672) and process
creation (4688) events, which feed the brute-force, privilege-escalation and
suspicious-process rules.

---

## Detection rules

| ID   | Rule                                   | Severity | Trigger (configurable in `.env`)              |
|------|----------------------------------------|----------|-----------------------------------------------|
| R001 | Brute-force login                      | High     | ≥5 failed logins / IP in 5 min                |
| R002 | Password spray (multiple accounts)     | High     | failures across ≥5 accounts / IP              |
| R003 | Successful login after brute-force     | Critical | success following ≥5 failures from same IP    |
| R004 | Privilege escalation                   | High     | sudo/runas/4672/special privileges            |
| R005 | Suspicious PowerShell execution        | High     | `-enc`, `DownloadString`, `IEX`, hidden, …    |
| R006 | Port scanning                          | Medium   | ≥15 distinct dest ports / IP in 2 min         |
| R007 | Unusual network activity               | Medium   | abnormal connection volume / IP               |
| R008 | Sensitive resource access              | High/Med | access to shadow/SAM/ntds.dit/credentials/…   |

Alerts carry severity, risk score (0-100), source/dest, timestamps, evidence,
and are **deduplicated** by a per-rule key (repeat hits increment `event_count`
instead of spawning new alerts).

---

## AI triage

* Default provider is `heuristic` — fully **offline**, deterministic, no API key.
* To use an LLM, set in `.env`: `AI_PROVIDER=anthropic` (or `openai`),
  `AI_API_KEY=...`, optional `AI_MODEL=...`. On any failure it falls back to the
  heuristic engine — the SIEM never stops working without AI.
* Every suggestion includes confidence, explanation, supporting evidence,
  investigation steps, response actions, and a disclaimer. Re-run per alert from
  the alert detail page.

---

## Tests

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest                      # runs against throwaway SQLite — no Postgres needed
```

Covers ingestion, every detection rule, duplicate-alert prevention, AI triage
(advisory-only invariants), authentication/RBAC, real-time broadcast, and
persistence. **26 tests.**

---

## API surface (selected)

| Method | Path                         | Role     | Purpose                         |
|--------|------------------------------|----------|---------------------------------|
| POST   | `/api/auth/login`            | —        | Obtain JWT                      |
| POST   | `/api/events` `/events/batch`| analyst  | Ingest events (runs detection)  |
| GET    | `/api/events`                | viewer+  | Search/filter events            |
| GET    | `/api/alerts`                | viewer+  | List/filter alerts              |
| PATCH  | `/api/alerts/{id}`           | analyst  | Set status / confirm verdict    |
| POST   | `/api/alerts/{id}/triage`    | analyst  | Re-run AI triage                |
| GET    | `/api/stats/*`               | viewer+  | Dashboard metrics               |
| WS     | `/ws?token=<jwt>`            | any user | Real-time event/alert stream    |

Interactive docs: http://localhost:8000/docs

---

## Managing the stack

```powershell
docker compose logs -f backend      # tail backend logs
docker compose ps                   # status + health
docker compose down                 # stop (keeps the DB volume)
docker compose down -v              # stop and ERASE the database
```

## Security notes

JWT auth, bcrypt password hashing, role-based access (viewer/analyst/admin),
Pydantic input validation, parameterised queries (no SQL injection), per-route
rate limiting, secrets only via environment, non-root containers, internal-only
database port, and an immutable audit log of analyst actions.
