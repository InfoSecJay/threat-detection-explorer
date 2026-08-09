# Detection Explorer

![Python](https://img.shields.io/badge/python-3.11+-blue)
![TypeScript](https://img.shields.io/badge/typescript-React-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Deployment](https://img.shields.io/badge/deployed-Vercel-black)

**Explore, compare, and track open-source detection rules across multiple security vendors — in one place.**

🌐 **Live Site: [detectionexplorer.io](https://detectionexplorer.io)**

<img width="1911" height="908" alt="image" src="https://github.com/user-attachments/assets/1fae0424-e2fa-4ced-a456-d04682ff37e2" />

---

Detection Explorer ingests and normalizes detection rules from 11 major open-source security content repositories into a unified schema, enabling cross-vendor comparison, MITRE ATT&CK coverage analysis, and coverage gap identification.

### Why?

Detection engineers work across multiple rule formats daily — Sigma YAML, Elastic TOML, Splunk YAML — each with different schemas, severity levels, and metadata structures. Detection Explorer normalizes all of them into a single searchable interface so you can:

- **Search & filter** across 11 vendors with full-text search, severity, status, and MITRE tactic/technique filters
- **Compare coverage** across vendors for any MITRE technique or keyword
- **Identify gaps** — find techniques covered by one vendor but missing from another
- **Stay current** — sync and re-ingest to pull the latest rules from each repo
- **Export** filtered results as JSON or CSV for downstream use

### Supported Sources

| Repository | Format |
|---|---|
| [SigmaHQ](https://github.com/SigmaHQ/sigma) | YAML |
| [Elastic Detection Rules](https://github.com/elastic/detection-rules) | TOML |
| [Elastic Hunting Queries](https://github.com/elastic/detection-rules/tree/main/hunting) | TOML |
| [Elastic Protections](https://github.com/elastic/protections-artifacts) | TOML |
| [Splunk Security Content](https://github.com/splunk/security_content) | YAML |
| [Sublime Rules](https://github.com/sublime-security/sublime-rules) | YAML |
| [LOLRMM](https://github.com/magicsword-io/LOLRMM) | YAML |
| [Microsoft Sentinel](https://github.com/Azure/Azure-Sentinel) | YAML |
| [Google SecOps](https://github.com/chronicle/detection-rules/tree/main/rules/community) | YARA-L |
| [Okta customer-detections](https://github.com/okta/customer-detections) | YAML (OIE / SPL) |
| [Auth0 customer-detections](https://github.com/auth0/auth0-customer-detections) | YAML (Sigma + SPL) |

---

## API

Detection Explorer ships a public, read-only REST API. The same backend the
frontend uses is reachable from your scripts, CI, or other tools.

**Base URL:** `https://threat-detection-explorer-production.up.railway.app/api`

**Interactive docs:** [Swagger UI](https://threat-detection-explorer-production.up.railway.app/docs)
— complete endpoint inventory, schemas, and a try-it-now console.
Raw OpenAPI spec at [`/openapi.json`](https://threat-detection-explorer-production.up.railway.app/openapi.json).

No authentication required.

### Quick examples

```bash
# List the first 25 Sigma rules tagged with T1059
curl "https://threat-detection-explorer-production.up.railway.app/api/detections?sources=sigma&mitre_techniques=T1059&limit=25"

# Corpus statistics (rule count per source, severity, status)
curl "https://threat-detection-explorer-production.up.railway.app/api/detections/statistics"

# Coverage for a MITRE technique across all 11 sources
curl "https://threat-detection-explorer-production.up.railway.app/api/compare?technique=T1059.001"

# All available filter facets (platforms, data sources, event types) with counts
curl "https://threat-detection-explorer-production.up.railway.app/api/detections/filters"
```

### Notes for consumers

- **Read-only intent.** A handful of write endpoints exist
  (`POST /api/repositories/{name}/sync`, `POST /api/scheduler/trigger`, etc.)
  but they're for the project's own sync infrastructure. They're not
  rate-limited yet; please don't queue floods.
- **Browser CORS** is allow-listed to `detectionexplorer.io`. Server-side
  callers (scripts, MCP servers, backend integrations) aren't affected.
- **Best-effort availability.** Hosted on Railway Pro; nightly sync at
  02:00 UTC. No SLA.

---

## Roadmap

Priorities and to-dos live in [GitHub Issues](https://github.com/InfoSecJay/threat-detection-explorer/issues), labeled by:

- **Priority**: [`priority:now`](https://github.com/InfoSecJay/threat-detection-explorer/labels/priority%3Anow) · [`priority:next`](https://github.com/InfoSecJay/threat-detection-explorer/labels/priority%3Anext) · [`priority:later`](https://github.com/InfoSecJay/threat-detection-explorer/labels/priority%3Alater)
- **Area**: [`area:backend`](https://github.com/InfoSecJay/threat-detection-explorer/labels/area%3Abackend) · [`area:frontend`](https://github.com/InfoSecJay/threat-detection-explorer/labels/area%3Afrontend) · [`area:infra`](https://github.com/InfoSecJay/threat-detection-explorer/labels/area%3Ainfra)
- **Type**: [`type:umbrella`](https://github.com/InfoSecJay/threat-detection-explorer/labels/type%3Aumbrella) (multi-week arcs with sub-task checklists) · [`type:tech-debt`](https://github.com/InfoSecJay/threat-detection-explorer/labels/type%3Atech-debt)

Recently-shipped history: `git log`.

Reference material (schema, taxonomy audits, design docs) stays in [`docs/`](docs/).

---

## Development

> Everything below is for running Detection Explorer locally.

### Quick Start

```bash
# Clone the repository
git clone git@github.com:InfoSecJay/threat-detection-explorer.git
cd threat-detection-explorer

# Backend setup
cd backend
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # macOS/Linux
pip install -r requirements.txt

# Frontend setup (in a new terminal)
cd frontend
npm install

# Run (in separate terminals)
# Terminal 1 - Backend:
cd backend && python run.py

# Terminal 2 - Frontend:
cd frontend && npm run dev
```

The frontend will be available at `http://localhost:5173` and the API at `http://localhost:8000`.

### Prerequisites

- Python 3.11+
- Node.js 18+
- Git

### Architecture

```
threat_detection_explorer/
├── backend/          # FastAPI Python backend
│   ├── app/
│   │   ├── api/      # REST API routes
│   │   ├── models/   # SQLAlchemy database models
│   │   ├── parsers/  # Vendor-specific rule parsers
│   │   ├── normalizers/  # Rule normalization logic
│   │   └── services/ # Business logic services
│   └── tests/        # Pytest test suite
├── frontend/         # React TypeScript frontend
│   └── src/
│       ├── components/
│       ├── pages/
│       ├── hooks/
│       └── services/
└── data/            # Runtime data (git-ignored)
    ├── repos/       # Cloned repositories
    └── threat_detection.db  # SQLite database
```

### Usage

#### 1. Sync Repositories

On first use, sync the detection rule repositories:

1. Go to the Dashboard
2. Click "Sync" for each repository (SigmaHQ, Elastic, Splunk, etc.)
3. Wait for the clone/pull to complete

#### 2. Ingest Rules

After syncing, ingest the rules into the database:

1. Click "Ingest" for each synced repository
2. Wait for parsing and normalization to complete

#### 3. Explore Detections

- **Browse**: Go to Detections page to search and filter rules
- **Compare**: Use the Compare page to see coverage across vendors
- **Export**: Download filtered results as JSON or CSV

### API Endpoints

When the backend is running locally, the full endpoint inventory and
try-it-now console are at [`http://localhost:8000/docs`](http://localhost:8000/docs)
(FastAPI auto-generated Swagger UI). For the live hosted API, see the
[API section](#api) at the top of this README.

### Normalized Schema

Every rule from every source ends up looking the same — ~40 canonical
fields covering identity, status/severity, the canonical
platform/data-source/event-type taxonomy, MITRE mapping, and observables
extracted from the detection logic itself.

**Full reference: [`docs/schema.md`](./docs/schema.md)** — field-by-field
table, per-source vendor → canonical mapping, and a worked round-trip
example.

For depth on how the canonical taxonomy resolver works per vendor, see
[`docs/taxonomy.md`](./docs/taxonomy.md).

### Running Tests

```bash
cd backend
pytest tests/ -v
```

### Configuration

Environment variables (can be set in `.env`):

- `DEBUG` - Enable debug mode (default: false)
- `DATABASE_URL` - SQLite database URL (default: sqlite+aiosqlite:///./data/threat_detection.db)
- `CORS_ORIGINS` - Allowed CORS origins (default: http://localhost:5173,http://localhost:3000)

## License

MIT
