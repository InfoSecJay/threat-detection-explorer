# Threat Detection Explorer

A web application for ingesting, normalizing, and exploring detection rules from multiple security content repositories. Enables cross-vendor comparison and coverage analysis.

## Features

- **Multi-Vendor Support**: Ingest rules from SigmaHQ, Elastic Detection Rules, Splunk Security Content, Sublime Rules, Elastic Protections, and LOLRMM
- **Normalization**: Convert vendor-specific formats to a unified schema
- **Search & Filter**: Full-text search with filters by source, severity, status, MITRE tactics/techniques
- **Cross-Vendor Comparison**: Compare detection coverage by technique or keyword
- **Coverage Gap Analysis**: Identify techniques covered by one vendor but not another
- **Export**: Download filtered results as JSON or CSV

## Quick Start

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

## Architecture

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

## Prerequisites

- Python 3.11+
- Node.js 18+
- Git

## Usage

### 1. Sync Repositories

On first use, sync the detection rule repositories:

1. Go to the Dashboard
2. Click "Sync" for each repository (SigmaHQ, Elastic, Splunk, etc.)
3. Wait for the clone/pull to complete

### 2. Ingest Rules

After syncing, ingest the rules into the database:

1. Click "Ingest" for each synced repository
2. Wait for parsing and normalization to complete

### 3. Explore Detections

- **Browse**: Go to Detections page to search and filter rules
- **Compare**: Use the Compare page to see coverage across vendors
- **Export**: Download filtered results as JSON or CSV

## API Endpoints

### Health
- `GET /api/health` - Health check

### Repositories
- `GET /api/repositories` - List all repositories
- `POST /api/repositories/{name}/sync` - Sync a repository
- `POST /api/repositories/{name}/ingest` - Ingest rules from repository

### Detections
- `GET /api/detections` - List detections with filters
- `GET /api/detections/{id}` - Get detection details
- `GET /api/detections/statistics` - Get statistics

### Compare
- `GET /api/compare?technique=T1059` - Compare by MITRE technique
- `GET /api/compare?keyword=powershell` - Compare by keyword
- `GET /api/compare/coverage-gap?base_source=sigma&compare_source=elastic` - Find coverage gaps

### Export
- `POST /api/export` - Export detections as JSON or CSV

## Normalized Schema

Each detection is normalized to:

```json
{
  "id": "uuid",
  "source": "sigma | elastic | splunk | sublime | elastic_protections | lolrmm",
  "title": "Detection title",
  "description": "Detection description",
  "author": "Author name",
  "status": "stable | experimental | deprecated | unknown",
  "severity": "low | medium | high | critical | unknown",
  "log_sources": ["windows", "linux", ...],
  "data_sources": ["sysmon", "security_event", ...],
  "mitre_tactics": ["TA0002", ...],
  "mitre_techniques": ["T1059", "T1059.001", ...],
  "detection_logic": "Human-readable detection logic",
  "tags": ["tag1", "tag2", ...],
  "false_positives": ["Known false positive scenarios", ...],
  "references": ["https://...", ...],
  "source_file": "path/to/rule.yml",
  "source_repo_url": "https://github.com/...",
  "rule_created_date": "2024-01-15",
  "rule_modified_date": "2024-06-20"
}
```

## Running Tests

```bash
cd backend
pytest tests/ -v
```

## Configuration

Environment variables (can be set in `.env`):

- `DEBUG` - Enable debug mode (default: false)
- `DATABASE_URL` - SQLite database URL (default: sqlite+aiosqlite:///./data/threat_detection.db)
- `CORS_ORIGINS` - Allowed CORS origins (default: http://localhost:5173,http://localhost:3000)

## Supported Repositories

| Repository | Format | URL |
|------------|--------|-----|
| SigmaHQ | YAML | https://github.com/SigmaHQ/sigma |
| Elastic Detection Rules | TOML | https://github.com/elastic/detection-rules |
| Splunk Security Content | YAML | https://github.com/splunk/security_content |
| Sublime Rules | YAML | https://github.com/sublime-security/sublime-rules |
| Elastic Protections | TOML | https://github.com/elastic/protections-artifacts |
| LOLRMM | YAML | https://github.com/magicsword-io/LOLRMM |

## License

MIT
