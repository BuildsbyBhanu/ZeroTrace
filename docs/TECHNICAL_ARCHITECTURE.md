# ZeroTrace — Technical Architecture Document

## 1. System Architecture Overview

ZeroTrace follows a **modular monolith architecture** optimized for local Windows development with a clear upgrade path to distributed SaaS.

```
┌─────────────────────────────────────────────────────┐
│                    Web Frontend                      │
│              (FastAPI + HTMX / Next.js)             │
└──────────────────┬──────────────────────────────────┘
                   │ HTTP/WebSocket
┌──────────────────▼──────────────────────────────────┐
│                  API Gateway                         │
│            (FastAPI + Uvicorn)                       │
│                                                      │
│  ┌─────────────┐  ┌─────────────┐  ┌────────────┐  │
│  │  Auth       │  │  Validation │  │  Rate      │  │
│  │  Middleware │  │  Middleware │  │  Limiter   │  │
│  └─────────────┘  └─────────────┘  └────────────┘  │
└──────────────────┬──────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────┐
│               Scanning Orchestrator                  │
│         (Async Task Queue / Celery-like)             │
│                                                      │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌────────┐ │
│  │Recon    │  │Headers  │  │SSL/TLS  │  │Vuln    │ │
│  │Module   │  │Module   │  │Module   │  │Modules  │ │
│  └─────────┘  └─────────┘  └─────────┘  └────────┘ │
└──────────────────┬──────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────┐
│              Shared Infrastructure                   │
│  ┌────────────┐  ┌────────────┐  ┌───────────────┐  │
│  │  Database  │  │   Storage   │  │   Audit Log   │  │
│  │ (SQLite/   │  │(Results/    │  │   (JSON file) │  │
│  │  Postgres) │  │ Reports)    │  │               │  │
│  └────────────┘  └────────────┘  └───────────────┘  │
└─────────────────────────────────────────────────────┘
```

---

## 2. Component Architecture

### 2.1 Backend API Layer (`backend/`)

**Technology:** FastAPI + Uvicorn (async-native, already installed)

Responsibilities:
- REST API endpoints for scan control, report retrieval, settings
- WebSocket endpoint for real-time scan progress streaming
- Request validation via Pydantic models
- Authentication middleware (JWT for future multi-user)
- CORS configuration for web frontend

### 2.2 Scanning Engine (`engine/`)

**Technology:** Pure Python — httpx, aiohttp, ssl, urllib.parse

Responsibilities:
- Modular scanner pipeline with pluggable detection modules
- Safe request throttling and concurrency control
- URL normalization, validation, and SSRF prevention
- Authentication session management
- Result aggregation and deduplication

**Module Categories:**
1. **Passive Modules** — Header analysis, response inspection (zero-side-effect)
2. **Active Modules** — Controlled probe requests (user-authorized)
3. **Integration Modules** — Wrap external tools (Nuclei, testssl.sh) when available

### 2.3 Detection Modules (`engine/modules/`)

Each module is a self-contained Python class following a统一interface:

```python
class BaseModule:
    name: str
    severity_base: str  # "info", "low", "medium", "high", "critical"
    
    async def execute(self, context: ScanContext) -> list[Finding]: ...
    
    def should_run(self, profile: str, context: ScanContext) -> bool: ...
```

### 2.4 Reporting Engine (`reporting/`)

**Technology:** Jinja2 (HTML), PyMuPDF/ReportLab (PDF), dict serialization (JSON)

Responsibilities:
- Template rendering for human-readable reports
- Structured data extraction for machine-readable exports
- Branding and styling consistent across formats
- Filtering by severity, category, and status

### 2.5 Database Layer (`database/`)

**Phase 1:** SQLite via SQLAlchemy (file-based, zero config)  
**Phase 2+:** PostgreSQL (production readiness)

Models:
- `Scan` — Scan job metadata and status
- `Finding` — Individual vulnerability findings
- `Target` — Stored target URLs (favorites)
- `Credentials` — Encrypted auth info (never logged)
- `Settings` — User preferences and config

### 2.6 CLI (`cli/`)

**Technology:** Python Typer (already installed)

Provides:
- `scan` command with profile selection
- `config` for persistent settings
- `reports` for result viewing and export
- `targets` for managing saved URLs
- Same engine invocation as web UI (shared codebase)

---

## 3. Data Flow

### Scan Lifecycle

```
User submits URL → Validate & sanitize URL → Create Scan record
  → Dispatch to Orchestrator → Run Reconnaissance
  → Run passive modules (headers, SSL, cookies)
  → Run active modules (vulnerability probes)
  → Aggregate findings → Deduplicate
  → Store results → Notify progress stream
  → Generate report (on-demand or auto)
```

### Progress Streaming

```
Orchestrator ──► WebSocket broadcaster
                    │
                    ▼
              Frontend progress bar
              Module-by-module status updates
              Live finding count
```

---

## 4. Database Schema (High-Level)

```sql
scans (
  id: UUID PK,
  target_url: TEXT,
  profile: ENUM('quick','standard','deep','custom'),
  status: ENUM('pending','running','completed','failed','cancelled'),
  created_at: TIMESTAMP,
  completed_at: TIMESTAMP,
  total_findings: INT,
  auth_config_id: FK
)

findings (
  id: UUID PK,
  scan_id: FK → scans,
  title: TEXT,
  category: TEXT,        -- OWASP A01-A10
  severity: ENUM(...),
  status: ENUM('confirmed','potential','informational','not_detected','manual_required'),
  affected_url: TEXT,
  request: TEXT,         -- sanitized
  evidence: TEXT,
  impact: TEXT,
  remediation: TEXT,
  references: JSON,
  module_name: TEXT
)

credentials (
  id: UUID PK,
  username_encrypted: BLOB,
  password_encrypted: BLOB,
  cookie_header: TEXT,
  token: TEXT,           -- encrypted JWT/session token
  stored_at: TIMESTAMP
)
```

---

## 5. Security Boundaries

```
┌──────────────────────────────────────────────┐
│  EXTERNAL                                     │
│  ┌────────────────────────────────────────┐  │
│  │  INPUT VALIDATION (first line of       │  │
│  │  defense) — URL sanitization,          │  │
│  │  length limits, type checking          │  │
│  └────────────────────────────────────────┘  │
├──────────────────────────────────────────────┤
│  INTERNAL                                      │
│  ┌────────────────────────────────────────┐  │
│  │  SCAN SANDBOX                          │  │
│  │  - Private IP blocking                 │  │
│  │  - SSRF guard (allowlist/denylist)     │  │
│  │  - DNS rebinding detection             │  │
│  │  - Redirect chain limiter (max 5)      │  │
│  │  - Request timeout per module          │  │
│  │  - Global rate limiter                 │  │
│  └────────────────────────────────────────┘  │
├──────────────────────────────────────────────┤
│  DATA LAYER                                    │
│  ┌────────────────────────────────────────┐  │
│  │  CREDENTIAL ENCRYPTION (Fernet)        │  │
│  │  AUDIT LOGGING (immutable journal)     │  │
│  └────────────────────────────────────────┘  │
└──────────────────────────────────────────────┘
```

---

## 6. Communication Patterns

| Pair | Protocol | Reason |
|------|----------|--------|
| Frontend ↔ API | HTTP REST + WebSocket | REST for data, WS for live progress |
| API ↔ Engine | In-process function calls | Tight coupling, shared memory, no RPC overhead |
| Engine ↔ External Tools | subprocess (optional) | ZAP/Nuclei/testssl.sh integration |
| Any ↔ Database | SQLAlchemy async | Type-safe queries, migration support |

---

## 7. Deployment Model

### Phase 1 — Local Development
```
localhost:8000 (FastAPI/Uvicorn)
localhost:3000 (React dev server, optional)
SQLite file: data/zerotrace.db
All assets served from local filesystem
```

### Phase 3 — Production Readiness
- Containerization-ready (Dockerfile defined, runs without container)
- Environment variable configuration
- Structured JSON logging
- Health check endpoint (`/health`)
- Graceful shutdown handling

### Phase 4 — SaaS
- Horizontal scaling via stateless API layer
- Redis for WebSocket broadcast and rate limiting
- Cloud database (PostgreSQL managed)
- CDN for static assets
