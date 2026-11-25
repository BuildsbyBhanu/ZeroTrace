# ZeroTrace — Development Roadmap

## 1. Overview

Development is divided into four phases. Each phase delivers working, testable functionality. Phase 1 is the minimum viable product (MVP). Phases 2–4 add capability progressively.

---

## 2. Phase 1 — Core MVP (Estimated: 4–6 Weeks)

### Goal
A functional local security assessment tool with web UI and CLI, supporting Quick and Standard scan profiles.

### Features

| Feature | Description | Deliverable |
|---------|-------------|-------------|
| Project scaffold | Repository structure, CI config stub, linting setup | `K:\ZeroTrace` initialized |
| Database layer | SQLAlchemy models, Alembic migrations, SQLite backend | `database/` module complete |
| URL validator | SSRF prevention, IP blocking, normalization | `engine/validation.py` |
| Passive modules | Security headers, SSL/TLS, cookie analysis, server info | 6+ detection modules |
| Engine core | Async orchestrator, progress tracking, result aggregation | `engine/orchestrator.py` |
| CLI (`zerotrace scan`) | Profile selection, output format, credential input | `cli/main.py` |
| Web UI — scan page | URL input, profile selector, progress display | Templates + HTMX routes |
| Web UI — results page | Finding list, severity filter, detail view | Dashboard template |
| Reporting engine | HTML, PDF, JSON export | `reporting/engine.py` |
| Scan profiles | Quick and Standard implemented | Two working profiles |
| Auth support (basic) | Form-based login credential handling | Stored encrypted, used in scans |
| Test suite | Unit tests for engine modules, validation logic | >70% coverage on engine |
| Documentation | README, setup guide, usage docs | Project docs |

### Dependencies
- FastAPI, Uvicorn, HTTPX, SQLAlchemy, Alembic, Typer, PyMuPDF, Jinja2, HTMX, Tailwind CSS, pytest, cryptography

### Acceptance Criteria
- [ ] `zerotrace scan http://localhost:8080 --profile quick` produces findings (local targets only)
- [ ] Web UI loads at `http://localhost:8000` and accepts URLs
- [ ] Scanning private IPs is blocked with a clear error
- [ ] Reports download correctly in all three formats
- [ ] No credentials appear in any log output
- [ ] All engine unit tests pass

---

## 3. Phase 2 — Enhanced Coverage (Estimated: 3–4 Weeks)

### Goal
Expand vulnerability detection breadth and improve the user experience.

### Features

| Feature | Description | Deliverable |
|---------|-------------|-------------|
| Deep scan profile | Authenticated session testing, deeper endpoint enumeration | New scan profile |
| Custom scan builder | Module-level granularity, selective enabling/disabling | Custom profile UI |
| Nuclei integration | Subprocess bridge to Nuclei engine, template-based detection | `engine/integrations/nuclei.py` |
| OWASP Top 10 mapping | Findings mapped to all 10 categories with descriptions | Complete category coverage |
| Findings deduplication | Smart dedupe across modules and requests | Cleaner results |
| Progress dashboard | Real-time WebSocket progress, module status indicators | Live progress UI |
| Target management | Save/favorite/target history, batch operations | `targets` CRUD |
| Improved PDF reports | Professional layout, executive summary section | Styled PDF output |
| Error recovery | Resume interrupted scans, partial result preservation | Robustness improvements |

### Dependencies
- Nuclei binary (downloaded at runtime or bundled), WebSocket support

### Acceptance Criteria
- [ ] Deep scan completes within 15 minutes for standard sites
- [ ] Custom scan with only selected modules runs correctly
- [ ] Nuclei findings merge cleanly with native findings
- [ ] Scan can resume after interruption without data loss

---

## 4. Phase 3 — Production Readiness (Estimated: 3–4 Weeks)

### Goal
Prepare ZeroTrace for deployment beyond localhost.

### Features

| Feature | Description | Deliverable |
|---------|-------------|-------------|
| PostgreSQL migration | Switch DB dialect, run migration, verify parity | `DATABASE_URL=postgres://...` works |
| Configuration system | `.env` based settings, CLI override, GUI settings panel | Centralized config |
| Health check endpoint | `/health` returning service status | Production-ready API |
| Structured logging | JSON log format, log rotation, structured fields | Production logging |
| Docker support | Multi-stage Dockerfile, docker-compose for dev | Container deployment |
| REST API documentation | Auto-generated OpenAPI, example requests | `/docs` and `/redoc` |
| Authentication (local) | PIN protection for single-user mode | Local access control |
| Performance hardening | Connection pooling, query optimization, memory profiling | Benchmarks < 5s startup |
| Vulnerability DB | Local vulnerability knowledge base, version tracking | `data/vuln_db.json` |

### Acceptance Criteria
- [ ] Application starts in under 5 seconds
- [ ] Docker Compose brings up the complete stack
- [ ] PostgreSQL backend functions identically to SQLite
- [ ] API responds to health checks within 100ms

---

## 5. Phase 4 — SaaS Preparation (Estimated: 6–8 Weeks)

### Goal
Architectural changes enabling multi-tenant cloud deployment.

### Features

| Feature | Description | Deliverable |
|---------|-------------|-------------|
| Multi-tenancy | Isolated data per organization, scoped API keys | Tenant-aware DB queries |
| JWT authentication | Token-based auth, role-based access control | Auth middleware |
| Redis integration | Session storage, WebSocket broadcast, rate limiting | Redis-backed services |
| Subscription billing | Stripe integration (planned), trial periods | Payment flow |
| API security module | OpenAPI parser, parameterized endpoint testing | API scanning feature |
| AI-assisted analysis | Vulnerability explanation, prioritization suggestions | Optional AI module |
| Team features | Shared reports, comments, collaboration | Group functionality |
| Public deployment | Vercel/Render/AWS deployment, CDN, monitoring | Production infrastructure |

### Acceptance Criteria
- [ ] Two tenants can run scans simultaneously without data leakage
- [ ] API key authentication restricts access appropriately
- [ ] Scan queue handles concurrent jobs via Redis
- [ ] Application monitors (uptime, latency, error rate) operational

---

## 6. Dependency Graph by Phase

```
Phase 1 Dependencies:
  fastapi, uvicorn, httpx, aiohttp, sqlalchemy, alembic,
  typer, jinja2, pymupdf, pydantic, pydantic-settings,
  python-dotenv, rich, pytest, cryptography, httptools

Phase 2 Additions:
  websockets, redis (later phase), nuclei-binary

Phase 3 Additions:
  psycopg2-binary or asyncpg, docker-sdk

Phase 4 Additions:
  stripe, langchain/openai SDK, celery/arq
```

---

## 7. Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| npm execution policy blocks frontend upgrade | Phase 2 React switch delayed | HTMX works without npm; fix policy early |
| Python 3.10 EOL (Oct 2026) | Security patches stop | Upgrade to 3.12 during Phase 2 |
| SQLite write contention under load | Scan stalls | WAL mode enabled; migrate to Postgres in Phase 3 |
| Nuclei GPL license conflict | Commercial SaaS blocker | Isolate in subprocess; option to vendor or replace |
| False positive findings erode trust | User confidence drops | Clear severity labels; "potential" vs "confirmed" distinction enforced |

---

## 8. Milestone Checklist

```
Phase 1 ──────────────────────────────────────────
  █ Project scaffold and directory structure
  █ Database models and migrations  
  █ URL validation and SSRF prevention
  █ Passive scanning modules (headers, SSL, cookies)
  █ Engine orchestrator and progress tracking
  █ CLI implementation
  █ Web UI (scan + results pages)
  █ Report generation (HTML, PDF, JSON)
  █ Test suite and documentation
  ─────────────────────────────────────────────────
Phase 2 ──────────────────────────────────────────
  █ Deep scan profile
  █ Custom scan builder
  █ Nuclei integration
  █ WebSocket live progress
  █ Target management
  ─────────────────────────────────────────────────
Phase 3 ──────────────────────────────────────────
  █ PostgreSQL support
  █ Configuration system
  █ Docker setup
  █ Production hardening
  ─────────────────────────────────────────────────
Phase 4 ──────────────────────────────────────────
  █ Multi-tenancy
  █ JWT auth
  █ API scanning module
  █ SaaS deployment
  ─────────────────────────────────────────────────
```
