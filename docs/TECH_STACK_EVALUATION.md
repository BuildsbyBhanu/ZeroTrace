# ZeroTrace — Technology Stack Evaluation

## 1. Evaluation Criteria

Each technology is assessed against these factors:
- **Windows compatibility** — Works natively on Windows 10/11
- **Existing installation** — Already present in the environment
- **Community & maintenance** — Active development, good docs
- **Learning curve** — Team familiarity and onboarding cost
- **Scalability** — Path to production SaaS
- **Licensing** — Permissive vs. copyleft concerns

---

## 2. Backend Framework

### Candidates

| Option | Pros | Cons | Recommendation |
|--------|------|------|----------------|
| **FastAPI** ✅ | Async-native, auto-docs, already installed, excellent performance | Newer ecosystem than Flask | **SELECTED** |
| Django | Batteries-included, admin panel, ORM | Heavyweight, synchronous-by-default | Rejected — overkill for this scope |
| Flask | Simple, mature | No built-in async, more manual setup | Rejected — FastAPI supersedes for this use case |

**Decision: FastAPI + Uvicorn**  
Already installed (`fastapi==0.162.0`, `uvicorn==0.54.0`). Async-first design aligns perfectly with concurrent scanning workloads. Auto-generates OpenAPI docs at `/docs`.

---

## 3. Frontend Approach

### Candidates

| Option | Pros | Cons | Recommendation |
|--------|------|------|----------------|
| **HTMX + Tailwind** ✅ | Lightweight, no build step, works with FastAPI templates | Less interactive than SPAs | **SELECTED for Phase 1** |
| React + Vite | Rich interactivity, large ecosystem | npm blocked, build complexity | Deferred to Phase 2 |
| Next.js | SSR, routing, best-in-class DX | npm execution policy issue, heavier | Deferred to Phase 2 |
| Streamlit | Fast prototyping | Not production-grade UI, limited customization | Rejected — inappropriate for security product |

**Decision: HTMX + Jinja2 Templates + Tailwind CSS**  
No build step required. Server-rendered pages with AJAX enhancements via HTMX. Renders directly from FastAPI templates. For Phase 1, this avoids the npm execution policy problem entirely while delivering a modern, responsive UI. React/Next.js backend can swap in cleanly later since the API is already RESTful.

---

## 4. Database

### Candidates

| Option | Pros | Cons | Recommendation |
|--------|------|------|----------------|
| **SQLite** ✅ | Zero config, file-based, SQLAlchemy supported | Limited concurrent writes | **SELECTED for Phase 1** |
| PostgreSQL | Production-grade, concurrent, robust | Requires installation | Phase 3+ |
| MySQL 8.0 | Running locally, familiar | Overhead for single-user local dev | Rejected — SQLite sufficient for now |

**Decision: SQLite with SQLAlchemy + Alembic**  
`SQLAlchemy==2.0.48` and `alembic==1.18.4` are already installed. Zero infrastructure setup. Migrates cleanly to PostgreSQL when needed — SQLAlchemy abstracts the dialect. SQLite WAL mode provides adequate concurrency for a single-user desktop application.

---

## 5. CLI Framework

### Candidates

| Option | Pros | Cons | Recommendation |
|--------|------|------|----------------|
| **Typer** ✅ | Modern, auto-help, already installed | Smaller ecosystem than Click | **SELECTED** |
| Click | Mature, widely used | Verbose boilerplate | Rejected — Typer is cleaner |
| argparse | Built-in, no dependency | Primitive, poor DX | Rejected |

**Decision: Typer**  
Already installed (`typer==0.24.1`). Produces clean help text and integrates naturally with Python functions. Can share models directly with the FastAPI backend.

---

## 6. HTTP Client

### Candidates

| Option | Pros | Cons | Recommendation |
|--------|------|------|----------------|
| **HTTPX** ✅ | Async/sync, modern API, supports both | Larger footprint than requests | **SELECTED** |
| Requests | Simpler API, synchronous | No native async | Rejected — sync blocks scanning |
| aiohttp | True async, performant | Different API style | Secondary (already installed) |

**Decision: HTTPX as primary, aiohttp as fallback**  
`httpx==0.28.1` already installed. Native async/await support, seamless sync fallback, excellent timeout and redirect control. Essential for SSRF prevention and controlled request behavior.

---

## 7. PDF Generation

### Candidates

| Option | Pros | Cons | Recommendation |
|--------|------|------|----------------|
| **PyMuPDF (fitz)** ✅ | Pythonic, fast, creates PDFs from scratch | GPL/Commercial dual license | **SELECTED** |
| ReportLab | Mature, pure Python | Steeper learning curve | Alternative |
| WeasyPrint | HTML→PDF, good CSS support | Requires system dependencies | Rejected — too complex |

**Decision: PyMuPDF for programmatic PDFs, Jinja2→HTML for styled reports**  
`pymupdf==1.28.2` already installed. Used for generating structured PDF reports with proper fonts, tables, and layout. HTML reports use Jinja2 templates rendered to string then optionally converted.

---

## 8. Background Task Processing

### Options

| Option | Approach | Recommendation |
|--------|----------|----------------|
| **In-process asyncio tasks** ✅ | Run scans as async background tasks within Uvicorn | **SELECTED for Phase 1** |
| Celery + Redis | Distributed task queue | Phase 3+ |
| ARQ | Async Redis queue | Phase 3+ |

**Decision: asyncio + asyncio.Task**  
For a single-user local tool, a dedicated task queue is over-engineering. `asyncio.create_task()` spawns scans concurrently within the same process. Clean, no extra dependencies.

---

## 9. Testing

| Tool | Purpose | Status |
|------|---------|--------|
| pytest | Unit and integration tests | To install |
| httpx (test client) | API endpoint testing | Already installed |
| coverage | Code coverage reporting | To install |
| factory-boy | Test data fixtures | To install |

---

## 10. Security Libraries

| Library | Purpose | Status |
|---------|---------|--------|
| cryptography | Credential encryption (Fernet) | **Must install** |
| python-dotenv | Environment configuration | Already installed |
| pydantic-settings | Typed settings management | Already installed (pydantic-settings) |

---

## 11. Final Stack Summary

| Layer | Technology | Installed? |
|-------|-----------|------------|
| Backend API | FastAPI + Uvicorn | ✅ |
| Frontend | HTMX + Jinja2 + Tailwind | ⚠️ Tailwind via CDN |
| Database | SQLite + SQLAlchemy + Alembic | ✅ (SQLite only) |
| CLI | Typer | ✅ |
| HTTP Client | HTTPX | ✅ |
| PDF Generation | PyMuPDF | ✅ |
| Task Management | asyncio | ✅ |
| Testing | pytest | ❌ Must install |
| Encryption | cryptography | ❌ Must install |
| Logging | Python stdlib + structlog optional | ✅ stdlib |

**Total new installs needed:** pytest, cryptography, ruff (linting), python-multipart (form parsing — verify), pillow (image handling for evidence)

---

## 12. npm Execution Policy Issue — Resolution

The PowerShell execution policy blocks `.ps1` scripts. Resolution options:

1. **Set user-scoped policy:** `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` — allows local scripts, signed remote scripts
2. **Use node directly:** Invoke npm JavaScript files directly: `node "C:\Program Files\nodejs\node_modules\npm\bin\npm-cli.js" ...`
3. **Skip npm:** Use HTMX + vanilla JS frontend — no npm build needed

**Recommendation:** Set `RemoteSigned` policy (Option 1). This is a one-time admin action that unlocks the entire Node.js ecosystem for future frontend upgrades.
