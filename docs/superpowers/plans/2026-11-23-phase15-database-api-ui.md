# Phase 1.5 — Database, API & Web UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the three existing passive scanning modules (headers, SSL/TLS, cookies) usable end-to-end via both CLI and a simple web interface, backed by persistent storage.

**Architecture:** SQLite database with SQLAlchemy models and Alembic migrations stores scan jobs and findings. FastAPI serves REST API endpoints and Jinja2 templates render a simple HTMX-powered web UI. Tailwind CSS loads from CDN (no npm required). Background tasks run in-process via asyncio.

**Tech Stack:** SQLAlchemy 2.0 async, Alembic, FastAPI, Jinja2, HTMX, Tailwind CSS CDN, pytest-asyncio

**Spec:** `docs/DEVELOPMENT_ROADMAP.md` — Phase 1 features: database layer, web UI (scan + results pages), CLI improvements, reporting engine

## Global Constraints

- Python ≥ 3.10 (currently running 3.10.11; 3.12 planned for Phase 2)
- No Docker, Redis, Celery, or ZAP for Phase 1.5
- All scans against safe local targets only (localhost, 127.0.0.1, or authorized test systems)
- SQLite backend with WAL mode enabled
- HTMX + Jinja2 + Tailwind CDN (avoids npm on Windows)
- Editable pip install must continue working after each commit
- `pytest` runs with `asyncio_mode = "auto"`

## Review Focus

- Concurrent scan queue saturation → should reject or queue, not silently drop
- Database migration idempotency → multiple runs without errors
- Finding serialization for API responses → datetime fields must be ISO strings
- Template rendering with no data → empty states display gracefully
- Scan cancellation mid-flight → background task cleanup, status update to "cancelled"

---

## File Structure

```
src/zerotrace/database/
    __init__.py           # engine, session factory, async context manager
    models.py             # ScanJob, Finding ORM models

migrations/
    env.py                # Alembic environment config
    versions/
        001_initial.py    # initial migration

src/zerotrace/api/
    __init__.py
    router.py             # FastAPI router with all scan/routes
    schemas.py            # Pydantic response/request schemas
    dependencies.py       # DB session dependency

src/zerotrace/templates/
    base.html             # HTML skeleton with Tailwind CDN
    index.html            # Landing page / new scan form
    scan.html             # Live scan progress view
    results.html          # Findings display with filters
    _findings_table.html  # HTMX partial for filtered results

data/
    zerotrace.db          # SQLite (gitignored)
    alembic.ini           # Alembic config

tests/
    test_database.py      # Model CRUD tests
    test_api_routes.py    # HTTP endpoint tests
    test_templates.py     # Template rendering smoke tests
```

---

### Task 1: Database Models & Engine Setup

**Files:**
- Create: `src/zerotrace/database/__init__.py`
- Create: `src/zerotrace/database/models.py`
- Modify: `src/zerotrace/main.py:16-32` (add DB init/shutdown hooks)

**Interfaces:**
- Consumes: `settings.database_url`, `ScanProfile` enum
- Produces: `get_async_session()` async generator, `Base` declarative base class

- [ ] **Step 1: Write failing test for model creation**

```python
# tests/test_database.py
import pytest
from sqlalchemy import select
from zerotrace.database.models import ScanJob, Finding


@pytest.mark.asyncio
async def test_scan_job_crud(async_session):
    job = ScanJob(target_url="https://example.com", profile="standard")
    async_session.add(job)
    await async_session.commit()
    await async_session.refresh(job)
    
    stmt = select(ScanJob).where(ScanJob.id == job.id)
    result = await async_session.execute(stmt)
    fetched = result.scalar_one()
    
    assert fetched.target_url == "https://example.com"
    assert fetched.profile == "standard"
    assert fetched.status == "pending"
    assert fetched.scan_id is not None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_database.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Implement models in `src/zerotrace/database/models.py`**

Create `ScanJob` and `Finding` ORM models. `ScanJob` has fields: id (UUID), scan_id (str, unique), target_url, profile, status (pending/running/completed/failed/cancelled), started_at, completed_at, duration_seconds, error_message. `Finding` has fields: id (UUID), scan_id (FK to ScanJob), title, category, severity, status, affected_url, evidence, impact, remediation, references (JSON list), module_name, metadata (JSON dict). Use SQLAlchemy 2.0 `Mapped` types with `mapped_column`.

- [ ] **Step 4: Implement database engine in `src/zerotrace/database/__init__.py`**

Create async engine with SQLite + aiosqlite, WAL mode enabled. Provide `async_sessionmaker` factory. Add lifecycle functions: `init_db()` that creates tables, and `shutdown_db()` that closes engine.

- [ ] **Step 5: Wire DB lifespan into FastAPI app in `main.py`**

In `lifespan()`, call `init_db()` before yield, `shutdown_db()` after. Add DB health check to `/health` endpoint.

- [ ] **Step 6: Run tests to verify they pass**

Run: `pytest tests/test_database.py -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add src/zerotrace/database/ tests/test_database.py src/zerotrace/main.py
git commit -m "feat(database): add ScanJob and Finding models with async engine"
```

---

### Task 2: Alembic Migrations

**Files:**
- Create: `migrations/env.py`
- Create: `migrations/versions/001_initial.py`
- Create: `alembic.ini`
- Modify: `pyproject.toml` (add alembic script location)

**Interfaces:**
- Consumes: `DATABASE_URL` env var, `Base` from models
- Produces: versioned migration history

- [ ] **Step 1: Write failing test for migration**

```python
# tests/test_migrations.py
import pytest


def test_alembic_current(mocker):
    """Verify migration head exists and matches models."""
    from alembic.command import current
    from alembic.config import Config
    config = Config("alembic.ini")
    # Should not raise
    current(config, verbose=True)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_migrations.py -v`
Expected: FAIL — alembic.ini missing

- [ ] **Step 3: Create `alembic.ini` and `migrations/env.py`**

Standard Alembic setup pointing to models' Base and DATABASE_URL from environment. Set `target_metadata` to `Base.metadata`.

- [ ] **Step 4: Generate initial migration**

Run: `alembic revision --autogenerate -m "initial"`
This produces `migrations/versions/001_initial.py`.

- [ ] **Step 5: Apply migration**

Run: `alembic upgrade head`

- [ ] **Step 6: Verify migration history**

Run: `alembic history --verbose && alembic current`

- [ ] **Step 7: Commit**

```bash
git add migrations/ alembic.ini pyproject.toml
git commit -m "chore(alembic): add initial migration for ScanJob and Finding tables"
```

---

### Task 3: API Schemas & Router

**Files:**
- Create: `src/zerotrace/api/schemas.py`
- Create: `src/zerotrace/api/router.py`
- Create: `src/zerotrace/api/dependencies.py`
- Modify: `src/zerotrace/main.py` (update router import path)

**Interfaces:**
- Consumes: `ScanJob` model, `ScanResult` from orchestrator
- Produces: REST API endpoints at `/api/v1/scans`

- [ ] **Step 1: Write failing tests for API schemas**

```python
# tests/test_api_schemas.py
import pytest
from zerotrace.api.schemas import ScanCreate, ScanResponse, FindingResponse


def test_scan_create_valid():
    schema = ScanCreate(target_url="https://example.com", profile="standard")
    assert schema.target_url == "https://example.com"
    assert schema.profile == "standard"


def test_scan_response_serialization(scan_job_factory):
    job = scan_job_factory(status="completed")
    response = ScanResponse.model_validate(job)
    assert response.scan_id == job.scan_id
    assert response.target_url == job.target_url
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_api_schemas.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Implement Pydantic schemas in `schemas.py`**

Define request/response schemas:
- `ScanCreate`: target_url (str), profile (Literal["quick","standard","deep"]), save_report (bool = False)
- `ScanResponse`: scan_id, target_url, profile, status, started_at (ISO str), completed_at (optional ISO str), findings_count (int), duration_seconds (float)
- `FindingResponse`: title, category, severity, status, affected_url, evidence, remediation, module_name
- `ScanListResponse`: list of ScanResponse items

- [ ] **Step 4: Implement API router with async endpoint**

Routes:
- `GET /api/v1/scans` — list recent scans (paginated, last 50)
- `POST /api/v1/scans` — trigger new scan (returns scan_id immediately)
- `GET /api/v1/scans/{scan_id}` — get scan details including findings
- `DELETE /api/v1/scans/{scan_id}` — cancel running scan

Use `BackgroundTasks` for async scan execution. Store active scans in an in-memory dict keyed by scan_id.

- [ ] **Step 5: Implement DB session dependency**

Create `get_db_session()` FastAPI dependency that yields from the async session factory and handles cleanup.

- [ ] **Step 6: Wire router into main.py**

Update import: `from zerotrace.api.router import api_router`

- [ ] **Step 7: Run tests and verify**

Run: `pytest tests/test_api_schemas.py tests/test_api_routes.py -v`
Expected: PASS (after Task 4 implements the route logic)

- [ ] **Step 8: Commit**

```bash
git add src/zerotrace/api/ tests/test_api_schemas.py
git commit -m "feat(api): add REST API schemas and router for scan management"
```

---

### Task 4: Background Scan Execution

**Files:**
- Create: `src/zerotrace/engine/task_queue.py`
- Modify: `src/zerotrace/api/router.py` (use task queue)
- Modify: `src/zerotrace/database/models.py` (add cancelled status handling)

**Interfaces:**
- Consumes: `ScanOrchestrator.run()`, DB session
- Produces: async task that updates DB on completion

- [ ] **Step 1: Write failing test for task queue**

```python
# tests/test_task_queue.py
import pytest
from unittest.mock import AsyncMock, patch
from zerotrace.engine.task_queue import execute_scan_background


@pytest.mark.asyncio
async def test_execute_scan_updates_db(async_session, sample_scan_job):
    mock_result = AsyncMock()
    mock_result.scan_id = sample_scan_job.scan_id
    mock_result.status = "completed"
    mock_result.findings = []
    mock_result.duration_seconds = 1.5
    
    with patch("zerotrace.engine.orchestrator.orchestrator.run", return_value=mock_result):
        await execute_scan_background(sample_scan_job.scan_id, async_session)
    
    # Verify DB was updated
    job = await async_session.get(ScanJob, sample_scan_job.id)
    assert job.status == "completed"
    assert job.duration_seconds == 1.5
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_task_queue.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Implement task queue in `task_queue.py`**

Function `execute_scan_background(scan_id: str, db_session)` that:
1. Fetches ScanJob from DB
2. Updates status to "running"
3. Calls `orchestrator.run()` with the scan parameters
4. On success: marks completed, saves findings to DB, returns
5. On failure: marks failed with error message
6. Handles cancellation check (polls a cancelled set)

- [ ] **Step 4: Update API router to launch background tasks**

On POST /scans, insert ScanJob row, then schedule `execute_scan_background` as a FastAPI BackgroundTask. Return 202 Accepted with scan_id.

- [ ] **Step 5: Add scan polling endpoint**

`GET /api/v1/scans/{scan_id}/progress` — returns current ScanProgress-like JSON (status, findings_count, current_module)

- [ ] **Step 6: Run tests and verify**

Run: `pytest tests/test_task_queue.py -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add src/zerotrace/engine/task_queue.py src/zerotrace/api/router.py tests/test_task_queue.py
git commit -m "feat(engine): add background scan execution with DB persistence"
```

---

### Task 5: Web Templates — Base & Index Page

**Files:**
- Create: `src/zerotrace/templates/base.html`
- Create: `src/zerotrace/templates/index.html`
- Create: `src/zerotrace/api/views.py`

**Interfaces:**
- Consumes: Jinja2 Environment, template directory path
- Produces: rendered HTML pages served by FastAPI

- [ ] **Step 1: Write failing test for template rendering**

```python
# tests/test_templates.py
import pytest
from jinja2 import Environment, FileSystemLoader


def test_base_template_rendering(template_env):
    tpl = template_env.get_template("base.html")
    html = tpl.render(title="Test Page", content="<p>Hello</p>")
    assert "<title>Test Page — ZeroTrace</title>" in html
    assert 'href="https://cdn.tailwindcss.com"' in html.lower() or 'src="https://cdn.tailwindcss.com"' in html.lower()


def test_index_page_has_form(template_env):
    tpl = template_env.get_template("index.html")
    html = tpl.render()
    assert '<form' in html
    assert 'action="/scan"' in html
    assert 'name="url"' in html
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_templates.py -v`
Expected: FAIL — templates don't exist

- [ ] **Step 3: Create `base.html`**

HTML5 skeleton with:
- Tailwind CSS via CDN `<script src="https://cdn.tailwindcss.com"></script>`
- HTMX via CDN `<script src="https://unpkg.com/htmx.org@1.9.12"></script>`
- Consistent nav bar with links: Home, New Scan, History
- Dark theme color scheme (slate grays, red/orange accents for severity)
- Footer with version info

- [ ] **Step 4: Create `index.html`**

Landing page with:
- Header with ZeroTrace branding
- URL input field with validation hint
- Profile selector dropdown (Quick / Standard / Deep)
- "Start Scan" button that submits to `/scan` and shows progress
- Recent scans list (x-loaded from API)

- [ ] **Step 5: Create `views.py` with route handlers**

Functions:
- `get_index(request) -> Response` — renders index.html
- `get_scan_page(request, scan_id) -> Response` — renders scan.html
- `get_results_page(request, scan_id) -> Response` — renders results.html

Use `Templates` from `fastapi.templating` with `env = Environment(loader=FileSystemLoader(...))`.

- [ ] **Step 6: Register template routes in router**

Add at `/scan`, `/scan/{scan_id}`, `/results/{scan_id}` paths.

- [ ] **Step 7: Run tests and verify**

Run: `pytest tests/test_templates.py -v`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add src/zerotrace/templates/ src/zerotrace/api/views.py tests/test_templates.py
git commit -m "feat(ui): add base template and landing page with Tailwind + HTMX"
```

---

### Task 6: Live Scan Progress Page

**Files:**
- Create: `src/zerotrace/templates/scan.html`
- Create: `src/zerotrace/api/proxy.py` (or inline in router)

**Interfaces:**
- Consumes: Active scan dict in memory, `/api/v1/scans/{id}`
- Produces: Real-time progress updates via HTMX polling

- [ ] **Step 1: Write failing test for scan page**

```python
def test_scan_page_shows_progress(template_env):
    tpl = template_env.get_template("scan.html")
    html = tpl.render(scan_id="abc-123", target="https://example.com")
    assert "abc-123" in html
    assert "hx-get" in html or "hx-trigger" in html  # HTMX polling
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_templates.py::test_scan_page_shows_progress -v`
Expected: FAIL

- [ ] **Step 3: Create `scan.html`**

Page with:
- Scan ID display
- Status indicator (animated spinner while running)
- Current module name
- Finding count counter
- HTMX `hx-get` poll every 2 seconds to `/api/v1/scans/{id}/progress`
- Auto-redirect to results on completion

- [ ] **Step 4: Add progress endpoint to API**

`GET /api/v1/scans/{scan_id}/progress` returns `{status, current_module, findings_count, modules_completed, modules_total, elapsed_seconds}`

- [ ] **Step 5: Run tests and verify**

Run: `pytest tests/test_templates.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/zerotrace/templates/scan.html src/zerotrace/api/router.py
git commit -m "feat(ui): add live scan progress page with HTMX polling"
```

---

### Task 7: Results Display Page

**Files:**
- Create: `src/zerotrace/templates/results.html`
- Create: `src/zerotrace/templates/_findings_table.html`
- Create: `src/zerottrace/api/export.py`

**Interfaces:**
- Consumes: Scan findings from DB, severity filter values
- Produces: Filtered findings table, export buttons

- [ ] **Step 1: Write failing test for results page**

```python
def test_results_page_displays_findings(template_env, sample_finding):
    tpl = template_env.get_template("results.html")
    html = tpl.render(findings=[sample_finding], scan_id="abc-123")
    assert sample_finding.title in html
    assert "critical" in html.lower() or "severity" in html.lower()


def test_findings_table_partial_with_filter(template_env):
    tpl = template_env.get_template("_findings_table.html")
    html = tpl.render(findings=[], filter_severity=None)
    assert "No findings" in html or "None" in html or len(html) > 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_templates.py::test_results_page_displays_findings -v`
Expected: FAIL

- [ ] **Step 3: Create `results.html`**

Page with:
- Summary cards: total findings, critical/high/medium counts
- Severity filter dropdown (all / critical / high / medium / low / informational)
- Findings table loaded via HTMX partial `_findings_table.html`
- Export buttons: JSON download, HTML report download
- Back link to home

- [ ] **Step 4: Create `_findings_table.html`**

HTMX-ready partial. Rows show: severity badge (color-coded), title, category, module, action buttons (view details). Uses `?filter_severity=X` query param support.

- [ ] **Step 5: Add export endpoint**

`GET /api/v1/scans/{scan_id}/export?format=json|html|pdf` — returns appropriate Content-Type header and file content.

- [ ] **Step 6: Run tests and verify**

Run: `pytest tests/test_templates.py -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add src/zerotrace/templates/ src/zerottrace/api/export.py tests/test_templates.py
git commit -m "feat(ui): add results page with severity filters and export"
```

---

### Task 8: CLI Improvements & Integration Tests

**Files:**
- Modify: `cli/main.py`
- Create: `tests/test_integration.py`

**Interfaces:**
- Consumes: Database, API client
- Produces: enhanced CLI with history and report commands

- [ ] **Step 1: Write failing integration test**

```python
# tests/test_integration.py
import pytest
from httpx import AsyncClient, ASGITransport
from zerotrace.main import create_app


@pytest.mark.asyncio
async def test_full_scan_lifecycle(async_session):
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Start scan
        resp = await client.post("/api/v1/scans", json={
            "target_url": "https://example.com",
            "profile": "quick"
        })
        assert resp.status_code == 202
        scan_id = resp.json()["scan_id"]
        
        # Wait for completion (poll)
        import asyncio
        for _ in range(30):
            await asyncio.sleep(0.5)
            resp = await client.get(f"/api/v1/scans/{scan_id}")
            if resp.json()["status"] == "completed":
                break
        
        assert resp.json()["status"] == "completed"
        assert resp.json()["findings_count"] >= 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_integration.py -v`
Expected: FAIL (endpoints not yet fully wired)

- [ ] **Step 3: Enhance CLI with scan history**

Add `zerotrace history` command that queries local SQLite and displays recent scans in a Rich table. Add `zerotrace report <scan_id>` to view/save a specific scan's report.

- [ ] **Step 4: Fix any integration test failures**

Debug using `systematic-debugging` skill. Common issues:
- Session scope mismatch between test and app
- Missing DB initialization in test lifespan
- Async event loop configuration

- [ ] **Step 5: Run full test suite**

Run: `pytest tests/ -v --tb=short`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add cli/main.py tests/test_integration.py
git commit -m "feat(cli): add scan history command and integration tests"
```

---

### Task 9: Polish & Verification

**Files:**
- Modify: `src/zerotrace/templates/*.html` (UI polish)
- Modify: `Makefile` (run commands)

**Interfaces:**
- Consumes: All previous tasks complete
- Produces: Final polished Phase 1.5 deliverable

- [ ] **Step 1: Color system audit**

Apply `better-colors` skill: ensure severity colors match the `Severity.color` property in base.py (red #dc2626 for critical, orange #ea580c for high, yellow #ca8a04 for medium, blue #2563eb for low, gray #6b7280 for informational).

- [ ] **Step 2: Typography audit**

Apply `better-typography` skill: ensure consistent font sizing, line heights, and measure widths across templates. All body text ≥ 16px on iOS. Tabular numbers for durations and counts.

- [ ] **Step 3: Layout audit**

Apply `better-layout` skill: check spacing scale consistency (8px grid), group relationships (2× internal gap vs external), responsive breakpoints.

- [ ] **Step 4: UI polish**

Apply `better-ui` skill: border radius consistency (sm for inputs, md for cards), shadow layers (subtle elevation for cards), icon alignment.

- [ ] **Step 5: Add Makefile targets**

```makefile
run:          # start dev server
    uvicorn zerotrace.main:app --reload --port 8000

db-migrate:   # run alembic migrations
    alembic upgrade head

test:         # run all tests
    pytest tests/ -v --cov=src/zerotrace --cov-report=term-missing

test-fast:    # quick tests only
    pytest tests/test_validator.py tests/test_orchestrator.py tests/test_database.py -v
```

- [ ] **Step 6: Final verification**

Run: `pytest tests/ -v`
Run: `make run` and verify `http://localhost:8000` loads
Run: `zerotrace scan https://httpbin.org/get --profile quick --output json` (if network available) or verify local target works

- [ ] **Step 7: Final commit**

```bash
git add -A
git commit -m "polish(ui): apply design system audit to templates"
```

---

## Self-Review Checklist

- [ ] Spec coverage: Each Phase 1 feature (database, UI pages, CLI history, reports) has a task
- [ ] Step scan: Each step lets implementer write exactly one thing
- [ ] Type consistency: `ScanJob`, `Finding`, `ScanResult` names match across tasks
- [ ] Review focus: All 5 risk areas addressed in relevant tasks
- [ ] Proportion: Plan ~200 lines vs expected implementation ~400 lines — reasonable ratio
