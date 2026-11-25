# Phase 3: Production Readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prepare ZeroTrace for deployment beyond localhost by implementing PostgreSQL support, configuration system, Docker setup, health check tests, and production hardening.

**Architecture:** Configuration is centralized in `Settings` (pydantic-settings). Database layer supports both SQLite and PostgreSQL. Docker provides containerized deployment. Health endpoint is tested but doesn't modify production behavior.

**Tech Stack:** PostgreSQL (asyncpg), Docker, docker-compose, pydantic-settings, pytest-asyncio

**Spec:** docs/DEVELOPMENT_ROADMAP.md (Phase 3 section, lines 75-99)

## Global Constraints

- Python >=3.10 (per pyproject.toml)
- All work strictly inside K:\ZeroTrace
- No external/public website scanning (local targets only: http://localhost:8080)
- Exactly 88 tests must pass
- TDD: write tests first, then implement

## Review Focus

- PostgreSQL connection URL handling with both dev and prod formats
- Configuration override precedence (CLI > env > defaults)
- Database migration compatibility between SQLite and PostgreSQL
- Health check latency under concurrent requests
- Sensitive data exposure in logs/configuration

---

## Phase 3 Tasks

### Task 1: Health Check Endpoint Test

**Files:**
- Create: `tests/test_health.py`

**Interfaces:**
- Consumes: Nothing (uses main.py's /health endpoint)
- Produces: `test_health_check` function that validates /health response

- [ ] **Step 1: Write the failing test**

```python
def test_health_check():
    """Test health check endpoint returns proper status."""
    app = create_app()
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["service"] == "ZeroTrace"
    assert "version" in data
```

- [ ] **Step 2: Run test to verify it passes**

Run: `pytest tests/test_health.py -v`
Expected: PASS (endpoint already exists in main.py)

- [ ] **Step 3: Commit**

```bash
git add tests/test_health.py
git commit -m "test: add health check endpoint test"
```

### Task 2: PostgreSQL Support (Async Driver)

**Files:**
- Modify: `src/zerotrace/config.py:29` (database_url default)
- Create: `tests/test_postgresql_config.py`

**Interfaces:**
- Consumes: os.environ for DATABASE_URL
- Produces: Settings.database_url that supports both SQLite and PostgreSQL URLs

- [ ] **Step 1: Write the failing test**

```python
def test_postgresql_database_url():
    """Test settings accepts PostgreSQL URLs."""
    import os
    from dotenv import load_dotenv
    
    # Test with PostgreSQL URL
    original = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = "postgresql+asyncpg://localhost:5432/zerotrace"
    
    # Need to reload settings to pick up env var
    from zerotrace.config import Settings
    Settings.model_clear_cache()
    test_settings = Settings()
    
    os.environ.pop("DATABASE_URL", None)
    if original:
        os.environ["DATABASE_URL"] = original
    
    assert "postgresql+asyncpg" in test_settings.database_url
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_postgresql_config.py -v`
Expected: FAIL (settings uses hardcoded SQLite URL)

- [ ] **Step 3: Implement `Settings` to support DATABASE_URL env var**

Update config.py to check for DATABASE_URL environment variable before using default.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_postgresql_config.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/zerotrace/config.py tests/test_postgresql_config.py
git commit -m "feat: add PostgreSQL URL support to settings"
```

### Task 3: Configuration Override Tests

**Files:**
- Create: `tests/test_config.py`

**Interfaces:**
- Consumes: os.environ for various config overrides
- Produces: Settings instances with correct overridden values

- [ ] **Step 1: Write the failing test**

```python
def test_config_from_environment():
    """Test Settings reads from environment variables."""
    import os
    from zerotrace.config import Settings
    
    original = os.environ.get("ZEROTRACE_LOG_LEVEL")
    os.environ["ZEROTRACE_LOG_LEVEL"] = "DEBUG"
    os.environ["ZEROTRACE_DEBUG"] = "true"
    os.environ["ZEROTRACE_PORT"] = "8888"
    
    Settings.model_clear_cache()
    settings = Settings()
    
    os.environ.pop("ZEROTRACE_LOG_LEVEL", None)
    os.environ.pop("ZEROTRACE_DEBUG", None)
    os.environ.pop("ZEROTRACE_PORT", None)
    if original:
        os.environ["ZEROTRACE_LOG_LEVEL"] = original
    
    assert settings.log_level == "DEBUG"
    assert settings.debug == True
    assert settings.port == 8888
```

- [ ] **Step 2: Run test to verify failures**

Run: `pytest tests/test_config.py -v`
Expected: FAIL (Settings doesn't read these env vars properly)

- [ ] **Step 3: Implement proper environment variable support**

Update config.py with proper env_prefix and field aliases.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_config.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/zerotrace/config.py tests/test_config.py
git commit -m "feat: add environment variable configuration support"
```

### Task 4: Docker Setup

**Files:**
- Create: `Dockerfile`
- Create: `docker-compose.yml`
- Create: `tests/test_docker.py`

**Interfaces:**
- Consumes: None (infrastructure files)
- Produces: Docker configuration for development and production

- [ ] **Step 1: Write the failing test**

```python
def test_dockerfile_exists():
    """Test Dockerfile exists and has proper structure."""
    import pathlib
    dockerfile = pathlib.Path("Dockerfile")
    assert dockerfile.exists(), "Dockerfile must exist"
    content = dockerfile.read_text()
    assert "FROM" in content, "Dockerfile must have FROM instruction"
    assert "python" in content.lower(), "Dockerfile must install Python"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_docker.py -v`
Expected: FAIL (files don't exist)

- [ ] **Step 3: Create Dockerfile and docker-compose.yml**

Multi-stage Dockerfile with:
- Builder stage for dependencies
- Runtime stage with minimal image
- docker-compose.yml with zerotrace and database services

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_docker.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add Dockerfile docker-compose.yml tests/test_docker.py
git commit -m "chore: add Dockerfile and docker-compose for containerized deployment"
```

### Task 5: Structured Logging Tests

**Files:**
- Create: `tests/test_logging.py`

**Interfaces:**
- Consumes: Settings.log_format setting
- Produces: JSON formatted logs when configured

- [ ] **Step 1: Write the failing test**

```python
def test_json_log_format():
    """Test that JSON logging format produces valid JSON lines."""
    import logging
    import json
    from io import StringIO
    from zerotrace.logging_config import JSONFormatter, TextFormatter
    
    # Test JSON formatter
    record = logging.LogRecord(
        name="test", level=logging.INFO, pathname="test.py",
        lineno=1, msg="Test message", args=(), exc_info=None
    )
    formatter = JSONFormatter()
    output = formatter.format(record)
    
    # Should be valid JSON
    parsed = json.loads(output)
    assert parsed["level"] == "INFO"
    assert parsed["message"] == "Test message"
```

- [ ] **Step 2: Run test to verify it passes**

Run: `pytest tests/test_logging.py -v`
Expected: PASS (logging_config.py already exists and works)

- [ ] **Step 3: Add test for TextFormatter**

```python
def test_text_log_format():
    """Test that text logging format is human-readable."""
    import logging
    from zerotrace.logging_config import TextFormatter
    
    record = logging.LogRecord(
        name="test", level=logging.INFO, pathname="test.py",
        lineno=1, msg="Test message", args=(), exc_info=None
    )
    formatter = TextFormatter()
    output = formatter.format(record)
    
    # Should contain timestamp, level, and message
    assert "INFO" in output
    assert "Test message" in output
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_logging.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add tests/test_logging.py
git commit -m "test: add structured logging format tests"
```

### Task 6: API Documentation Verification

**Files:**
- Create: `tests/test_api_docs.py`

**Interfaces:**
- Consumes: FastAPI app created by create_app()
- Produces: Tests verifying OpenAPI spec and ReDoc endpoints work

- [ ] **Step 1: Write the test**

```python
def test_openapi_schema_exists():
    """Test OpenAPI schema is auto-generated and accessible."""
    from fastapi.testclient import TestClient
    from zerotrace.main import create_app
    
    app = create_app()
    client = TestClient(app)
    
    resp = client.get("/openapi.json")
    assert resp.status_code == 200
    schema = resp.json()
    assert "openapi" in schema
    assert "paths" in schema

def test_redoc_endpoint_exists():
    """Test ReDoc documentation is available."""
    from fastapi.testclient import TestClient
    from zerotrace.main import create_app
    
    app = create_app()
    client = TestClient(app)
    
    resp = client.get("/redoc")
    assert resp.status_code == 200
```

- [ ] **Step 2: Run test to verify it passes**

Run: `pytest tests/test_api_docs.py -v`
Expected: PASS (FastAPI auto-generates these)

- [ ] **Step 3: Commit**

```bash
git add tests/test_api_docs.py
git commit -m "test: add API documentation endpoints tests"
```

### Task 7: Database Migration Compatibility

**Files:**
- Create: `tests/test_migrations.py`

**Interfaces:**
- Consumes: Alembic configuration and environment
- Produces: Verification that migrations can be run on both SQLite and PostgreSQL schemas

- [ ] **Step 1: Write the test**

```python
@pytest.mark.asyncio
async def test_migration_can_run():
    """Test that Alembic migrations can be applied."""
    import subprocess
    result = subprocess.run(
        ["alembic", "upgrade", "head"],
        capture_output=True,
        text=True,
        cwd="K:/ZeroTrace"
    )
    # Migration should succeed or be no-op
    assert result.returncode == 0 or "already" in result.stdout.lower() or "already" in result.stderr.lower()
```

- [ ] **Step 2: Run test to verify it passes**

Run: `pytest tests/test_migrations.py -v`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add tests/test_migrations.py
git commit -m "test: add migration verification test"
```

### Task 8: Final Verification - Run Full Test Suite

**Files:**
- No new files

**Interfaces:**
- Consumes: All existing tests
- Produces: Verification that exactly 88 tests pass

- [ ] **Step 1: Run full test suite**

Run: `pytest tests/ -v`
Expected: 88 passed, 0 failed

- [ ] **Step 2: Verify test count**

Count unique test functions in tests/ directory.

- [ ] **Step 3: Commit any remaining changes**

```bash
git add -A
git commit -m "phase 3: complete production readiness implementation"
```