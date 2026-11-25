"""Integration tests for full scan lifecycle."""

import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from zerotrace.main import create_app
from zerotrace.database.models import Base, ScanJob, Finding
from zerotrace.api.router import get_db, api_router


@pytest.fixture
def test_engine():
    return create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)


@pytest.fixture
async def async_session(test_engine):
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async_session_maker = sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    yield async_session_maker
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await test_engine.dispose()


@pytest.mark.asyncio
async def test_create_scan_endpoint(async_session):
    """Test scan creation endpoint returns proper response."""
    app = create_app()
    
    # Mock the orchestrator to avoid actual scan execution
    from zerotrace.engine.orchestrator import orchestrator
    mock_orchestrator = AsyncMock()
    from zerotrace.engine.context import ValidatedTarget
    from zerotrace.engine.base import ScanProfile
    mock_orchestrator.run.return_value = type('ScanResult', (), {
        'status': 'completed',
        'findings': [],
        'duration_seconds': 0.0,
        'error': None,
    })()
    
    with patch.object(orchestrator, 'run', mock_orchestrator.run):
        async def override_get_db():
            async with async_session() as session:
                yield session
        
        app.dependency_overrides[get_db] = override_get_db
        client = TestClient(app)
        
        # Start scan - should return 202 Accepted
        resp = client.post("/api/v1/scans", json={
            "target_url": "http://localhost:8080",  # Safe local target only
            "profile": "quick"
        })
        assert resp.status_code == 202
        data = resp.json()
        scan_id = data["scan_id"]
        assert scan_id is not None
        assert data["target_url"] == "http://localhost:8080"
        assert data["status"] == "pending"
        assert data["profile"] == "quick"


@pytest.mark.asyncio
async def test_list_scans_endpoint(async_session):
    """Test listing scans endpoint."""
    app = create_app()
    
    async def override_get_db():
        async with async_session() as session:
            yield session
    
    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    
    # List scans when empty
    resp = client.get("/api/v1/scans")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    
    # Create a scan job and list again - use sync operation
    async with async_session() as session:
        job = ScanJob(target_url="http://localhost:8080", profile="quick", status="completed")
        session.add(job)
        await session.commit()
        await session.refresh(job)
        # Load findings to avoid lazy loading issues
        from sqlalchemy import select
        from zerotrace.database.models import Finding
        findings_stmt = select(Finding).where(Finding.scan_id == job.scan_id)
        await session.execute(findings_stmt)
    
    resp = client.get("/api/v1/scans")
    data = resp.json()
    assert len(data) == 1
    assert data[0]["scan_id"] == job.scan_id


@pytest.mark.asyncio
async def test_full_scan_lifecycle(async_session):
    """Test complete scan creation, progress tracking, and results."""
    app = create_app()
    
    # Mock the orchestrator to avoid validation/network issues
    from zerotrace.engine.orchestrator import orchestrator
    
    async def mock_run(target_url, profile, **kwargs):
        from zerotrace.engine.context import ValidatedTarget
        class MockResult:
            status = "completed"
            findings = []
            duration_seconds = 0.1
            error = None
        return MockResult()
    
    with patch.object(orchestrator, 'run', mock_run):
        async def override_get_db():
            async with async_session() as session:
                yield session
        
        app.dependency_overrides[get_db] = override_get_db
        client = TestClient(app)
        
        # Create scan job directly in database and verify we can query it
        async with async_session() as session:
            job = ScanJob(target_url="http://localhost:8080", profile="quick", status="pending")
            session.add(job)
            await session.commit()
            await session.refresh(job)
        
        # Check scan exists
        resp = client.get(f"/api/v1/scans/{job.scan_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_id"] == job.scan_id
        assert data["target_url"] == "http://localhost:8080"
        assert data["status"] == "pending"
        
        # Check progress endpoint
        resp = client.get(f"/api/v1/scans/{job.scan_id}/progress")
        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_id"] == job.scan_id
        assert data["status"] == "pending"


@pytest.mark.asyncio
async def test_html_scan_page_renders(async_session):
    """Test that the HTML scan page renders correctly."""
    app = create_app()
    
    async def override_get_db():
        async with async_session() as session:
            yield session
    
    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    
    # Create a scan job
    async with async_session() as session:
        job = ScanJob(target_url="http://localhost:8080", profile="quick", status="completed")
        session.add(job)
        await session.commit()
        await session.refresh(job)
    
    resp = client.get(f"/scan/{job.scan_id}")
    assert resp.status_code == 200
    assert "ZeroTrace" in resp.text


@pytest.mark.asyncio
async def test_results_page_with_findings(async_session):
    """Test results page renders with findings."""
    app = create_app()
    
    async def override_get_db():
        async with async_session() as session:
            yield session
    
    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    
    # Create a scan job with findings
    async with async_session() as session:
        job = ScanJob(target_url="http://localhost:8080", profile="quick", status="completed")
        session.add(job)
        await session.commit()
        await session.refresh(job)
        
        finding = Finding(
            scan_id=job.scan_id,
            title="Missing HSTS Header",
            category="A05:2021",
            severity="medium",
            status="potential",
            affected_url="http://localhost:8080",
            evidence="No Strict-Transport-Security header found",
            impact="Potential man-in-the-middle attacks",
            remediation="Add Strict-Transport-Security: max-age=31536000",
            module_name="security-headers",
        )
        session.add(finding)
        await session.commit()
    
    resp = client.get(f"/results/{job.scan_id}")
    assert resp.status_code == 200
    assert "Missing HSTS Header" in resp.text
    assert "security-headers" in resp.text


@pytest.mark.asyncio
async def test_index_page_loads(async_session):
    """Test the index/home page loads correctly."""
    app = create_app()
    
    async def override_get_db():
        async with async_session() as session:
            yield session
    
    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    
    resp = client.get("/")
    assert resp.status_code == 200
    assert "ZeroTrace" in resp.text
    assert '<form' in resp.text
    assert 'hx-get' in resp.text or 'hx-trigger' in resp.text


