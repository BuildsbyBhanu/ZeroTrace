"""Tests for PDF report generation."""

import pytest
from pathlib import Path
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
async def test_pdf_export_endpoint_exists(async_session):
    """Test that PDF export endpoint returns PDF content."""
    app = create_app()
    
    async def override_get_db():
        async with async_session() as session:
            yield session
    
    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    
    # Create a scan job
    async with async_session() as session:
        job = ScanJob(
            target_url="http://localhost:8080", 
            profile="quick", 
            status="completed"
        )
        session.add(job)
        await session.commit()
        await session.refresh(job)
        
        finding = Finding(
            scan_id=job.scan_id,
            title="Test Finding",
            category="A05:2021",
            severity="medium",
            status="potential",
            affected_url="http://localhost:8080",
            evidence="Test evidence",
            impact="Test impact",
            remediation="Test remediation",
            module_name="test-module",
        )
        session.add(finding)
        await session.commit()
    
    resp = client.get(f"/api/v1/scans/{job.scan_id}/export?format=pdf")
    assert resp.status_code == 200
    # PDF should start with %PDF header (PyMuPDF generates %PDF-1.x format)
    assert resp.content[:5].upper().startswith(b"%PDF")


@pytest.mark.asyncio
async def test_pdf_export_creates_valid_pdf(async_session):
    """Test that PDF export creates a valid PDF file."""
    app = create_app()
    
    async def override_get_db():
        async with async_session() as session:
            yield session
    
    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    
    # Create a scan job with multiple findings
    async with async_session() as session:
        job = ScanJob(
            target_url="http://localhost:8080", 
            profile="quick", 
            status="completed"
        )
        session.add(job)
        await session.commit()
        await session.refresh(job)
        
        for i in range(3):
            finding = Finding(
                scan_id=job.scan_id,
                title=f"Test Finding {i+1}",
                category="A05:2021",
                severity=["critical", "high", "medium"][i % 3],
                status="potential" if i % 2 == 0 else "confirmed",
                affected_url=f"http://localhost:8080/path{i}",
                evidence=f"Evidence for finding {i+1}",
                impact=f"Impact for finding {i+1}",
                remediation=f"Remediation for finding {i+1}",
                module_name="test-module",
            )
            session.add(finding)
        await session.commit()
    
    resp = client.get(f"/api/v1/scans/{job.scan_id}/export?format=pdf")
    assert resp.status_code == 200
    # Verify it's valid PDF - check for PDF header and EOF marker
    assert b"%PDF" in resp.content
    assert b"%%EOF" in resp.content


@pytest.mark.asyncio
async def test_pdf_report_closes(async_session):
    """Test that PDF has proper EOF marker."""
    app = create_app()
    
    async def override_get_db():
        async with async_session() as session:
            yield session
    
    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    
    async with async_session() as session:
        job = ScanJob(
            target_url="http://localhost:8080",
            profile="quick",
            status="completed"
        )
        session.add(job)
        await session.commit()
        await session.refresh(job)
    
    resp = client.get(f"/api/v1/scans/{job.scan_id}/export?format=pdf")
    assert resp.status_code == 200
    # PDF should end with %%EOF (PyMuPDF generates lowercase %%eof)
    content = resp.content
    assert b"%%eof" in content.lower()