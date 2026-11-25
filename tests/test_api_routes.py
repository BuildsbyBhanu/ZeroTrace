"""Tests for API routes."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from zerotrace.main import create_app
from zerotrace.database.models import Base
from zerotrace.api.router import api_router, get_db


@pytest.fixture
def test_engine():
    return create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)


@pytest.fixture
async def async_session(test_engine):
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async_session = sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    yield async_session
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await test_engine.dispose()


@pytest.mark.asyncio
async def test_list_scans_empty(async_session):
    app = create_app()
    app.include_router(api_router, prefix="/api/v1")
    client = TestClient(app)

    async def override_get_db():
        async with async_session() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db

    resp = client.get("/api/v1/scans")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_get_scan_not_found(async_session):
    app = create_app()
    app.include_router(api_router, prefix="/api/v1")
    client = TestClient(app)

    async def override_get_db():
        async with async_session() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db

    resp = client.get("/api/v1/scans/nonexistent")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_export_json_format(async_session):
    app = create_app()
    app.include_router(api_router, prefix="/api/v1")
    client = TestClient(app)

    async def override_get_db():
        async with async_session() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db

    # Create a scan job first
    from zerotrace.database.models import ScanJob
    async with async_session() as session:
        job = ScanJob(target_url="http://localhost:8080", profile="quick", status="completed")
        session.add(job)
        await session.commit()
        await session.refresh(job)

    resp = client.get(f"/api/v1/scans/{job.scan_id}/export?format=json")
    assert resp.status_code == 200
    data = resp.json()
    assert data["scan_id"] == job.scan_id
    assert data["target_url"] == "http://localhost:8080"


@pytest.mark.asyncio
async def test_export_html_format(async_session):
    app = create_app()
    app.include_router(api_router, prefix="/api/v1")
    client = TestClient(app)

    async def override_get_db():
        async with async_session() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db

    from zerotrace.database.models import ScanJob
    async with async_session() as session:
        job = ScanJob(target_url="http://localhost:8080", profile="quick", status="completed")
        session.add(job)
        await session.commit()
        await session.refresh(job)

    resp = client.get(f"/api/v1/scans/{job.scan_id}/export?format=html")
    assert resp.status_code == 200
    assert "<html" in resp.text.lower()
    assert "ZeroTrace" in resp.text
