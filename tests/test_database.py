"""Tests for database models (ScanJob, Finding)."""

import pytest
from sqlalchemy import select


@pytest.mark.asyncio
async def test_scan_job_crud(async_session):
    from zerotrace.database.models import ScanJob

    job = ScanJob(target_url="http://localhost:8080", profile="standard")
    async_session.add(job)
    await async_session.commit()
    await async_session.refresh(job)

    stmt = select(ScanJob).where(ScanJob.id == job.id)
    result = await async_session.execute(stmt)
    fetched = result.scalar_one()

    assert fetched.target_url == "http://localhost:8080"
    assert fetched.profile == "standard"
    assert fetched.status == "pending"
    assert fetched.scan_id is not None


@pytest.mark.asyncio
async def test_scan_job_update_status(async_session):
    from zerotrace.database.models import ScanJob

    job = ScanJob(target_url="http://localhost:8080", profile="quick")
    async_session.add(job)
    await async_session.commit()
    await async_session.refresh(job)

    job.status = "running"
    await async_session.commit()

    stmt = select(ScanJob).where(ScanJob.id == job.id)
    fetched = (await async_session.execute(stmt)).scalar_one()
    assert fetched.status == "running"


@pytest.mark.asyncio
async def test_finding_creation(async_session):
    from zerotrace.database.models import ScanJob, Finding

    job = ScanJob(target_url="http://localhost:8080", profile="standard")
    async_session.add(job)
    await async_session.commit()
    await async_session.refresh(job)

    finding = Finding(
        scan_id=job.scan_id,
        title="Missing HSTS",
        category="A05",
        severity="medium",
        status="potential",
        affected_url="http://localhost:8080",
        evidence="No Strict-Transport-Security header",
        impact="Potential man-in-the-middle risk",
        remediation="Add Strict-Transport-Security header",
        module_name="security-headers",
    )
    async_session.add(finding)
    await async_session.commit()
    await async_session.refresh(finding)

    stmt = select(Finding).where(Finding.scan_id == job.scan_id)
    results = (await async_session.execute(stmt)).scalars().all()
    assert len(results) == 1
    assert results[0].title == "Missing HSTS"
    assert results[0].severity == "medium"


@pytest.mark.asyncio
async def test_scan_job_not_found(async_session):
    from zerotrace.database.models import ScanJob

    stmt = select(ScanJob).where(ScanJob.scan_id == "nonexistent-id")
    result = (await async_session.execute(stmt)).scalar_one_or_none()
    assert result is None
