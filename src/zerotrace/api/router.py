"""FastAPI router for ZeroTrace API."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import AsyncGenerator, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pathlib import Path

from zerotrace.api.schemas import (
    ScanCreate,
    ScanDetailResponse,
    ScanResponse,
    ProgressResponse,
    FindingResponse,
)
from zerotrace.database.models import ScanJob, Finding
from zerotrace.engine.orchestrator import orchestrator, ScanProfile
from zerotrace.logging_config import get_logger

logger = get_logger("api")

# Separate routers for HTML and API routes
api_router = APIRouter()
html_router = APIRouter()

# Setup Jinja2 environment
def get_jinja_env():
    template_dir = Path(__file__).parent.parent / "templates"
    return Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(['html', 'xml'])
    )

template_env = get_jinja_env()

# In-memory store for active scans
_active_scans: dict[str, asyncio.Task] = {}


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields an async DB session."""
    from sqlalchemy.ext.asyncio import create_async_engine
    from zerotrace.config import settings
    
    engine = create_async_engine(settings.database_url, echo=False, connect_args={"check_same_thread": False})
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        yield session


# HTML Routes
@html_router.get("/", response_class=HTMLResponse)
async def index_page():
    """Render the index/landing page."""
    template = template_env.get_template("index.html")
    html = template.render(title="Home", version="0.1.0")
    return HTMLResponse(content=html)


@html_router.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_progress_page(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Render the scan progress page."""
    stmt = select(ScanJob).where(ScanJob.scan_id == scan_id)
    result = await db.execute(stmt)
    job = result.scalar_one_or_none()
    
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Query findings count separately to avoid lazy-loading issues
    from sqlalchemy import func
    count_stmt = select(func.count(Finding.id)).where(Finding.scan_id == scan_id)
    count_result = await db.execute(count_stmt)
    findings_count = count_result.scalar_one()
    
    template = template_env.get_template("scan.html")
    from datetime import datetime, timezone
    # Calculate elapsed time safely, handling both naive and aware datetimes
    if job.status == "running" and job.started_at:
        now = datetime.now(timezone.utc)
        if job.started_at.tzinfo is None:
            job_started_at_aware = job.started_at.replace(tzinfo=timezone.utc)
        else:
            job_started_at_aware = job.started_at
        elapsed = (now - job_started_at_aware).total_seconds()
    else:
        elapsed = job.duration_seconds or 0
    html = template.render(
        scan_id=scan_id,
        target=job.target_url,
        status=job.status,
        findings_count=findings_count,
        elapsed_seconds=f"{int(elapsed/60)}:{int(elapsed%60):02d}",
        error_message=job.error_message,
    )
    return HTMLResponse(content=html)


@html_router.get("/results/{scan_id}", response_class=HTMLResponse)
async def results_page(scan_id: str, filter_severity: Optional[str] = Query(None), db: AsyncSession = Depends(get_db)):
    """Render the results page with findings."""
    stmt = select(ScanJob).where(ScanJob.scan_id == scan_id)
    result = await db.execute(stmt)
    job = result.scalar_one_or_none()
    
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    findings_stmt = select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.created_at.desc())
    findings_result = await db.execute(findings_stmt)
    findings = findings_result.scalars().all()
    
    findings_data = [
        {
            "finding_id": f.finding_id,
            "title": f.title,
            "category": f.category,
            "severity": f.severity,
            "status": f.status,
            "affected_url": f.affected_url or "",
            "request": f.request or "",
            "evidence": f.evidence or "",
            "impact": f.impact or "",
            "remediation": f.remediation or "",
            "references": f.references or [],
            "module_name": f.module_name,
        }
        for f in findings
    ]
    
    # Compute severity counts for summary
    severity_counts = {
        "critical": sum(1 for f in findings_data if f["severity"] == "critical"),
        "high": sum(1 for f in findings_data if f["severity"] == "high"),
        "medium": sum(1 for f in findings_data if f["severity"] == "medium"),
        "low": sum(1 for f in findings_data if f["severity"] == "low"),
        "informational": sum(1 for f in findings_data if f["severity"] == "informational"),
    }
    
    template = template_env.get_template("results.html")
    html = template.render(
        scan_id=scan_id,
        target=job.target_url,
        status=job.status,
        profile=job.profile,
        duration_seconds=job.duration_seconds,
        findings_count=len(findings),
        all_findings=findings_data,
        severity_counts=severity_counts,
        filter_severity=filter_severity or 'all'
    )
    return HTMLResponse(content=html)


@api_router.post("/scans", response_model=ScanResponse, status_code=202)
async def create_scan(
    scan_in: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Trigger a new security scan."""
    # Create scan job
    job = ScanJob(
        target_url=scan_in.target_url,
        profile=scan_in.profile,
        status="pending",
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    # Launch background task
    task = asyncio.create_task(_run_scan(job.id, db))
    _active_scans[job.scan_id] = task

    return ScanResponse(
        scan_id=job.scan_id,
        target_url=job.target_url,
        profile=job.profile,
        status=job.status,
        started_at=job.started_at,
        findings_count=0,
    )


async def _run_scan(job_id: int, db: AsyncSession) -> None:
    """Run a scan in background and persist results."""
    # Fetch job
    result = await db.execute(select(ScanJob).where(ScanJob.id == job_id))
    job = result.scalar_one()

    job.mark_running()
    await db.commit()

    try:
        profile = ScanProfile(job.profile)
        scan_result = await orchestrator.run(job.target_url, profile)

        # Update job
        job.completed_at = datetime.now(timezone.utc)
        job.duration_seconds = scan_result.duration_seconds
        if scan_result.status == "completed":
            job.mark_completed(scan_result.duration_seconds, len(scan_result.findings))
        else:
            job.mark_failed(scan_result.error or "Unknown error")
        await db.commit()

        # Persist findings
        for finding in scan_result.findings:
            finding_record = Finding.from_finding(job.scan_id, finding.to_dict())
            db.add(finding_record)
        await db.commit()

    except Exception as exc:
        logger.error("Scan failed", extra={"job_id": job_id, "error": str(exc)})
        job.mark_failed(str(exc))
        await db.commit()
    finally:
        _active_scans.pop(job.scan_id, None)


@api_router.get("/scans", response_model=list[ScanResponse])
async def list_scans(
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """List recent scan jobs."""
    from sqlalchemy import func
    
    # Use lateral join to count findings efficiently without lazy loading
    findings_count_stmt = select(
        Finding.scan_id,
        func.count(Finding.id).label("count")
    ).group_by(Finding.scan_id)
    
    stmt = (
        select(ScanJob)
        .order_by(ScanJob.started_at.desc())
        .limit(limit)
    )
    result = await db.execute(stmt)
    jobs = result.scalars().all()
    
    # Get findings counts separately
    findings_counts = {}
    for job in jobs:
        count_stmt = select(func.count(Finding.id)).where(Finding.scan_id == job.scan_id)
        count_result = await db.execute(count_stmt)
        findings_counts[job.scan_id] = count_result.scalar_one()
    
    return [
        ScanResponse(
            scan_id=j.scan_id,
            target_url=j.target_url,
            profile=j.profile,
            status=j.status,
            started_at=j.started_at,
            completed_at=j.completed_at,
            findings_count=findings_counts.get(j.scan_id, 0),
            duration_seconds=j.duration_seconds,
        )
        for j in jobs
    ]


@api_router.get("/scans/{scan_id}", response_model=ScanDetailResponse)
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get scan details with findings."""
    stmt = select(ScanJob).where(ScanJob.scan_id == scan_id)
    result = await db.execute(stmt)
    job = result.scalar_one_or_none()

    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_stmt = select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.created_at.desc())
    findings_result = await db.execute(findings_stmt)
    findings = findings_result.scalars().all()

    return ScanDetailResponse(
        scan_id=job.scan_id,
        target_url=job.target_url,
        profile=job.profile,
        status=job.status,
        started_at=job.started_at,
        completed_at=job.completed_at,
        findings_count=len(findings),
        duration_seconds=job.duration_seconds,
        error_message=job.error_message,
        findings=[
            FindingResponse(
                finding_id=f.finding_id,
                title=f.title,
                category=f.category,
                severity=f.severity,
                status=f.status,
                affected_url=f.affected_url or "",
                request=f.request or "",
                evidence=f.evidence or "",
                impact=f.impact or "",
                remediation=f.remediation or "",
                references=f.references or [],
                module_name=f.module_name,
            )
            for f in findings
        ],
    )


@api_router.get("/scans/{scan_id}/progress", response_model=ProgressResponse)
async def get_progress(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Get real-time scan progress."""
    stmt = select(ScanJob).where(ScanJob.scan_id == scan_id)
    result = await db.execute(stmt)
    job = result.scalar_one_or_none()

    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_stmt = select(Finding).where(Finding.scan_id == scan_id)
    findings_result = await db.execute(findings_stmt)
    findings = findings_result.scalars().all()

    # Calculate elapsed time safely, handling both naive and aware datetimes
    if job.status == "running" and job.started_at:
        now = datetime.now(timezone.utc)
        if job.started_at.tzinfo is None:
            job_started_at_aware = job.started_at.replace(tzinfo=timezone.utc)
        else:
            job_started_at_aware = job.started_at
        elapsed = (now - job_started_at_aware).total_seconds()
    else:
        elapsed = job.duration_seconds or 0

    return ProgressResponse(
        scan_id=job.scan_id,
        status=job.status,
        current_module="",
        modules_total=3,
        modules_completed=3 if job.status in ("completed", "failed") else 0,
        findings_count=len(findings),
        elapsed_seconds=elapsed,
        error_message=job.error_message,
    )


@api_router.delete("/scans/{scan_id}", status_code=204)
async def cancel_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Cancel a running scan."""
    stmt = select(ScanJob).where(ScanJob.scan_id == scan_id)
    result = await db.execute(stmt)
    job = result.scalar_one_or_none()

    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")

    if job.status != "running":
        raise HTTPException(status_code=400, detail="Scan is not running")

    # Cancel background task
    task = _active_scans.get(scan_id)
    if task:
        task.cancel()

    job.mark_cancelled()
    await db.commit()


@api_router.get("/scans/{scan_id}/export")
async def export_scan(
    scan_id: str,
    format: str = Query("json", pattern="^(json|html|pdf)$"),
    db: AsyncSession = Depends(get_db),
):
    """Export scan results in specified format."""
    stmt = select(ScanJob).where(ScanJob.scan_id == scan_id)
    result = await db.execute(stmt)
    job = result.scalar_one_or_none()

    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_stmt = select(Finding).where(Finding.scan_id == scan_id)
    findings_result = await db.execute(findings_stmt)
    findings = findings_result.scalars().all()

    if format == "json":
        from fastapi.responses import JSONResponse
        data = {
            "scan_id": job.scan_id,
            "target_url": job.target_url,
            "profile": job.profile,
            "status": job.status,
            "started_at": job.started_at.isoformat(),
            "completed_at": job.completed_at.isoformat() if job.completed_at else None,
            "duration_seconds": job.duration_seconds,
            "findings_count": len(findings),
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "title": f.title,
                    "category": f.category,
                    "severity": f.severity,
                    "status": f.status,
                    "affected_url": f.affected_url or "",
                    "request": f.request or "",
                    "evidence": f.evidence or "",
                    "impact": f.impact or "",
                    "remediation": f.remediation or "",
                    "references": f.references or [],
                    "module_name": f.module_name,
                }
                for f in findings
            ],
        }
        return JSONResponse(content=data)
    elif format == "pdf":
        # PDF export
        from fastapi.responses import Response
        from zerotrace.reporting.pdf_generator import generate_pdf_report
        
        findings_data = [
            {
                "finding_id": f.finding_id,
                "title": f.title,
                "category": f.category,
                "severity": f.severity,
                "status": f.status,
                "affected_url": f.affected_url or "",
                "request": f.request or "",
                "evidence": f.evidence or "",
                "impact": f.impact or "",
                "remediation": f.remediation or "",
                "references": f.references or [],
                "module_name": f.module_name,
            }
            for f in findings
        ]
        
        scan_data = {
            "scan_id": job.scan_id,
            "target_url": job.target_url,
            "profile": job.profile,
            "status": job.status,
            "started_at": job.started_at.isoformat() if job.started_at else None,
            "completed_at": job.completed_at.isoformat() if job.completed_at else None,
            "duration_seconds": job.duration_seconds,
            "findings": findings_data,
        }
        
        pdf_bytes = generate_pdf_report(scan_data)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=zerotrace_report_{job.scan_id}.pdf"}
        )
    else:
        # HTML export - use the professional template
        from fastapi.responses import HTMLResponse
        from datetime import datetime, timezone
        
        findings_data = [
            {
                "finding_id": f.finding_id,
                "title": f.title,
                "category": f.category,
                "severity": f.severity,
                "status": f.status,
                "affected_url": f.affected_url or "",
                "request": f.request or "",
                "evidence": f.evidence or "",
                "impact": f.impact or "",
                "remediation": f.remediation or "",
                "references": f.references or [],
                "module_name": f.module_name,
            }
            for f in findings
        ]
        
        html = template_env.get_template("report.html").render(
            scan_id=job.scan_id,
            target_url=job.target_url,
            profile=job.profile,
            status=job.status,
            started_at=job.started_at.isoformat() if job.started_at else None,
            completed_at=job.completed_at.isoformat() if job.completed_at else None,
            duration_seconds=job.duration_seconds,
            findings=findings_data,
            severity_labels={
                "critical": "Confirmed Vulnerability",
                "high": "Confirmed Vulnerability",
                "medium": "Potential Vulnerability",
                "low": "Potential Vulnerability",
                "informational": "Informational Finding",
            },
            status_labels={
                "confirmed": "Confirmed",
                "potential": "Potential",
                "informational": "Informational",
                "requires_manual_verification": "Requires Manual Verification",
            },
        )
        return HTMLResponse(content=html)
