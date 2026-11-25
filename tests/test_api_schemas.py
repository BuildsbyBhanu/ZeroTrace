"""Tests for API schemas."""

import pytest
from datetime import datetime, timezone


def test_scan_create_valid():
    from zerotrace.api.schemas import ScanCreate

    schema = ScanCreate(target_url="http://localhost:8080", profile="standard")
    assert schema.target_url == "http://localhost:8080"
    assert schema.profile == "standard"
    assert schema.save_report is False


def test_scan_response_serialization():
    from zerotrace.api.schemas import ScanResponse

    now = datetime.now(timezone.utc)
    resp = ScanResponse(
        scan_id="abc-123",
        target_url="http://localhost:8080",
        profile="standard",
        status="completed",
        started_at=now,
        findings_count=5,
    )
    assert resp.scan_id == "abc-123"
    assert resp.findings_count == 5


def test_finding_response_serialization():
    from zerotrace.api.schemas import FindingResponse

    resp = FindingResponse(
        finding_id="ZT-2026-001",
        title="Missing HSTS",
        category="A05",
        severity="medium",
        status="potential",
        affected_url="http://localhost:8080",
        evidence="No HSTS header",
        remediation="Add HSTS header",
        module_name="security-headers",
    )
    assert resp.title == "Missing HSTS"
    assert resp.severity == "medium"


def test_progress_response():
    from zerotrace.api.schemas import ProgressResponse

    resp = ProgressResponse(
        scan_id="abc-123",
        status="running",
        findings_count=3,
    )
    assert resp.status == "running"
    assert resp.findings_count == 3
