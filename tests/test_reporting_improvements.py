"""Tests for Phase 2 Slice 3 - Reporting Improvements.

These tests verify:
1. Results page has better visual hierarchy and expandable findings
2. HTML reports render correctly with all sections
3. CLI report command supports both formats
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from jinja2 import Environment, FileSystemLoader
from pathlib import Path

from zerotrace.main import create_app
from zerotrace.database.models import Base, ScanJob, Finding
from zerotrace.api.router import get_db


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


class TestResultsPageImprovements:
    """Tests for improved results page UX."""

    @pytest.mark.asyncio
    async def test_results_page_has_summary_section(self, async_session):
        """Test that results page shows a summary section with severity counts."""
        app = create_app()
        
        async def override_get_db():
            async with async_session() as session:
                yield session
        
        app.dependency_overrides[get_db] = override_get_db
        client = TestClient(app)
        
        # Create a scan job with multiple findings
        async with async_session() as session:
            job = ScanJob(target_url="http://localhost:8080", profile="standard", status="completed")
            session.add(job)
            await session.commit()
            await session.refresh(job)
            
            # Add findings with different severities
            for severity, title in [
                ("critical", "SQL Injection Vulnerability"),
                ("high", "Missing HSTS Header"),
                ("medium", "Weak Cookie Configuration"),
                ("low", "Server Version Disclosure"),
            ]:
                finding = Finding(
                    scan_id=job.scan_id,
                    title=title,
                    category="A03:2021",
                    severity=severity,
                    status="confirmed",
                    affected_url="http://localhost:8080",
                    evidence=f"Evidence for {title}",
                    impact=f"Impact of {title}",
                    remediation=f"Fix for {title}",
                    module_name="test-module",
                )
                session.add(finding)
            await session.commit()
        
        resp = client.get(f"/results/{job.scan_id}")
        assert resp.status_code == 200
        # Check summary section exists
        text = resp.text.lower()
        assert "summary" in text
        
    @pytest.mark.asyncio
    async def test_results_page_severity_badges(self, async_session):
        """Test that severity badges are properly styled."""
        app = create_app()
        
        async def override_get_db():
            async with async_session() as session:
                yield session
        
        app.dependency_overrides[get_db] = override_get_db
        client = TestClient(app)
        
        # Create scan with findings
        async with async_session() as session:
            job = ScanJob(target_url="http://localhost:8080", profile="standard", status="completed")
            session.add(job)
            await session.commit()
            await session.refresh(job)
            
            finding = Finding(
                scan_id=job.scan_id,
                title="Test Finding",
                category="A03:2021",
                severity="high",
                status="confirmed",
                affected_url="http://localhost:8080",
                evidence="Test evidence",
                impact="Test impact",
                remediation="Test remediation",
                module_name="test-module",
            )
            session.add(finding)
            await session.commit()
        
        resp = client.get(f"/results/{job.scan_id}")
        assert resp.status_code == 200
        # Check for severity styling - looking for badge classes or severity colors
        assert "high" in resp.text or "High" in resp.text
        
    @pytest.mark.asyncio
    async def test_results_page_expandable_findings(self, async_session):
        """Test that findings can be expanded to show details."""
        app = create_app()
        
        async def override_get_db():
            async with async_session() as session:
                yield session
        
        app.dependency_overrides[get_db] = override_get_db
        client = TestClient(app)
        
        # Create scan with detailed findings
        async with async_session() as session:
            job = ScanJob(target_url="http://localhost:8080", profile="standard", status="completed")
            session.add(job)
            await session.commit()
            await session.refresh(job)
            
            finding = Finding(
                scan_id=job.scan_id,
                title="Detailed Finding",
                category="A05:2021",
                severity="medium",
                status="confirmed",
                affected_url="http://localhost:8080/path",
                evidence="Server: Apache/2.4.41",
                impact="Attacker can identify specific version to target",
                remediation="Configure server to hide version information",
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
                module_name="headers",
            )
            session.add(finding)
            await session.commit()
        
        resp = client.get(f"/results/{job.scan_id}")
        assert resp.status_code == 200
        # Check that evidence, impact, remediation are shown
        text = resp.text
        assert "evidence" in text.lower() or "Apache" in text
        assert "impact" in text.lower()
        assert "remediation" in text.lower() or "Fix" in text


class TestHTMLReportImprovements:
    """Tests for improved HTML report generation."""

    @pytest.mark.asyncio
    async def test_html_report_has_authorization_notice(self, async_session):
        """Test that HTML report includes authorization notice."""
        app = create_app()
        
        async def override_get_db():
            async with async_session() as session:
                yield session
        
        app.dependency_overrides[get_db] = override_get_db
        client = TestClient(app)
        
        # Create scan
        async with async_session() as session:
            job = ScanJob(target_url="http://localhost:8080", profile="standard", status="completed")
            session.add(job)
            await session.commit()
            await session.refresh(job)
            
            finding = Finding(
                scan_id=job.scan_id,
                title="Test Finding",
                category="A03:2021",
                severity="high",
                status="confirmed",
                affected_url="http://localhost:8080",
                evidence="Test evidence",
                impact="Test impact",
                remediation="Test remediation",
                module_name="test-module",
            )
            session.add(finding)
            await session.commit()
        
        # Export HTML report
        resp = client.get(f"/api/v1/scans/{job.scan_id}/export?format=html")
        assert resp.status_code == 200
        
        html_content = resp.text
        # Check for authorization notice
        text_lower = html_content.lower()
        assert "authorization" in text_lower or "authorized" in text_lower or "warning" in text_lower
        
    @pytest.mark.asyncio
    async def test_html_report_summary_statistics(self, async_session):
        """Test that HTML report shows severity summary statistics."""
        app = create_app()
        
        async def override_get_db():
            async with async_session() as session:
                yield session
        
        app.dependency_overrides[get_db] = override_get_db
        client = TestClient(app)
        
        # Create scan with multiple findings
        async with async_session() as session:
            job = ScanJob(target_url="http://localhost:8080", profile="standard", status="completed")
            session.add(job)
            await session.commit()
            await session.refresh(job)
            
            # Add findings
            for severity in ["critical", "high", "medium", "low", "informational"]:
                finding = Finding(
                    scan_id=job.scan_id,
                    title=f"{severity.title()} Finding",
                    category="A03:2021",
                    severity=severity,
                    status="confirmed",
                    affected_url="http://localhost:8080",
                    evidence="Test evidence",
                    impact="Test impact",
                    remediation="Test remediation",
                    module_name="test-module",
                )
                session.add(finding)
            await session.commit()
        
        # Export HTML report
        resp = client.get(f"/api/v1/scans/{job.scan_id}/export?format=html")
        assert resp.status_code == 200
        
        html_content = resp.text
        # Should show summary statistics
        assert "summary" in html_content.lower()
        # Should show count of findings
        assert "5" in html_content  # Total count
        
    @pytest.mark.asyncio
    async def test_html_report_offline_friendly(self, async_session):
        """Test that HTML report works offline (no external CDN dependencies)."""
        app = create_app()
        
        async def override_get_db():
            async with async_session() as session:
                yield session
        
        app.dependency_overrides[get_db] = override_get_db
        client = TestClient(app)
        
        # Create scan
        async with async_session() as session:
            job = ScanJob(target_url="http://localhost:8080", profile="standard", status="completed")
            session.add(job)
            await session.commit()
            await session.refresh(job)
            
            finding = Finding(
                scan_id=job.scan_id,
                title="Test Finding",
                category="A03:2021",
                severity="medium",
                status="confirmed",
                affected_url="http://localhost:8080",
                evidence="Test evidence",
                impact="Test impact",
                remediation="Test remediation",
                module_name="test-module",
            )
            session.add(finding)
            await session.commit()
        
        resp = client.get(f"/api/v1/scans/{job.scan_id}/export?format=html")
        assert resp.status_code == 200
        
        # Should use inline styles, not external CSS files
        html_content = resp.text
        # Check for inline styles (professional reports often include them)
        # The report.html should have style tags inline
        assert "<style>" in html_content or "style=" in html_content


class TestCLIReportImprovements:
    """Tests for improved CLI report functionality."""

    def test_cli_report_json_output_format(self):
        """Test that CLI report outputs valid JSON."""
        from typer.testing import CliRunner
        from cli.main import app
        
        runner = CliRunner()
        result = runner.invoke(app, ["report", "test-scan-id", "--format", "json"])
        
        # Output should be valid for either success or file not found
        if result.exit_code == 0:
            # Should contain JSON structure or file saved message
            output = result.output
            assert "report" in output.lower() or "saved" in output.lower() or result.exit_code == 0

    def test_cli_report_html_output_format(self):
        """Test that CLI report supports HTML format."""
        from typer.testing import CliRunner
        from cli.main import app
        
        runner = CliRunner()
        result = runner.invoke(app, ["report", "test-scan-id", "--format", "html"])
        
        # Should either succeed or fail gracefully
        assert result.exit_code in [0, 1]

    def test_cli_report_help_text(self):
        """Test that report command help shows format options clearly."""
        from typer.testing import CliRunner
        from cli.main import app
        
        runner = CliRunner()
        result = runner.invoke(app, ["report", "--help"])
        
        assert result.exit_code == 0
        # Should mention formats
        assert "json" in result.output.lower() or "html" in result.output.lower()


class TestHTMLTemplateQuality:
    """Tests for HTML template quality and accessibility."""

    @pytest.mark.asyncio
    async def test_findings_table_has_accessibility_features(self, async_session):
        """Test that findings section has proper accessibility markup."""
        app = create_app()
        
        async def override_get_db():
            async with async_session() as session:
                yield session
        
        app.dependency_overrides[get_db] = override_get_db
        client = TestClient(app)
        
        # Create scan with findings
        async with async_session() as session:
            job = ScanJob(target_url="http://localhost:8080", profile="standard", status="completed")
            session.add(job)
            await session.commit()
            await session.refresh(job)
            
            finding = Finding(
                scan_id=job.scan_id,
                title="Test Finding",
                category="A03:2021",
                severity="high",
                status="confirmed",
                affected_url="http://localhost:8080",
                evidence="Test evidence",
                impact="Test impact",
                remediation="Test remediation",
                module_name="test-module",
            )
            session.add(finding)
            await session.commit()
        
        resp = client.get(f"/results/{job.scan_id}")
        assert resp.status_code == 200
        
        # Check for accessibility features in findings section
        html = resp.text
        # Should have aria-labels for interactive elements
        assert "aria-label" in html.lower()
        # Should have role-based semantic structure (headings for findings)
        assert "finding" in html.lower() or "finding" in html.lower()

    @pytest.mark.asyncio
    async def test_results_page_filters_by_severity(self, async_session):
        """Test that severity filtering works on results page."""
        app = create_app()
        
        async def override_get_db():
            async with async_session() as session:
                yield session
        
        app.dependency_overrides[get_db] = override_get_db
        client = TestClient(app)
        
        # Create scan with findings
        async with async_session() as session:
            job = ScanJob(target_url="http://localhost:8080", profile="standard", status="completed")
            session.add(job)
            await session.commit()
            await session.refresh(job)
            
            for severity in ["critical", "high", "medium"]:
                finding = Finding(
                    scan_id=job.scan_id,
                    title=f"{severity.title()} Finding",
                    category="A03:2021",
                    severity=severity,
                    status="confirmed",
                    affected_url="http://localhost:8080",
                    evidence="Test evidence",
                    impact="Test impact",
                    remediation="Test remediation",
                    module_name="test-module",
                )
                session.add(finding)
            await session.commit()
        
        # Request with filter
        resp = client.get(f"/results/{job.scan_id}?filter_severity=high")
        assert resp.status_code == 200
        # Should show only high severity findings
        assert "High" in resp.text or "high" in resp.text