"""Tests for Information Disclosure module."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from zerotrace.engine.modules.info_disclosure import InfoDisclosureModule
from zerotrace.engine.base import Severity, FindingStatus
from zerotrace.engine.context import ScanContext, ValidatedTarget


@pytest.fixture
def info_module():
    return InfoDisclosureModule()


@pytest.fixture
def mock_context():
    """Create a mock ScanContext for testing."""
    target = ValidatedTarget(
        original_url="http://localhost:8080",
        normalized_url="http://localhost:8080",
        base_url="http://localhost:8080",
    )
    return ScanContext(target=target)


@pytest.mark.asyncio
async def test_info_module_initialization(info_module):
    """Test that the info disclosure module initializes correctly."""
    assert info_module.name == "info-disclosure"
    assert info_module.owasp_category == "A05"
    assert info_module.run_in_quick is True
    assert info_module.run_in_standard is True


@pytest.mark.asyncio
async def test_info_module_executes_with_no_findings(info_module, mock_context):
    """Test module runs without errors when no disclosures found."""
    # Headers indicate clean response
    mock_context.headers_observed = {
        "server": "unknown",
        "content-type": "text/html",
    }

    findings = await info_module.execute(mock_context)

    assert isinstance(findings, list)
    # Should not crash - may have informational findings or none


@pytest.mark.asyncio
async def test_info_server_version_disclosed(info_module, mock_context):
    """Test detection of server version disclosure."""
    mock_context.headers_observed = {
        "server": "Apache/2.4.41 (Ubuntu)",
    }

    findings = await info_module.execute(mock_context)

    # Should detect server version disclosure
    assert len(findings) >= 1
    assert any("Server" in f.title or "Version" in f.title for f in findings)


@pytest.mark.asyncio
async def test_info_powered_by_header(info_module, mock_context):
    """Test detection of X-Powered-By header."""
    mock_context.headers_observed = {
        "x-powered-by": "PHP/7.4.3",
    }

    findings = await info_module.execute(mock_context)

    assert len(findings) >= 1
    assert any("PHP" in f.evidence or "powered-by" in f.title.lower() for f in findings)


@pytest.mark.asyncio
async def test_info_x_generator_header(info_module, mock_context):
    """Test detection of X-Generator header."""
    mock_context.headers_observed = {
        "x-generator": "WordPress 5.8.1",
    }

    findings = await info_module.execute(mock_context)

    assert len(findings) >= 1
    assert "generator" in findings[0].title.lower() or "wordpress" in findings[0].evidence.lower()


@pytest.mark.asyncio
async def test_info_no_server_header(info_module, mock_context):
    """Test no findings when no server header present."""
    mock_context.headers_observed = {
        "content-type": "text/html",
    }

    findings = await info_module.execute(mock_context)

    # Should not have any server-related findings when server header is missing
    server_findings = [f for f in findings if "Server" in f.title or "server" in f.title.lower()]
    assert len(server_findings) == 0


@pytest.mark.asyncio
async def test_info_should_run_in_profiles(info_module, mock_context):
    """Test module runs in appropriate profiles."""
    from zerotrace.engine.base import ScanProfile

    assert info_module.should_run(ScanProfile.QUICK, mock_context) is True
    assert info_module.should_run(ScanProfile.STANDARD, mock_context) is True
    assert info_module.should_run(ScanProfile.DEEP, mock_context) is True


@pytest.mark.asyncio
async def test_info_aspnet_header_detection(info_module, mock_context):
    """Test detection of ASP.NET version disclosure."""
    mock_context.headers_observed = {
        "x-aspnet-version": "4.0.30319",
        "x-aspnetmvc-version": "5.2",
    }

    findings = await info_module.execute(mock_context)

    # Should detect ASP.NET version via x-aspnet-version or x-aspnetmvc-version header
    aspnet_findings = [f for f in findings if "asp" in f.title.lower() or "aspnet" in f.evidence.lower()]
    assert len(aspnet_findings) >= 1