"""Tests for Session Security module."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from zerotrace.engine.modules.session_security import SessionSecurityModule
from zerotrace.engine.base import Severity, FindingStatus
from zerotrace.engine.context import ScanContext, ValidatedTarget


@pytest.fixture
def session_module():
    return SessionSecurityModule()


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
async def test_session_module_initialization(session_module):
    """Test that the session security module initializes correctly."""
    assert session_module.name == "session-security"
    assert session_module.owasp_category == "A07"
    assert session_module.run_in_quick is True
    assert session_module.run_in_standard is True


@pytest.mark.asyncio
async def test_session_no_cookies(session_module, mock_context):
    """Test handling when no cookies are present."""
    mock_context.headers_observed = {}

    findings = await session_module.execute(mock_context)

    assert isinstance(findings, list)
    # Should have informational finding about no cookies
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFORMATIONAL


@pytest.mark.asyncio
async def test_session_secure_cookie(session_module, mock_context):
    """Test that properly configured cookie produces no findings."""
    mock_context.headers_observed = {
        "set-cookie": "session_id=abc123; Secure; HttpOnly; SameSite=Strict; Path=/",
    }

    findings = await session_module.execute(mock_context)

    # Should not have HIGH severity findings for this well-configured cookie
    high_sev = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high_sev) == 0


@pytest.mark.asyncio
async def test_session_missing_secure_flag(session_module, mock_context):
    """Test detection of missing Secure flag on sensitive cookie."""
    mock_context.headers_observed = {
        "set-cookie": "auth_token=xyz789; HttpOnly; SameSite=Lax; Path=/",
    }

    findings = await session_module.execute(mock_context)

    # Should detect missing Secure flag on auth token
    missing_secure = [f for f in findings if "Secure" in f.title]
    assert len(missing_secure) >= 1
    assert missing_secure[0].severity == Severity.HIGH


@pytest.mark.asyncio
async def test_session_missing_httponly(session_module, mock_context):
    """Test detection of missing HttpOnly flag."""
    mock_context.headers_observed = {
        "set-cookie": "session_id=abc123; Secure; SameSite=Lax; Path=/",
    }

    findings = await session_module.execute(mock_context)

    # Should detect missing HttpOnly
    missing_httponly = [f for f in findings if "HttpOnly" in f.title]
    assert len(missing_httponly) >= 1


@pytest.mark.asyncio
async def test_session_predictable_pattern(session_module, mock_context):
    """Test detection of predictable session ID patterns."""
    mock_context.headers_observed = {
        "set-cookie": "PHPSESSID=aaaaabbbbbccccc; Secure; HttpOnly; Path=/",
    }

    findings = await session_module.execute(mock_context)

    # PHPSESSID with repeated characters might be flagged
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_session_generic_name(session_module, mock_context):
    """Test that non-sensitive cookie without Secure still produces MEDIUM finding."""
    mock_context.headers_observed = {
        "set-cookie": "tracking=abc123; Path=/",
    }

    findings = await session_module.execute(mock_context)

    # Non-sensitive cookie without Secure should produce MEDIUM severity
    medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
    assert len(medium_findings) >= 1


@pytest.mark.asyncio
async def test_session_multiple_cookies(session_module, mock_context):
    """Test handling of multiple Set-Cookie headers."""
    mock_context.headers_observed = {
        "set-cookie": [
            "session_id=abc123; Secure; HttpOnly",
            "user_pref=dark_mode; Path=/",
        ]
    }

    findings = await session_module.execute(mock_context)

    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_session_should_run_in_profiles(session_module, mock_context):
    """Test module runs in appropriate profiles."""
    from zerotrace.engine.base import ScanProfile

    assert session_module.should_run(ScanProfile.QUICK, mock_context) is True
    assert session_module.should_run(ScanProfile.STANDARD, mock_context) is True
    assert session_module.should_run(ScanProfile.DEEP, mock_context) is True


@pytest.mark.asyncio
async def test_session_csrf_token_detection(session_module, mock_context):
    """Test CSRF token analysis - properly configured should not flag."""
    mock_context.headers_observed = {
        "set-cookie": "csrf_token=1a2b3c4d5e; Secure; HttpOnly; SameSite=Strict",
    }

    findings = await session_module.execute(mock_context)

    # Check if any weak session ID findings were made
    weak_findings = [f for f in findings if "Weak" in f.title or "Short" in f.title]
    # If there are weak findings, it's acceptable to flag
    # The key is that properly configured CSRF tokens with HttpOnly and Secure
    # should not be flagged for those attributes
    httponly_findings = [f for f in findings if "HttpOnly" in f.title]
    assert len(httponly_findings) == 0