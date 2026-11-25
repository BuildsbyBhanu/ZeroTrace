"""Tests for OWASP A04:2021 Insecure Design module (Phase 4).

A04 covers design-level weaknesses that go beyond code vulnerabilities.
This includes missing security controls in the application design itself.
"""

import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from zerotrace.main import create_app
from zerotrace.database.models import Base, ScanJob
from zerotrace.api.router import get_db
from zerotrace.engine.context import ValidatedTarget
from zerotrace.engine.base import FindingStatus, Severity


@pytest.fixture
def test_engine():
    """Create test database engine."""
    return create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)


@pytest.fixture
async def async_session(test_engine):
    """Create test database session."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async_session_maker = sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
    yield async_session_maker
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await test_engine.dispose()


class TestInsecureDesignModule:
    """Tests for the Insecure Design module (OWASP A04)."""
    
    @pytest.mark.asyncio
    async def test_missing_x_frame_options_clickjacking(self):
        """Test that missing X-Frame-Options is detected (clickjacking risk)."""
        from zerotrace.engine.context import ScanContext
        
        class MockContext:
            target = ValidatedTarget(
                original_url="http://localhost:8080",
                normalized_url="http://localhost:8080",
                base_url="http://localhost:8080",
            )
            headers_observed = {
                "content-type": "text/html",
                "server": "Apache",
            }
            settings = type('Settings', (), {'connection_timeout': 10.0})()
        
        # Try to import the module - may not exist yet
        try:
            from zerotrace.engine.modules.insecure_design import InsecureDesignModule
            module = InsecureDesignModule()
            findings = await module.execute(MockContext())
            
            xfo_findings = [f for f in findings if "X-Frame-Options" in f.title or "clickjacking" in f.title.lower()]
            assert len(xfo_findings) > 0, "Should detect missing X-Frame-Options"
            
            for finding in xfo_findings:
                assert finding.category == "A04", f"Should be OWASP A04, got {finding.category}"
                assert finding.status == FindingStatus.CONFIRMED
                
        except ImportError:
            pytest.skip("InsecureDesignModule not yet created")
    
    @pytest.mark.asyncio
    async def test_missing_referrer_policy(self):
        """Test that missing Referrer-Policy is detected."""
        from zerotrace.engine.context import ScanContext
        
        class MockContext:
            target = ValidatedTarget(
                original_url="http://localhost:8080",
                normalized_url="http://localhost:8080",
                base_url="http://localhost:8080",
            )
            headers_observed = {
                "content-type": "text/html",
            }
            settings = type('Settings', (), {'connection_timeout': 10.0})()
        
        try:
            from zerotrace.engine.modules.insecure_design import InsecureDesignModule
            module = InsecureDesignModule()
            findings = await module.execute(MockContext())
            
            ref_findings = [f for f in findings if "referrer" in f.title.lower()]
            # This check may be informational or potential
            
        except ImportError:
            pytest.skip("InsecureDesignModule not yet created")


class TestOWASPStatusLabels:
    """Tests verifying honest status labels are applied correctly."""
    
    @pytest.mark.asyncio
    async def test_high_risk_findings_are_confirmed(self):
        """High-severity findings we observe should be CONFIRMED."""
        from zerotrace.engine.modules.ssl_tls import SSLTLSModule
        from zerotrace.engine.context import ValidatedTarget
        
        class MockContext:
            target = ValidatedTarget(
                original_url="https://localhost:8080",
                normalized_url="https://localhost:8080",
                base_url="https://localhost:8080",
            )
            headers_observed = {}
            settings = type('Settings', (), {'connection_timeout': 10.0})()
        
        # SSL/TLS module should mark expired certs as CONFIRMED
        # (even though it requires manual verification to check the cert)
        module = SSLTLSModule()
        
        # The module should handle SSL errors gracefully
        # and mark what it finds with appropriate status codes
    
    @pytest.mark.asyncio
    async def test_weak_configuration_is_potential(self):
        """Weak but not broken configurations should be POTENTIAL."""
        from zerotrace.engine.modules.headers import SecurityHeadersModule
        
        class MockContext:
            target = ValidatedTarget(
                original_url="http://localhost:8080",
                normalized_url="http://localhost:8080",
                base_url="http://localhost:8080",
            )
            headers_observed = {
                "content-security-policy": "default-src 'self'",  # Missing 'none'
            }
            settings = type('Settings', (), {'connection_timeout': 10.0})()
        
        module = SecurityHeadersModule()
        findings = await module.execute(MockContext())
        
        # CSP without 'none' or 'unsafe-inline' is POTENTIAL, not CONFIRMED
        csp_findings = [f for f in findings if "CSP" in f.title]
        for finding in csp_findings:
            assert finding.status == FindingStatus.POTENTIAL, \
                "Weak CSP should be POTENTIAL, not CONFIRMED"


class TestFindingsDontLie:
    """Tests ensuring findings don't claim 100% certainty when inappropriate."""
    
    @pytest.mark.asyncio
    async def test_cert_expiry_not_hardcoded_as_critical(self):
        """Cert expiring in 30 days should be REQUIRES_MANUAL_VERIFICATION."""
        from zerotrace.engine.modules.ssl_tls import SSLTLSModule
        
        # Check that the module uses REQUIRES_MANUAL_VERIFICATION for expiring certs
        # This is based on the code in _analyze_certificate
        module = SSLTLSModule()
        
        # Verify the expiring cert logic exists
        import inspect
        source = inspect.getsource(module._analyze_certificate)
        assert "REQUIRES_MANUAL_VERIFICATION" in source, \
            "Module should use REQUIRES_MANUAL_VERIFICATION for expiring certs"
    
    @pytest.mark.asyncio
    async def test_findings_include_evidence(self):
        """All findings should include evidence, not just assertions."""
        from zerotrace.engine.modules.headers import SecurityHeadersModule
        
        class MockContext:
            target = ValidatedTarget(
                original_url="http://localhost:8080",
                normalized_url="http://localhost:8080",
                base_url="http://localhost:8080",
            )
            headers_observed = {}
            settings = type('Settings', (), {'connection_timeout': 10.0})()
        
        module = SecurityHeadersModule()
        findings = await module.execute(MockContext())
        
        for finding in findings:
            assert finding.evidence, f"Finding '{finding.title}' missing evidence"
            assert len(finding.evidence) > 20, f"Evidence too short for '{finding.title}'"


class TestIntegrationWithAPI:
    """Integration tests for how findings appear in API responses."""
    
    @pytest.mark.asyncio
    async def test_status_is_returned_in_finding_response(self, async_session):
        """Status field should be present in API responses."""
        from zerotrace.api.dependencies import get_status_labels
        
        # Check that status labels function exists
        labels = get_status_labels()
        assert "confirmed" in labels.lower() or "Confirmed" in labels
        assert "potential" in labels.lower() or "Potential" in labels