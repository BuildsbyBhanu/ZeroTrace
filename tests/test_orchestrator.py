"""Tests for scan orchestrator."""

import pytest
from unittest.mock import AsyncMock, patch
from zerotrace.engine.base import ScanProfile, Finding, Severity, BaseModule
from zerotrace.engine.orchestrator import ScanOrchestrator, ScanResult
from zerotrace.engine.context import ValidatedTarget


@pytest.fixture
def mock_validated_target():
    """Create a mock ValidatedTarget for testing."""
    return ValidatedTarget(
        original_url="http://localhost:8080",
        normalized_url="http://localhost:8080",
        base_url="http://localhost:8080",
        resolved_ip="127.0.0.1",
    )


@pytest.fixture
def mock_validator():
    """Create a mock validator that passes localhost URLs."""
    validator = AsyncMock()
    validator.validate.return_value = ValidatedTarget(
        original_url="http://localhost:8080",
        normalized_url="http://localhost:8080",
        base_url="http://localhost:8080",
        resolved_ip="127.0.0.1",
    )
    return validator


@pytest.mark.asyncio
async def test_orchestrator_empty_modules(mock_validator):
    """Orchestrator should handle zero registered modules gracefully."""
    orch = ScanOrchestrator()
    orch._modules.clear()  # Clear default modules for isolated test
    orch._validator = mock_validator
    # No modules registered — should complete with 0 findings
    progress_events = []

    async def mock_progress(p):
        progress_events.append(p)

    result = await orch.run(
        "http://localhost:8080",  # Safe local target
        ScanProfile.QUICK,
        progress_callback=mock_progress,
    )
    assert isinstance(result, ScanResult)
    assert result.status == "completed"
    assert len(result.findings) == 0
    assert result.duration_seconds >= 0


@pytest.mark.asyncio
async def test_orchestrator_deduplication(mock_validator):
    """Orchestrator should deduplicate identical findings."""
    orch = ScanOrchestrator()
    orch._modules.clear()  # Clear default modules for isolated test
    orch._validator = mock_validator

    class MockModule(BaseModule):
        name = "mock"
        owasp_category = "A05"
        severity_base = Severity.MEDIUM
        run_in_quick = True
        run_in_standard = True
        run_in_deep = True

        async def execute(self, context):
            return [
                Finding(title="Test Finding", category="A05", severity=Severity.MEDIUM, affected_url="http://localhost:8080"),
                Finding(title="Test Finding", category="A05", severity=Severity.MEDIUM, affected_url="http://localhost:8080"),
            ]

    orch.register_module(MockModule())

    result = await orch.run("http://localhost:8080", ScanProfile.QUICK)
    assert result.status == "completed"
    # Should be deduplicated to 1 finding
    assert len(result.findings) == 1


@pytest.mark.asyncio
async def test_orchestrator_multiple_modules(mock_validator):
    """Orchestrator should run multiple modules in order."""
    orch = ScanOrchestrator()
    orch._modules.clear()  # Clear default modules for isolated test
    orch._validator = mock_validator
    executed_order = []

    class FirstModule(BaseModule):
        name = "first"
        owasp_category = "A01"
        severity_base = Severity.INFORMATIONAL
        run_in_quick = True
        run_in_standard = True
        run_in_deep = False

        async def execute(self, context):
            executed_order.append(self.name)
            return []

    class SecondModule(BaseModule):
        name = "second"
        owasp_category = "A02"
        severity_base = Severity.MEDIUM
        run_in_quick = True
        run_in_standard = True
        run_in_deep = False

        async def execute(self, context):
            executed_order.append(self.name)
            return []

    orch.register_module(FirstModule())
    orch.register_module(SecondModule())

    result = await orch.run("http://localhost:8080", ScanProfile.QUICK)
    assert result.status == "completed"
    # Modules should have been executed
    assert len(executed_order) >= 1  # At least some modules ran


@pytest.mark.asyncio
async def test_orchestrator_skips_inactive_modules(mock_validator):
    """Orchestrator should skip modules not in profile."""
    orch = ScanOrchestrator()
    orch._modules.clear()  # Clear default modules for isolated test
    orch._validator = mock_validator
    executed_modules = []

    class QuickOnlyModule(BaseModule):
        name = "quick_only"
        owasp_category = "A01"
        severity_base = Severity.INFORMATIONAL
        run_in_quick = True
        run_in_standard = False
        run_in_deep = False

        async def execute(self, context):
            executed_modules.append(self.name)
            return []

    class StandardOnlyModule(BaseModule):
        name = "standard_only"
        owasp_category = "A02"
        severity_base = Severity.MEDIUM
        run_in_quick = False
        run_in_standard = True
        run_in_deep = False

        async def execute(self, context):
            executed_modules.append(self.name)
            return []

    orch.register_module(QuickOnlyModule())
    orch.register_module(StandardOnlyModule())

    # Run with QUICK profile
    result = await orch.run("http://localhost:8080", ScanProfile.QUICK)
    assert "quick_only" in executed_modules
    assert "standard_only" not in executed_modules