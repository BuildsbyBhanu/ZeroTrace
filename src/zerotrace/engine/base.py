"""Base classes and shared types for the scanning engine."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

    @property
    def priority(self) -> int:
        """Lower number = higher priority for sorting."""
        return {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}[self.value]

    @property
    def color(self) -> str:
        """CSS-friendly color name."""
        return {
            "critical": "#dc2626",
            "high": "#ea580c",
            "medium": "#ca8a04",
            "low": "#2563eb",
            "informational": "#6b7280",
        }[self.value]


class FindingStatus(str, Enum):
    """Classification status for a finding."""

    CONFIRMED = "confirmed"
    POTENTIAL = "potential"
    INFORMATIONAL = "informational"
    NOT_TESTED = "not_tested"
    REQUIRES_MANUAL_VERIFICATION = "requires_manual_verification"


class ScanProfile(str, Enum):
    """Available scan profiles."""

    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"
    CUSTOM = "custom"


@dataclass
class Finding:
    """A single vulnerability finding."""

    title: str
    category: str  # OWASP category, e.g., "A05"
    severity: Severity
    status: FindingStatus = FindingStatus.POTENTIAL
    affected_url: str = ""
    request: str = ""
    evidence: str = ""
    impact: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    module_name: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    finding_id: str = ""  # Will be populated when saved to database

    def to_dict(self) -> dict[str, Any]:
        """Convert Finding to a dictionary representation.
        
        Note: Empty strings are converted to None for nullable fields
        to ensure proper database storage.
        """
        def value_or_none(val: str) -> Optional[str]:
            return val if val else None
        
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity.value,
            "status": self.status.value,
            "affected_url": value_or_none(self.affected_url),
            "request": value_or_none(self.request),
            "evidence": value_or_none(self.evidence),
            "impact": value_or_none(self.impact),
            "remediation": value_or_none(self.remediation),
            "references": self.references or [],
            "module_name": self.module_name,
            "metadata": self.metadata or {},
        }


@dataclass
class ValidatedTarget:
    """A URL that has passed all validation checks."""

    original_url: str
    normalized_url: str
    base_url: str  # scheme + hostname + port
    resolved_ip: str = ""
    final_url: str = ""
    redirect_chain: list[str] = field(default_factory=list)


class BaseModule(ABC):
    """Abstract base class for all scanning modules."""

    name: str = "base"
    description: str = ""
    owasp_category: Optional[str] = None
    severity_base: Severity = Severity.INFORMATIONAL
    run_in_quick: bool = False
    run_in_standard: bool = True
    run_in_deep: bool = True

    @abstractmethod
    async def execute(self, context: "ScanContext") -> list[Finding]:
        """Run the module and return findings."""
        ...

    def should_run(self, profile: ScanProfile, context: "ScanContext") -> bool:
        """Determine if this module should execute for the given profile."""
        if profile == ScanProfile.QUICK:
            return self.run_in_quick
        if profile == ScanProfile.STANDARD:
            return self.run_in_standard
        if profile == ScanProfile.DEEP:
            return self.run_in_deep
        if profile == ScanProfile.CUSTOM:
            return context.custom_modules and self.name in context.custom_modules
        return False

    def _make_finding(
        self,
        title: str,
        category: str,
        severity: Severity,
        *,
        status: FindingStatus = FindingStatus.POTENTIAL,
        affected_url: str = "",
        request: str = "",
        evidence: str = "",
        impact: str = "",
        remediation: str = "",
        references: Optional[list[str]] = None,
        **kwargs: Any,
    ) -> Finding:
        """Factory helper to create a Finding with the module's defaults."""
        import hashlib
        # Generate a finding_id based on module + title + url for consistency
        finding_seed = f"{self.name}:{title}:{affected_url or kwargs.get('url', '')}"
        short_hash = hashlib.md5(finding_seed.encode()).hexdigest()[:3]
        auto_finding_id = f"ZT-2026-{int(short_hash, 16):03d}"
        
        return Finding(
            title=title,
            category=category,
            severity=severity,
            status=status,
            affected_url=affected_url or kwargs.pop("url", ""),
            request=request or kwargs.pop("request", ""),
            evidence=evidence,
            impact=impact,
            remediation=remediation,
            references=references or [],
            module_name=self.name,
            finding_id=auto_finding_id,
            **kwargs,
        )
