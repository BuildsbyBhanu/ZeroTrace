"""SQLAlchemy ORM models for ZeroTrace."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import Float, ForeignKey, JSON, DateTime, Integer, String, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""


class ScanJob(Base):
    """Represents a single scan job stored in the database."""

    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(36), unique=True, index=True, default=lambda: str(uuid.uuid4()))
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    profile: Mapped[str] = mapped_column(String(20), nullable=False, default="standard")  # quick, standard, deep
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")  # pending, running, completed, failed, cancelled
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[float] = mapped_column(Float, nullable=False, default=0)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationship to findings
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan_job", cascade="all, delete-orphan")

    def mark_running(self) -> None:
        self.status = "running"

    def mark_completed(self, duration: float, finding_count: int) -> None:
        self.status = "completed"
        self.completed_at = datetime.now(timezone.utc)
        self.duration_seconds = duration
        # Note: findings_count is not stored as it's calculated from the relationship

    def mark_failed(self, error: str) -> None:
        self.status = "failed"
        self.completed_at = datetime.now(timezone.utc)
        self.error_message = error

    def mark_cancelled(self) -> None:
        self.status = "cancelled"
        self.completed_at = datetime.now(timezone.utc)


class Finding(Base):
    """Stores an individual vulnerability finding linked to a scan job."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scan_jobs.scan_id"), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    category: Mapped[str] = mapped_column(String(20), nullable=False)  # OWASP category
    severity: Mapped[str] = mapped_column(String(20), nullable=False)  # critical, high, medium, low, informational
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="potential")
    affected_url: Mapped[str] = mapped_column(String(2048), nullable=True)
    request: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # HTTP request that triggered finding
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    impact: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    references: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    module_name: Mapped[str] = mapped_column(String(100), nullable=False)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    def __init__(self, **kwargs):
        """Initialize Finding, auto-generating finding_id if not provided."""
        # Auto-generate finding_id if not provided
        if 'finding_id' not in kwargs or not kwargs.get('finding_id'):
            import hashlib
            seed = f"{kwargs.get('title', '')}:{kwargs.get('affected_url', '')}:{id(object())}"
            short_hash = hashlib.md5(seed.encode()).hexdigest()[:3]
            kwargs['finding_id'] = f"ZT-2026-{int(short_hash, 16):03d}"
        super().__init__(**kwargs)

    # Relationship back to scan job
    scan_job: Mapped["ScanJob"] = relationship(back_populates="findings")

    @classmethod
    def from_finding(cls, scan_id: str, finding_data: dict) -> "Finding":
        """Create a Finding ORM object from a dict (e.g. from Finding.to_dict())."""
        # Generate finding_id if not present (format: ZT-YYYY-XXX)
        if "finding_id" not in finding_data or not finding_data.get("finding_id"):
            # Use a hash-based ID from title and affected_url for consistency
            import hashlib
            seed = f"{scan_id}:{finding_data.get('title', '')}:{finding_data.get('affected_url', '')}"
            short_hash = hashlib.md5(seed.encode()).hexdigest()[:3]
            finding_data["finding_id"] = f"ZT-2026-{int(short_hash, 16):03d}"
        
        finding_id = finding_data.get("finding_id", "")
        if not finding_id:
            # Generate fresh ID if somehow still empty
            import hashlib
            seed = f"{scan_id}:{finding_data.get('title', '')}:{finding_data.get('affected_url', '')}:{id(object())}"
            short_hash = hashlib.md5(seed.encode()).hexdigest()[:3]
            finding_id = f"ZT-2026-{int(short_hash, 16):03d}"
        
        def normalize_nullable(value: Any) -> Optional[str]:
            """Convert empty strings to None for nullable fields."""
            if value == "" or value == []:
                return None
            return value
        
        def normalize_optional_dict(value: Any) -> dict:
            """Ensure we always have a dict for metadata (not None)."""
            if value is None:
                return {}
            return value
        
        return cls(
            scan_id=scan_id,
            finding_id=finding_data.get("finding_id", ""),
            title=finding_data.get("title", ""),
            category=finding_data.get("category", ""),
            severity=finding_data.get("severity", "informational"),
            status=finding_data.get("status", "potential"),
            affected_url=normalize_nullable(finding_data.get("affected_url", "")),
            request=normalize_nullable(finding_data.get("request", "")),
            evidence=normalize_nullable(finding_data.get("evidence", "")),
            impact=normalize_nullable(finding_data.get("impact", "")),
            remediation=normalize_nullable(finding_data.get("remediation", "")),
            references=finding_data.get("references", []),
            module_name=finding_data.get("module_name", ""),
            metadata_=normalize_optional_dict(finding_data.get("metadata", {})),
        )
    
    def to_dict(self) -> dict:
        """Convert Finding to a dictionary representation."""
        return {
            "finding_id": self.finding_id,
            "scan_id": self.scan_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "status": self.status,
            "affected_url": self.affected_url,
            "request": self.request,
            "evidence": self.evidence,
            "impact": self.impact,
            "remediation": self.remediation,
            "references": self.references,
            "module_name": self.module_name,
            "metadata": self.metadata_,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
