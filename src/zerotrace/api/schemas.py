"""Pydantic schemas for ZeroTrace API."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class ScanCreate(BaseModel):
    """Request schema for creating a new scan."""

    model_config = ConfigDict(str_strip_whitespace=True)
    
    target_url: str = Field(..., description="Target URL to scan")
    profile: str = Field(..., description="Scan profile (quick/standard/deep)")
    save_report: bool = Field(False, description="Whether to save report to file")


class ScanResponse(BaseModel):
    """Response schema for a scan job."""

    model_config = ConfigDict(from_attributes=True)
    
    scan_id: str
    target_url: str
    profile: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    findings_count: int = 0
    duration_seconds: float = 0.0


class FindingResponse(BaseModel):
    """Response schema for a single finding."""

    model_config = ConfigDict(from_attributes=True)
    
    finding_id: str
    title: str
    category: str
    severity: str
    status: str
    affected_url: Optional[str] = None
    request: Optional[str] = None
    evidence: Optional[str] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None
    references: list[str] = Field(default_factory=list)
    module_name: str


class ScanDetailResponse(BaseModel):
    """Detailed response including all findings."""

    model_config = ConfigDict(from_attributes=True)
    
    scan_id: str
    target_url: str
    profile: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    findings_count: int = 0
    duration_seconds: float = 0.0
    error_message: Optional[str] = None
    findings: list[FindingResponse] = Field(default_factory=list)


class ProgressResponse(BaseModel):
    """Real-time progress response."""

    model_config = ConfigDict(from_attributes=True)
    
    scan_id: str
    status: str
    current_module: str = ""
    modules_total: int = 0
    modules_completed: int = 0
    findings_count: int = 0
    elapsed_seconds: float = 0.0
    error_message: Optional[str] = None
