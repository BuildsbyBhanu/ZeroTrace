"""PDF report generation using PyMuPDF."""

from __future__ import annotations

import pymupdf
from datetime import datetime
from typing import Optional


class PDFGenerator:
    """Generate PDF reports from scan data."""

    def __init__(self, page_width: float = 612, page_height: float = 792):
        """Initialize PDF generator with page dimensions in points (1 inch = 72 points)."""
        self.doc = pymupdf.Document()
        self.page_width = page_width
        self.page_height = page_height

    def _add_page(self, title: str) -> pymupdf.Page:
        """Create a new page and return it."""
        page = self.doc.new_page(width=self.page_width, height=self.page_height)
        return page

    def _draw_header(self, page: pymupdf.Page, scan_id: str, target_url: str, 
                     profile: str, status: str, duration: float, completed_at: Optional[str]) -> None:
        """Draw the report header with scan metadata."""
        margin = 50
        y = 50
        
        # Title - using default font (Helvetica)
        page.insert_text(
            (margin, y),
            "ZeroTrace Security Report",
            fontsize=24,
            color=(0.4, 0.4, 0.4)
        )
        y += 40
        
        # Authorization warning
        page.insert_text(
            (margin, y),
            "AUTHORIZATION NOTICE: Only scan systems you own or have explicit permission to test.",
            fontsize=10,
            color=(0.5, 0.3, 0)
        )
        y += 25
        
        # Scan metadata in a table-like layout
        metadata = [
            ("Scan ID:", scan_id[:36]),
            ("Target:", target_url[:50]),
            ("Profile:", profile),
            ("Status:", status.capitalize()),
            ("Duration:", f"{duration:.1f}s"),
        ]
        
        if completed_at:
            metadata.append(("Completed:", completed_at[:19]))
        
        x = margin
        for label, value in metadata:
            page.insert_text((x, y), label, fontsize=10, color=(0.3, 0.3, 0.3))
            page.insert_text((x + 80, y), value, fontsize=10)
            y += 18

    def _draw_summary(self, page: pymupdf.Page, findings: list, severity_counts: dict) -> None:
        """Draw the summary section with severity breakdown."""
        y = 180
        
        # Summary header
        page.insert_text((50, y), "Summary", fontsize=16)
        y += 30
        
        total = len(findings)
        if total > 0:
            # Severity counts
            y += 15
            
            severity_items = [
                ("Critical", severity_counts.get("critical", 0), (0.8, 0.1, 0.1)),  # Red
                ("High", severity_counts.get("high", 0), (0.7, 0.3, 0.1)),       # Orange
                ("Medium", severity_counts.get("medium", 0), (0.7, 0.7, 0.1)),   # Yellow
                ("Low", severity_counts.get("low", 0), (0.1, 0.4, 0.8)),         # Blue
                ("Informational", severity_counts.get("informational", 0), (0.2, 0.2, 0.2)),
            ]
            
            for label, count, color in severity_items:
                if count > 0:
                    page.insert_text((50, y), f"{label}: {count}", fontsize=12, color=color)
                    y += 18
                    
            y += 10
            page.insert_text((50, y), f"Total Findings: {total}", fontsize=14)
        else:
            page.insert_text((50, y), "No findings detected. The target appears well-configured.", 
                           fontsize=12, color=(0.1, 0.5, 0.1))
            y += 25

    def _draw_findings(self, page: pymupdf.Page, findings: list) -> None:
        """Draw each finding with details."""
        y = 250
        margin = 50
        
        if not findings:
            return
        
        # Findings header
        page.insert_text((margin, y), "Findings", fontsize=16)
        y += 30
        
        for i, finding in enumerate(findings):
            if y > self.page_height - 150:
                # Add new page if needed
                page = self.doc.new_page(width=self.page_width, height=self.page_height)
                y = margin
            
            # Finding title (bold)
            title = finding.get("title", "Untitled Finding")
            severity = finding.get("severity", "informational")
            page.insert_text((margin, y), f"{i+1}. {title}", fontsize=11)
            y += 15
            
            # Severity badge
            severity_colors = {
                "critical": (0.8, 0.1, 0.1),
                "high": (0.7, 0.3, 0.1),
                "medium": (0.7, 0.7, 0.1),
                "low": (0.1, 0.4, 0.8),
                "informational": (0.2, 0.2, 0.2),
            }
            color = severity_colors.get(severity, (0.5, 0.5, 0.5))
            
            # Category and module
            category = finding.get("category", "Unknown")
            module = finding.get("module_name", "Unknown")
            status = finding.get("status", "potential")
            page.insert_text((margin + 10, y), f"Severity: {severity.upper()} | Category: {category} | Module: {module}", 
                           fontsize=9, color=color)
            y += 18
            
            # Evidence
            evidence = finding.get("evidence", "")
            if evidence:
                page.insert_text((margin, y), "Evidence:", fontsize=9, color=(0.3, 0.3, 0.3))
                page.insert_text((margin + 80, y), evidence[:200] + "..." if len(evidence) > 200 else evidence, 
                               fontsize=9)
                y += 18
            
            # Impact
            impact = finding.get("impact", "")
            if impact:
                page.insert_text((margin, y), "Impact:", fontsize=9, color=(0.3, 0.3, 0.3))
                page.insert_text((margin + 80, y), impact[:200] + "..." if len(impact) > 200 else impact, 
                               fontsize=9)
                y += 18
            
            # Remediation
            remediation = finding.get("remediation", "")
            if remediation:
                page.insert_text((margin, y), "Remediation:", fontsize=9, color=(0.3, 0.3, 0.3))
                page.insert_text((margin + 100, y), remediation[:200] + "..." if len(remediation) > 200 else remediation, 
                               fontsize=9)
                y += 18
            
            y += 10
            y += 5  # Separator
    
    def _draw_footer(self, page: pymupdf.Page) -> None:
        """Draw the report footer."""
        page.insert_text(
            (50, self.page_height - 50),
            "Generated by ZeroTrace - Automated Web Application Security Assessment Platform",
            fontsize=9,
            color=(0.4, 0.4, 0.4)
        )

    def generate(
        self,
        scan_id: str,
        target_url: str,
        profile: str,
        status: str,
        started_at: Optional[str],
        completed_at: Optional[str],
        duration_seconds: float,
        findings: list,
    ) -> bytes:
        """Generate the complete PDF and return as bytes."""
        # Calculate severity counts
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
        }
        for f in findings:
            sev = f.get("severity", "informational")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        # Create first page
        page = self._add_page("Report")
        
        # Draw sections
        self._draw_header(page, scan_id, target_url, profile, status, duration_seconds, completed_at)
        self._draw_summary(page, findings, severity_counts)
        self._draw_findings(page, findings)
        self._draw_footer(page)
        
        # Save to bytes
        return self.doc.write()


def generate_pdf_report(scan_data: dict) -> bytes:
    """Generate a PDF report from scan data.
    
    Args:
        scan_data: Dictionary containing scan_id, target_url, profile, status,
                   started_at, completed_at, duration_seconds, and findings list.
    
    Returns:
        PDF content as bytes
    """
    generator = PDFGenerator()
    return generator.generate(
        scan_id=scan_data.get("scan_id", ""),
        target_url=scan_data.get("target_url", ""),
        profile=scan_data.get("profile", "standard"),
        status=scan_data.get("status", "unknown"),
        started_at=scan_data.get("started_at"),
        completed_at=scan_data.get("completed_at"),
        duration_seconds=scan_data.get("duration_seconds", 0),
        findings=scan_data.get("findings", []),
    )