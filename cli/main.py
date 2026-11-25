"""CLI entry point for ZeroTrace using Typer."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

# Force UTF-8 mode for Windows console compatibility
if sys.platform == "win32":
    os.environ["PYTHONUTF8"] = "1"
    # Reconfigure stdout/stderr to UTF-8 if possible
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except (AttributeError, LookupError):
        pass

from zerotrace.config import settings
from zerotrace.engine.base import ScanProfile, Severity
from zerotrace.engine.orchestrator import ScanOrchestrator
from zerotrace.logging_config import setup_logging, get_logger

app = typer.Typer(
    name="zerotrace",
    help="ZeroTrace — Automated Web Application Security Assessment Platform",
    add_completion=False,
)

# Create console with UTF-8 encoding for Windows compatibility
# Note: encoding parameter not supported in all Rich versions, UTF-8 mode set via PYTHONUTF8 env var
console = Console(force_terminal=False)
orchestrator = ScanOrchestrator()


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context, version: bool = typer.Option(False, "--version", "-v")):
    if version:
        console.print(f"[bold cyan]ZeroTrace[/bold cyan] v{settings.app_version}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        app.print_help(ctx)


@app.command()
def scan(
    url: Annotated[str, typer.Argument(help="Target URL to scan (use only authorized/local targets)")],
    profile: Annotated[
        str,
        typer.Option("--profile", "-p", help="Scan profile to use"),
    ] = "standard",
    output: Annotated[
        str,
        typer.Option("--output", "-o", help="Output format for report"),
    ] = "json",
    save_report: Annotated[
        bool,
        typer.Option("--save", "-s", help="Save report to file"),
    ] = False,
):
    """Run a security assessment against a target URL.

⚠️ WARNING: Only scan systems you own or have explicit permission to test.
Unauthorized security scanning is illegal and unethical.
"""
    setup_logging()
    logger = get_logger("cli")

    # Validate input
    if not url.startswith(("http://", "https://")):
        console.print(f"[red]Error:[/red] URL must start with http:// or https:// — got: {url}")
        raise typer.Exit(code=1)

    profile_enum = ScanProfile(profile.lower())
    console.print(f"\n[bold]ZeroTrace Scanner[/bold]")
    console.print(f"Target:  [cyan]{url}[/cyan]")
    console.print(f"Profile: [yellow]{profile.value}[/yellow]")
    console.print("-" * 50)

    async def _run():
        result = await orchestrator.run(url, profile_enum)
        return result

    result = asyncio.run(_run())

    if result.status == "failed":
        console.print(f"\n[red]✗ Scan failed:[/red] {result.error}")
        raise typer.Exit(code=1)

    # Display summary
    console.print(f"\n[green]✓ Scan completed[/green] in {result.duration_seconds:.1f}s")
    console.print(f"Findings: [bold]{len(result.findings)}[/bold]")

    # Group by severity
    severity_counts = {}
    for f in result.findings:
        sev = f.severity.value if hasattr(f, 'severity') else str(type(f).__name__)
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    if severity_counts:
        table = Table(title="Findings by Severity", show_header=True, header_style="bold magenta")
        table.add_column("Severity", style="bold")
        table.add_column("Count")
        for sev in ["critical", "high", "medium", "low", "informational"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                table.add_row(sev.capitalize(), str(count))
        console.print(table)

    # Output results
    findings_data = []
    for f in result.findings:
        if hasattr(f, 'to_dict'):
            findings_data.append(f.to_dict())
        else:
            findings_data.append({k: str(v) if not isinstance(v, (str, int, float, bool, type(None))) else v
                                  for k, v in vars(f).items()})

    if output == "json":
        print(json.dumps({"scan_id": result.scan_id, "findings": findings_data,
                          "duration": result.duration_seconds, "target": url}, indent=2))
    elif output in ("html", "pdf"):
        if save_report:
            output_path = Path("reports") / f"report-{result.scan_id}.{output}"
            output_path.parent.mkdir(exist_ok=True)
            content = json.dumps(findings_data, indent=2)
            output_path.write_text(content)
            console.print(f"\n[dim]Report saved to: {output_path}[/dim]")

    console.print()


@app.command()
def validate(url: str):
    """Validate a URL for safe scanning (check SSRF, private IPs, etc.)."""
    from zerotrace.engine.validator import URLValidator
    validator = URLValidator()

    is_safe, message = validator.is_safe_target(url)
    if is_safe:
        console.print(f"[green]OK[/green] {url} appears safe to scan")
    else:
        console.print(f"[red]NO[/red] {url} — {message}")
        raise typer.Exit(code=1)


@app.command()
def history(
    limit: Annotated[int, typer.Option("--limit", "-n", help="Number of scans to show")] = 10,
):
    """View scan history from the SQLite database.

    Shows previously completed scans with their IDs, targets, status, and findings count.
    """
    import asyncio
    from datetime import datetime

    # Import database session
    from zerotrace.database import get_async_session, init_db
    from zerotrace.database.models import ScanJob, Finding
    from sqlalchemy import func

    async def _get_history():
        # Ensure database is initialized
        await init_db()
        
        async with get_async_session() as session:
            from sqlalchemy import select, desc, func
            
            # Get scan jobs
            stmt = select(ScanJob).order_by(desc(ScanJob.started_at)).limit(limit)
            result = await session.execute(stmt)
            jobs = result.scalars().all()
            
            # Count findings for each job (avoids lazy loading)
            for job in jobs:
                count_stmt = select(func.count(Finding.id)).where(Finding.scan_id == job.scan_id)
                count_result = await session.execute(count_stmt)
                job.findings_count = count_result.scalar()
            
            return jobs

    try:
        scans = asyncio.run(_get_history())
    except Exception as e:
        console.print(f"[red]Error loading scan history:[/red] {e}")
        raise typer.Exit(code=1)

    if not scans:
        console.print("[yellow]No scans found in history.[/yellow]")
        return

    table = Table(title="Scan History", show_header=True, header_style="bold magenta")
    table.add_column("Scan ID", style="bold", max_width=36)
    table.add_column("Target", style="cyan", max_width=40)
    table.add_column("Status", style="yellow")
    table.add_column("Findings", justify="right", style="")
    table.add_column("Duration", justify="right", style="")

    for scan in scans:
        duration = f"{scan.duration_seconds:.1f}s" if scan.duration_seconds else "-"
        # Use pre-computed findings_count to avoid lazy loading
        findings_count = getattr(scan, 'findings_count', 0)
        table.add_row(
            str(scan.scan_id)[:36],
            str(scan.target_url)[:40],
            scan.status,
            str(findings_count),
            duration,
        )

    console.print()
    console.print(table)


@app.command(name="report")
def report(
    scan_id: Annotated[str, typer.Argument(help="Scan ID to export")],
    format: Annotated[str, typer.Option("--format", "-f", help="Output format: json or html")] = "json",
):
    """Export a scan report by ID.

    Generates a report file for a completed scan in the specified format.
    """
    import asyncio
    from jinja2 import Environment, FileSystemLoader
    from pathlib import Path

    from zerotrace.database import get_async_session
    from zerotrace.database.models import ScanJob, Finding

    template_dir = Path(__file__).parent.parent / "src" / "zerotrace" / "templates"

    async def _get_scan():
        async with get_async_session() as session:
            from sqlalchemy import select
            stmt = select(ScanJob).where(ScanJob.scan_id == scan_id)
            result = await session.execute(stmt)
            job = result.scalar_one_or_none()
            if job:
                # Load findings
                from sqlalchemy import select
                findings_stmt = select(Finding).where(Finding.scan_id == scan_id)
                findings_result = await session.execute(findings_stmt)
                job.findings = findings_result.scalars().all()
            return job

    try:
        job = asyncio.run(_get_scan())
    except Exception as e:
        console.print(f"[red]Error loading scan:[/red] {e}")
        raise typer.Exit(code=1)

    if not job:
        console.print(f"[red]Scan not found with ID:[/red] {scan_id}")
        raise typer.Exit(code=1)

    if job.status != "completed":
        console.print(f"[red]Cannot export scan with status:[/red] {job.status}")
        raise typer.Exit(code=1)

    # Load findings
    findings_data = []
    for f in job.findings:
        findings_data.append(f.to_dict() if hasattr(f, 'to_dict') else {
            "title": f.title,
            "severity": f.severity.value if hasattr(f, 'severity') else str(f.severity),
            "status": f.status.value if hasattr(f, 'status') else str(f.status),
            "category": f.category,
            "module_name": f.module_name,
            "affected_url": f.affected_url,
            "evidence": f.evidence,
            "impact": f.impact,
            "remediation": f.remediation,
        })

    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)
    output_path = reports_dir / f"report-{scan_id}.{format}"

    if format == "json":
        output_path.write_text(json.dumps({
            "scan_id": scan_id,
            "target_url": job.target_url,
            "profile": job.profile,
            "status": job.status,
            "started_at": job.started_at.isoformat() if job.started_at else None,
            "completed_at": job.completed_at.isoformat() if job.completed_at else None,
            "duration_seconds": job.duration_seconds,
            "findings_count": len(findings_data),
            "findings": findings_data,
        }, indent=2))
    elif format == "html":
        env = Environment(loader=FileSystemLoader(str(template_dir)))
        template = env.get_template("report.html")
        html = template.render(
            scan_id=scan_id,
            target_url=job.target_url,
            profile=job.profile,
            status=job.status,
            started_at=job.started_at.isoformat() if job.started_at else None,
            duration_seconds=job.duration_seconds,
            findings=findings_data,
            severity_labels={
                "critical": "Confirmed Vulnerability",
                "high": "Confirmed Vulnerability",
                "medium": "Potential Vulnerability",
                "low": "Potential Vulnerability",
                "informational": "Informational Finding",
            },
            status_labels={
                "confirmed": "Confirmed",
                "potential": "Potential",
                "informational": "Informational",
                "requires_manual_verification": "Requires Manual Verification",
            },
        )
        output_path.write_text(html)
    else:
        console.print(f"[red]Invalid format:[/red] {format}. Use json or html.")
        raise typer.Exit(code=1)

    console.print(f"[green]Report saved to:[/green] {output_path}")


if __name__ == "__main__":
    app()
