"""Scan orchestrator — coordinates module execution for a single scan job."""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine, Optional

from zerotrace.engine.base import Finding, ScanProfile, Severity
from zerotrace.engine.context import AuthCredentials, ScanContext
from zerotrace.engine.validator import URLValidator, ValidatedTarget
from zerotrace.logging_config import get_logger

logger = get_logger("orchestrator")


@dataclass
class ScanProgress:
    """Real-time progress update for a running scan."""

    scan_id: str
    status: str  # pending, running, completed, failed, cancelled
    current_module: str = ""
    modules_total: int = 0
    modules_completed: int = 0
    findings_count: int = 0
    message: str = ""
    elapsed_seconds: float = 0.0


@dataclass
class ScanResult:
    """Final result of a completed scan."""

    scan_id: str
    target_url: str
    profile: ScanProfile
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    findings: list[Finding] = field(default_factory=list)
    duration_seconds: float = 0.0
    error: Optional[str] = None


class ScanOrchestrator:
    """Coordinates module execution within a single scan job."""

    def __init__(self) -> None:
        self._modules: list = []
        self._validator = URLValidator()
        self._populate_default_modules()
    
    def _populate_default_modules(self) -> None:
        """Populate modules from the default registry."""
        from zerotrace.engine.modules import MODULE_REGISTRY
        for module_class in MODULE_REGISTRY:
            self.register_module(module_class())

    def register_module(self, module) -> None:
        """Register a scanning module."""
        self._modules.append(module)

    async def run(
        self,
        target_url: str,
        profile: ScanProfile,
        *,
        credentials: Optional[AuthCredentials] = None,
        custom_modules: Optional[list[str]] = None,
        progress_callback: Optional[Callable[[ScanProgress], Coroutine[Any, Any, None]]] = None,
    ) -> ScanResult:
        """Execute a full scan against the target URL."""

        scan_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc)
        logger.info("Scan started", extra={"scan_id": scan_id, "target": target_url, "profile": profile.value})

        progress = ScanProgress(
            scan_id=scan_id,
            status="running",
            modules_total=len(self._modules),
        )

        try:
            # Phase 1: Validate target
            validated_target = await self._validator.validate(target_url)
            context = ScanContext(
                target=validated_target,
                credentials=credentials,
                custom_modules=custom_modules or [],
            )

            if progress_callback:
                await progress_callback(ScanProgress(
                    scan_id=scan_id, status="running",
                    current_module="validation",
                    message=f"Validated target: {validated_target.normalized_url}",
                ))

            # Phase 2: Select active modules
            active_modules = [m for m in self._modules if m.should_run(profile, context)]
            progress.modules_total = len(active_modules)

            logger.info(f"Running {len(active_modules)} modules", extra={"scan_id": scan_id})

            # Phase 3: Execute modules sequentially based on profile
            for module in active_modules:
                module_name = module.name
                try:
                    if progress_callback:
                        await progress_callback(ScanProgress(
                            scan_id=scan_id, status="running",
                            current_module=module_name,
                            modules_completed=context.request_count,
                            findings_count=len(context.findings),
                            message=f"Running: {module_name}",
                        ))

                    findings = await module.execute(context)
                    context.findings.extend(findings)

                    if progress_callback:
                        await progress_callback(ScanProgress(
                            scan_id=scan_id, status="running",
                            current_module=module_name,
                            modules_completed=len(context.findings),
                            findings_count=len(context.findings),
                            message=f"{module_name}: {len(findings)} findings",
                        ))

                except Exception as exc:
                    logger.error(f"Module {module_name} failed", extra={"scan_id": scan_id, "error": str(exc)})
                    context.errors.append({"module": module_name, "error": str(exc)})

            # Phase 4: Execute deep-only modules concurrently (optimized parallel execution)
            deep_modules = [m for m in active_modules if m.run_in_deep and not m.run_in_standard and not m.run_in_quick]
            
            if deep_modules:
                async def _run_deep(module):
                    try:
                        return await module.execute(context)
                    except Exception as exc:
                        logger.error(f"Deep module {module.name} failed", extra={"error": str(exc)})
                        context.errors.append({"module": module.name, "error": str(exc)})
                        return []

                tasks = [asyncio.create_task(_run_deep(m)) for m in deep_modules]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for result in results:
                    if isinstance(result, list):
                        context.findings.extend(result)

            # Phase 5: Post-processing
            deduped = self._deduplicate(context.findings)
            context.findings = deduped

            completed_at = datetime.now(timezone.utc)
            duration = (completed_at - started_at).total_seconds()

            result = ScanResult(
                scan_id=scan_id,
                target_url=target_url,
                profile=profile,
                status="completed",
                started_at=started_at,
                completed_at=completed_at,
                findings=context.findings,
                duration_seconds=duration,
            )

            logger.info(
                "Scan completed",
                extra={"scan_id": scan_id, "findings": len(context.findings), "duration": duration},
            )

            if progress_callback:
                await progress_callback(ScanProgress(
                    scan_id=scan_id, status="completed",
                    findings_count=len(context.findings),
                    message=f"Scan complete: {len(context.findings)} findings in {duration:.1f}s",
                ))

            return result

        except Exception as exc:
            logger.error("Scan failed", extra={"scan_id": scan_id, "error": str(exc)})
            return ScanResult(
                scan_id=scan_id,
                target_url=target_url,
                profile=profile,
                status="failed",
                started_at=started_at,
                error=str(exc),
            )

    def _deduplicate(self, findings: list) -> list:
        """Remove duplicate findings based on title + affected URL."""
        seen = set()
        unique = []
        for f in findings:
            key = (f.title, f.affected_url)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique


# Module-level singleton
orchestrator = ScanOrchestrator()
