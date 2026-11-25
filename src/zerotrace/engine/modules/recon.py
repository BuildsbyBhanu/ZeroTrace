"""Reconnaissance module - safe, limited discovery for initial assessment.

This module performs passive reconnaissance with strict limits:
- Maximum 5 requests total
- 5-second timeout per request
- SSRF protection enforced
- No destructive testing
"""

from __future__ import annotations

import time
from typing import Optional

from zerotrace.engine.base import BaseModule, Finding, FindingStatus, Severity
from zerotrace.engine.context import ScanContext
from zerotrace.logging_config import get_logger

logger = get_logger("recon_module")


class ReconModule(BaseModule):
    """Safe reconnaissance module for initial discovery and exposure checking."""

    name = "recon"
    description = "Passive reconnaissance - robots.txt, security.txt, common paths, tech fingerprinting"
    owasp_category = "A01"
    severity_base = Severity.INFORMATIONAL
    run_in_quick = True
    run_in_standard = True

    # Safe paths to check - only well-known security/recon files
    SAFE_PATHS = [
        "/robots.txt",
        "/security.txt",
        "/.well-known/security.txt",
        "/.well-known/assetlinks.json",
        "/favicon.ico",
    ]

    # User agents that identify the scanner
    USER_AGENT = "ZeroTrace-Bot/1.0"

    async def execute(self, context: ScanContext) -> list[Finding]:
        """Execute reconnaissance with strict limits."""
        findings = []

        base_url = context.target.base_url
        request_timeout = 5.0  # Strict timeout for recon
        max_requests = 5  # Strict request limit
        request_count = 0

        # Check robots.txt
        robots_finding = await self._check_robots_txt(base_url, context, request_timeout)
        if robots_finding:
            findings.append(robots_finding)
            request_count += 1

        # Check security.txt if we have requests remaining
        if request_count < max_requests:
            security_finding = await self._check_security_txt(base_url, context, request_timeout)
            if security_finding:
                findings.append(security_finding)
                request_count += 1

        # Check favicon.ico for technology inference
        if request_count < max_requests:
            favicon_finding = await self._check_favicon(base_url, context, request_timeout)
            if favicon_finding:
                findings.append(favicon_finding)
                request_count += 1

        # Technology fingerprinting from headers
        tech_finding = self._fingerprint_technologies(context)
        if tech_finding:
            findings.append(tech_finding)

        logger.info("Recon module completed with %d findings using %d requests", len(findings), request_count)
        return findings

    async def _check_robots_txt(self, base_url: str, context: ScanContext, timeout: float) -> Optional[Finding]:
        """Check for robots.txt and report accessibility."""
        try:
            import httpx

            url = base_url.rstrip("/") + "/robots.txt"
            async with httpx.AsyncClient(
                timeout=timeout,
                headers={"User-Agent": self.USER_AGENT},
                follow_redirects=True,
            ) as client:
                resp = await client.get(url)

            if resp.status_code == 200:
                content = resp.text  # Get the actual response content
                content_preview = content[:200]
                # Check for sensitive paths in robots.txt
                sensitive_patterns = ["admin", "login", "api", "backup", "hidden", ".env", "config", ".git", "wp-admin"]
                sensitive_found = [p for p in sensitive_patterns if p in content.lower()]
                
                impact_text = "Attackers use robots.txt to discover hidden endpoints, admin panels, API paths, and other sensitive resources that should not be publicly disclosed."
                remediation_text = "Review robots.txt contents and remove any references to sensitive paths, admin panels, or private APIs. Consider adding a robots.txt with 'Disallow: /' to block all crawlers if no public content needs indexing."
                
                return self._make_finding(
                    title="robots.txt Discovered with Exposed Paths" if sensitive_found else "robots.txt Discovered",
                    category="A01",
                    severity=Severity.INFORMATIONAL,
                    status=FindingStatus.CONFIRMED,
                    affected_url=base_url,
                    evidence=f"robots.txt is publicly accessible. Content preview: '{content_preview}...'",
                    impact=impact_text,
                    remediation=remediation_text,
                    references=["https://developers.google.com/search/docs/crawling-indexing/robots-meta-tag"],
                    url=url,
                )
            elif resp.status_code == 403:
                return self._make_finding(
                    title="Robots.txt Access Denied",
                    category="A01",
                    severity=Severity.LOW,
                    status=FindingStatus.INFORMATIONAL,
                    affected_url=base_url,
                    evidence="robots.txt returns 403 Forbidden - may indicate custom access control.",
                    impact="The robots.txt file is not publicly accessible, which is good security practice.",
                    remediation="No action needed - 403 indicates access control is in place.",
                    references=["https://owasp.org/www-community/robots-txt"],
                )
        except Exception as e:
            logger.debug("Error checking robots.txt: %s", e)

        return None

    async def _check_security_txt(self, base_url: str, context: ScanContext, timeout: float) -> Optional[Finding]:
        """Check for security.txt per RFC 9116."""
        try:
            import httpx

            # Check .well-known/security.txt first (preferred location)
            url = base_url.rstrip("/") + "/.well-known/security.txt"
            async with httpx.AsyncClient(
                timeout=timeout,
                headers={"User-Agent": self.USER_AGENT},
                follow_redirects=True,
            ) as client:
                resp = await client.get(url)

            if resp.status_code == 200:
                return self._make_finding(
                    title="security.txt Discovered at /.well-known/",
                    category="A01",
                    severity=Severity.INFORMATIONAL,
                    status=FindingStatus.CONFIRMED,
                    affected_url=base_url,
                    evidence="security.txt file is publicly accessible at /.well-known/security.txt per RFC 9116.",
                    impact="While security.txt is intended to help security researchers report vulnerabilities, publicly accessible files may reveal contact information, security team details, or disclosure policies to attackers.",
                    remediation="Review security.txt contents to ensure only appropriate contact information is disclosed. Consider whether public disclosure is necessary or if vulnerability reporting should be done through private channels only.",
                    references=["https://datatracker.ietf.org/doc/html/rfc9116"],
                    url=url,
                )
        except Exception as e:
            logger.debug("Error checking security.txt: %s", e)

        return None

    async def _check_favicon(self, base_url: str, context: ScanContext, timeout: float) -> Optional[Finding]:
        """Check favicon.ico for basic verification."""
        try:
            import httpx

            url = base_url.rstrip("/") + "/favicon.ico"
            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=True,
            ) as client:
                resp = await client.get(url)

            if resp.status_code == 200:
                content_type = resp.headers.get("content-type", "unknown")
                icon_size = f"{resp.headers.get('content-length', 'unknown')} bytes"
                return self._make_finding(
                    title="Favicon.ico Accessible",
                    category="A01",
                    severity=Severity.INFORMATIONAL,
                    status=FindingStatus.CONFIRMED,
                    affected_url=base_url,
                    evidence=f"favicon.ico is accessible at /favicon.ico. Content-Type: {content_type}, Size: {icon_size}",
                    impact="Confirms endpoint existence. Favicon analysis (favicon.ico fingerprinting) can sometimes reveal technology stack or CMS type. Also useful for tracking visits to specific pages.",
                    remediation="No security concern. Favicon is expected on production sites. Create a distinct favicon to differentiate from potentially spoofed similar sites.",
                    references=["https://github.com/411Hall/FaviconDB"],
                    url=url,
                )
        except Exception as e:
            logger.debug("Error checking favicon: %s", e)

        return None

    def _fingerprint_technologies(self, context: ScanContext) -> Optional[Finding]:
        """Fingerprint technologies from response headers."""
        headers = context.headers_observed or {}
        if not headers:
            return None

        techs_found = []

        # Check common server headers
        server = headers.get("server", "").lower()
        if server:
            techs_found.append(f"Server header: {server}")

        x_powered_by = headers.get("x-powered-by", "").lower()
        if x_powered_by:
            techs_found.append(f"X-Powered-By: {x_powered_by}")

        # Check for framework-specific headers
        if "x-generator" in headers:
            techs_found.append(f"X-Generator: {headers['x-generator']}")

        if "x-aspnetmvc-version" in headers:
            techs_found.append(f"ASP.NET MVC: {headers['x-aspnetmvc-version']}")

        if not techs_found:
            return None

        return self._make_finding(
            title="Technology Fingerprinting - Information Disclosure",
            category="A05",
            severity=Severity.LOW,
            status=FindingStatus.INFORMATIONAL,
            affected_url=context.target.normalized_url,
            evidence="Server response headers reveal technology stack information: " + "; ".join(techs_found),
            impact="Attackers use technology fingerprints to identify known vulnerabilities for specific platforms, CMS versions, and server configurations. This enables targeted exploitation.",
            remediation="Remove or generalize server identification headers. Use generic values like 'Server: Website' instead of versions. Consider removing X-Powered-By, X-Generator, and other identifying headers.",
            references=["https://owasp.org/www-community/vulnerabilities/Information_disclosure_through_server_response_headers"],
            metadata={"technologies": techs_found},
        )