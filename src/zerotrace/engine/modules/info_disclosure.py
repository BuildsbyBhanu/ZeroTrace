"""Information disclosure analysis module.

Checks for server-side information leakage through headers, error pages,
and common security configuration weaknesses.
"""

from __future__ import annotations

import re
from typing import Optional

from zerotrace.engine.base import BaseModule, FindingStatus, Severity
from zerotrace.engine.context import ScanContext


# Patterns that indicate potential information disclosure
SERVER_VERSION_PATTERNS = [
    re.compile(r"Apache/(\d+\.\d+\.\d+)", re.IGNORECASE),
    re.compile(r"Nginx/(\d+\.\d+\.\d+)", re.IGNORECASE),
    re.compile(r"IIS/(\d+\.\d+)", re.IGNORECASE),
    re.compile(r"nginx/(\d+\.\d+\.\d+)", re.IGNORECASE),
]

FRAMEWORK_INDICATORS = {
    "x-powered-by": ["php", "asp.net", "express", "nodejs"],
    "server": ["apache", "nginx", "iis", "cloudflare"],
}

INTERNAL_PATH_PATTERNS = [
    re.compile(r"/(tmp|temp|vendor|node_modules|\.git|\.svn)"),
    re.compile(r"C:\\|D:\\|/home/|/var/www"),
]

DEBUG_INDICATORS = [
    re.compile(r"debug[=:]\s*true", re.IGNORECASE),
    re.compile(r"show_errors\s*=\s*on", re.IGNORECASE),
    re.compile(r"django.*debug", re.IGNORECASE),
    re.compile(r"flask.*debug", re.IGNORECASE),
]


class InfoDisclosureModule(BaseModule):
    """Analyzes response for information disclosure vulnerabilities."""

    name = "info-disclosure"
    description = "Checks for server version disclosure, debug mode, internal path leaks"
    owasp_category = "A05"
    severity_base = Severity.LOW
    run_in_quick = True
    run_in_standard = True
    run_in_deep = True

    async def execute(self, context: ScanContext) -> list:
        """Execute information disclosure checks."""
        findings = []
        headers = context.headers_observed or {}

        # Check server header for version disclosure
        server_finding = self._check_server_version(headers, context.target.normalized_url)
        if server_finding:
            findings.append(server_finding)

        # Check for framework indicators
        framework_findings = self._check_framework_indicators(headers, context.target.normalized_url)
        findings.extend(framework_findings)

        # Check X-Generator and other info headers
        generator_finding = self._check_generator_header(headers, context.target.normalized_url)
        if generator_finding:
            findings.append(generator_finding)

        return findings

    def _check_server_version(self, headers: dict, url: str) -> Optional[Finding]:
        """Check for server version disclosure in Server header."""
        server = headers.get("server", "")
        if not server:
            return None

        for pattern in SERVER_VERSION_PATTERNS:
            match = pattern.search(server)
            if match:
                version = match.group(1)
                return self._make_finding(
                    title=f"Server Version Disclosure: {version}",
                    category="A05",
                    severity=Severity.LOW,
                    status=FindingStatus.INFORMATIONAL,
                    affected_url=url,
                    evidence=f"Server header reveals version information: '{server}'",
                    impact="Version disclosure helps attackers identify known vulnerabilities for this specific server version.",
                    remediation="Configure the server to suppress version information. For Apache, set 'ServerTokens Prod'. For Nginx, set 'server_tokens off;'.",
                    references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/04-Fingerprint_Web_Server"],
                )

        # Generic server header without version is less concerning
        if server.lower() not in ("unknown", "off"):
            return self._make_finding(
                title="Server Header Information Disclosure",
                category="A05",
                severity=Severity.LOW,
                status=FindingStatus.INFORMATIONAL,
                affected_url=url,
                evidence=f"Server header present with value: '{server}'",
                impact="Server identification can help attackers research platform-specific vulnerabilities.",
                remediation="Consider removing or generalizing the Server header. Use a generic value like 'Server: WebServer' instead of detailed version strings.",
                references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/04-Fingerprint_Web_Server"],
            )

        return None

    def _check_framework_indicators(self, headers: dict, url: str) -> list:
        """Check for framework-specific identifiers."""
        findings = []

        powered_by = headers.get("x-powered-by", "")
        if powered_by:
            powered_by_lower = powered_by.lower()
            sev = Severity.LOW
            if any(f in powered_by_lower for f in ["php", "asp.net"]):
                sev = Severity.MEDIUM  # More sensitive frameworks

            findings.append(self._make_finding(
                title=f"Framework Disclosure: {powered_by}",
                category="A05",
                severity=sev,
                status=FindingStatus.INFORMATIONAL,
                affected_url=url,
                evidence=f"X-Powered-By header reveals technology stack: '{powered_by}'",
                impact="Framework identification enables targeted attacks using known vulnerabilities for that specific technology.",
                remediation="Remove the X-Powered-By header or replace it with a generic value. Configure your framework to suppress this header.",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"],
            ))

        return findings

    def _check_generator_header(self, headers: dict, url: str) -> Optional[Finding]:
        """Check for CMS or application generator disclosure."""
        for header_name in ["x-generator", "x-cms-version", "x-aspnet-version"]:
            value = headers.get(header_name, "")
            if value:
                return self._make_finding(
                    title=f"{header_name.replace('-', ' ').title()} Disclosure",
                    category="A05",
                    severity=Severity.LOW,
                    status=FindingStatus.INFORMATIONAL,
                    affected_url=url,
                    evidence=f"{header_name} header contains: '{value}'",
                    impact="Application version disclosure assists attackers in identifying known vulnerabilities.",
                    remediation="Remove application version headers from responses. Only include necessary headers.",
                )
        return None