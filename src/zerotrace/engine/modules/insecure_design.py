"""OWASP A04:2021 - Insecure Design module.

This module checks for design-level security weaknesses that go beyond
code vulnerabilities. These are issues that require architectural or
design consideration rather than simple code fixes.

OWASP A04 covers:
- Missing security controls in design
- Weak authentication/authorization architecture
- Business logic flaws
- Insufficient logging & monitoring (covered separately in A09)
"""

from __future__ import annotations

from typing import Optional

from zerotrace.engine.base import BaseModule, Finding, FindingStatus, Severity
from zerotrace.engine.context import ScanContext
from zerotrace.logging_config import get_logger

logger = get_logger("insecure_design")


class InsecureDesignModule(BaseModule):
    """Checks for insecure design patterns and missing security controls.
    
    This module identifies design-level weaknesses that could allow
    attacks even when individual code components are secure.
    """

    name = "insecure-design"
    description = "Checks for insecure design patterns and missing security controls"
    owasp_category = "A04"
    severity_base = Severity.MEDIUM
    run_in_quick = True
    run_in_standard = True

    async def execute(self, context: ScanContext) -> list[Finding]:
        """Execute insecure design checks."""
        findings = []
        headers = context.headers_observed or {}

        # Check missing X-Frame-Options (clickjacking protection)
        if "x-frame-options" not in headers:
            findings.append(self._make_finding(
                title="Missing X-Frame-Options Header (Clickjacking Risk)",
                category="A04",
                severity=Severity.MEDIUM,
                status=FindingStatus.CONFIRMED,
                affected_url=context.target.normalized_url,
                evidence="The X-Frame-Options header is not present in response headers. This header is essential for preventing clickjacking attacks.",
                impact="Clickjacking attacks can trick users into performing actions they didn't intend. Attackers could overlay invisible frames to capture clicks or redirect users to malicious sites.",
                remediation="Add X-Frame-Options: DENY (for pages that should never be framed) or X-Frame-Options: SAMEORIGIN (to allow framing from same origin only). Consider using Content-Security-Policy frame-ancestors as a modern alternative.",
                references=[
                    "https://owasp.org/www-community/attacks/Clickjacking",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
                ],
            ))

        # Check missing Referrer-Policy
        if "referrer-policy" not in headers:
            findings.append(self._make_finding(
                title="Missing Referrer-Policy Header",
                category="A04",
                severity=Severity.LOW,
                status=FindingStatus.POTENTIAL,
                affected_url=context.target.normalized_url,
                evidence="The Referrer-Policy header is not present in response headers.",
                impact="Without Referrer-Policy, browsers send full URL referrer information, potentially leaking sensitive path information, query parameters, or session identifiers to third-party sites.",
                remediation="Add Referrer-Policy: strict-origin-when-cross-origin to limit referrer information sent to external sites while preserving it for same-origin requests.",
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-forcing_a_session_by_modifying_the_cookie"
                ],
            ))

        # Check for overly permissive CORS (if present)
        access_control_allow_origin = headers.get("access-control-allow-origin", "")
        if access_control_allow_origin == "*":
            findings.append(self._make_finding(
                title="Overly Permissive CORS Policy",
                category="A04",
                severity=Severity.HIGH,
                status=FindingStatus.CONFIRMED,
                affected_url=context.target.normalized_url,
                evidence=f"Access-Control-Allow-Origin is set to '*' allowing any origin to make cross-origin requests.",
                impact="Overly permissive CORS allows malicious websites to make authenticated requests to your application, potentially exposing sensitive user data or allowing unauthorized actions.",
                remediation="Specify only the origins that need cross-origin access. Use specific domains instead of '*' for Access-Control-Allow-Origin.",
                references=[
                    "https://owasp.org/www-community/vulnerabilities/Always_Select_Checked",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"
                ],
            ))

        # Check for missing Feature-Policy/Permissions-Policy
        if "permissions-policy" not in headers:
            findings.append(self._make_finding(
                title="Missing Permissions-Policy Header",
                category="A04",
                severity=Severity.LOW,
                status=FindingStatus.POTENTIAL,
                affected_url=context.target.normalized_url,
                evidence="The Permissions-Policy header is not present in response headers.",
                impact="Without Permissions-Policy, browsers may allow features like camera, microphone, geolocation, or fullscreen to be accessed by malicious scripts on the page.",
                remediation="Add Permissions-Policy header to restrict browser features. For example: Permissions-Policy: camera=(), microphone=(), geolocation=()",
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Configuration_Deployment_Protection_Testing/01-Testing_for_HTTP_Strong_Cryptography"
                ],
            ))

        # Check for missing Expect-CT (Certificate Transparency)
        if "expect-ct" not in headers:
            findings.append(self._make_finding(
                title="Missing Expect-CT Header",
                category="A04",
                severity=Severity.LOW,
                status=FindingStatus.INFORMATIONAL,
                affected_url=context.target.normalized_url,
                evidence="The Expect-CT header is not present. This header provides Certificate Transparency reporting.",
                impact="Without CT reporting, the site cannot detect if an illegitimate certificate has been issued for the domain by a compromised or malicious CA.",
                remediation="Consider adding Expect-CT: max-age=86400, report-uri=\"https://your-report-uri.example.com/report\" to enable Certificate Transparency reporting.",
                references=[
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT",
                    "https://blog.cloudflare.com/certificate-transparency-part-1/"
                ],
            ))

        return findings