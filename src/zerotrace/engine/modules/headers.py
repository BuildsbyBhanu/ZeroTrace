"""Security headers analysis module."""

from __future__ import annotations

import re

from zerotrace.engine.base import BaseModule, FindingStatus, Severity
from zerotrace.engine.context import ScanContext

# Required security headers per OWASP guidance
REQUIRED_HEADERS = {
    "strict-transport-security": ("HSTS", "Enforces HTTPS connections", "medium"),
    "content-security-policy": ("CSP", "Prevents XSS and injection attacks", "high"),
    "x-content-type-options": ("X-Content-Type-Options", "Prevents MIME-type sniffing", "low"),
    "x-frame-options": ("X-Frame-Options", "Prevents clickjacking", "medium"),
    "referrer-policy": ("Referrer-Policy", "Controls referrer information leakage", "low"),
    "permissions-policy": ("Permissions-Policy", "Restricts browser feature access", "medium"),
    "x-xss-protection": ("X-XSS-Protection", "Legacy XSS filter (deprecated but common)", "low"),
}

# Dangerous server info headers
DANGEROUS_SERVER_HEADERS = {
    "server": "Server version disclosure",
    "x-powered-by": "Technology stack disclosure",
    "via": "Proxy/infrastructure disclosure",
    "x-aspnet-version": "ASP.NET version disclosure",
    "x-aspnetmvc-version": "ASP.NET MVC version disclosure",
    "x-generator": "CMS/version disclosure",
    "x-stylesheet-facilitator": "Framework disclosure",
}

STRONG_CSP_PATTERNS = [
    re.compile(r"default-src\s+self", re.IGNORECASE),
    re.compile(r"'none'", re.IGNORECASE),
]


class SecurityHeadersModule(BaseModule):
    """Analyzes HTTP security headers for misconfigurations."""

    name = "security-headers"
    description = "Checks security headers (HSTS, CSP, X-Frame-Options, etc.)"
    owasp_category = "A05"
    severity_base = Severity.MEDIUM
    run_in_quick = True
    run_in_standard = True

    async def execute(self, context: ScanContext) -> list:
        findings = []

        # Fetch response headers if not cached
        headers = context.headers_observed
        if not headers:
            headers = await self._fetch_headers(context)
            context.headers_observed = headers

        # Check missing required headers
        for header, (name, desc, default_sev) in REQUIRED_HEADERS.items():
            if header not in headers:
                sev_map = {
                    "high": Severity.HIGH,
                    "medium": Severity.MEDIUM,
                    "low": Severity.LOW,
                }
                severity = sev_map.get(default_sev, Severity.MEDIUM)
                findings.append(self._make_finding(
                    title=f"Missing Security Header: {name}",
                    category=self.owasp_category,
                    severity=severity,
                    status=FindingStatus.CONFIRMED,
                    affected_url=context.target.normalized_url,
                    evidence=f"The '{header}' security header is not present in the HTTP response headers.",
                    impact=f"{desc}. This weakens the application's defense-in-depth posture and could allow attacks such as clickjacking, MIME sniffing, or XSS.",
                    remediation=f"Add the '{header}: <appropriate-value>' response header to all responses. See OWASP guidelines for recommended values specific to this header.",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"],
                ))

        # Check dangerous server information disclosure
        for header, warning in DANGEROUS_SERVER_HEADERS.items():
            if header in headers:
                header_value = headers[header]
                findings.append(self._make_finding(
                    title=f"Information Disclosure: {warning}",
                    category="A05",
                    severity=Severity.MEDIUM,
                    status=FindingStatus.CONFIRMED,
                    affected_url=context.target.normalized_url,
                    evidence=f"Header '{header}' present with value: {header_value[:100]}",
                    impact="Reveals technology stack and version details that attackers can use for targeted exploits and vulnerability research.",
                    remediation=f"Remove or generalize the '{header}' header. Use generic values like 'Server: Website' instead of versions.",
                    references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/04-Fingerprint_Web_Server"],
                ))

        # Validate HSTS configuration
        hsts = headers.get("strict-transport-security", "")
        if hsts:
            if "max-age=0" in hsts.lower():
                findings.append(self._make_finding(
                    title="HSTS Explicitly Disabled (max-age=0)",
                    category="A02",
                    severity=Severity.HIGH,
                    status=FindingStatus.CONFIRMED,
                    affected_url=context.target.normalized_url,
                    evidence=f"HSTS header is present but explicitly disabled: '{hsts}'. The max-age=0 directive forces browsers to remove HSTS from their cache.",
                    impact="HSTS is explicitly disabled, allowing SSL stripping attacks where an attacker downgrades the connection to HTTP.",
                    remediation="Set max-age to at least 31536000 (1 year). Add 'includeSubDomains' and 'preload' directives for maximum security. Remove max-age=0 entirely.",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
                ))
            elif "includesubdomains" not in hsts.lower():
                findings.append(self._make_finding(
                    title="HSTS Missing includeSubDomains Directive",
                    category="A02",
                    severity=Severity.MEDIUM,
                    status=FindingStatus.POTENTIAL,
                    affected_url=context.target.normalized_url,
                    evidence=f"HSTS header is configured but lacks 'includeSubDomains': '{hsts}'.",
                    impact="Subdomains are not protected by HSTS policy, allowing attackers to potentially downgrade HTTPS connections on subdomains.",
                    remediation="Add 'includeSubDomains' directive to the HSTS header to extend protection to all subdomains.",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
                ))

        # Validate CSP strength
        csp = headers.get("content-security-policy", "")
        if csp:
            is_strong = any(p.search(csp) for p in STRONG_CSP_PATTERNS)
            if not is_strong:
                findings.append(self._make_finding(
                    title="Weak or Ineffective Content Security Policy",
                    category="A03",
                    severity=Severity.MEDIUM,
                    status=FindingStatus.POTENTIAL,
                    affected_url=context.target.normalized_url,
                    evidence=f"CSP header is present but lacks strong restrictions: '{csp[:200]}'...",
                    impact="Weak CSP may allow XSS attacks through inadequate script source restrictions. Attackers could inject malicious scripts that bypass the policy.",
                    remediation="Implement a strict CSP with 'default-src 'self'' and specific allowed sources. Consider using 'script-src 'self'' and avoiding 'unsafe-inline' or 'unsafe-eval'.",
                    references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP", "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"],
                ))
        else:
            findings.append(self._make_finding(
                title="Missing Content Security Policy (CSP)",
                category="A03",
                severity=Severity.MEDIUM,
                status=FindingStatus.CONFIRMED,
                affected_url=context.target.normalized_url,
                evidence="The Content-Security-Policy header is not present in any response headers.",
                impact="Without CSP, the application is more vulnerable to Cross-Site Scripting (XSS) and data injection attacks. CSP provides a critical defense-in-depth layer.",
                remediation="Implement a Content Security Policy with appropriate directives for your application. Start with 'default-src 'self'' and add specific allowances as needed.",
                references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP", "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"],
            ))

        return findings

    async def _fetch_headers(self, context: ScanContext) -> dict:
        """Fetch initial response headers from the target."""
        import httpx
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=context.settings.connection_timeout if hasattr(context, 'settings') else 10.0,
            ) as client:
                resp = await client.get(context.target.normalized_url, follow_redirects=True)
                return {k.lower(): v for k, v in resp.headers.items()}
        except Exception:
            return {}

    @staticmethod
    def _sev_to_upper(sev: str) -> str:
        return sev.upper()
