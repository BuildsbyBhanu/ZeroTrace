"""Cookie security analysis module."""

from __future__ import annotations

import re
from typing import Optional

from zerotrace.engine.base import BaseModule, FindingStatus, Severity
from zerotrace.engine.context import ScanContext
from zerotrace.logging_config import get_logger

logger = get_logger("cookie_module")

# Cookies that should always have Secure flag
SENSITIVE_COOKIE_NAMES = re.compile(
    r"(session|auth|token|jwt|refresh|access|user|login|admin|csrf|xsrf)"
    r"|_id\b",
    re.IGNORECASE,
)


class CookieSecurityModule(BaseModule):
    """Analyzes cookie security configuration."""

    name = "cookie-security"
    description = "Checks cookie security flags (Secure, HttpOnly, SameSite)"
    owasp_category = "A07"
    severity_base = Severity.LOW
    run_in_quick = True
    run_in_standard = True

    async def execute(self, context: ScanContext) -> list:
        findings = []
        headers = context.headers_observed

        set_cookie_headers = [
            v for k, v in headers.items()
            if k.lower() == "set-cookie"
        ]

        if not set_cookie_headers:
            findings.append(self._make_finding(
                title="No Cookies Set",
                category="A07",
                severity=Severity.INFORMATIONAL,
                status=FindingStatus.INFORMATIONAL,
                affected_url=context.target.normalized_url,
                evidence="No Set-Cookie headers found in response.",
                impact="May indicate stateless application or cookies handled via JS/localStorage.",
                remediation="No action needed if the application is truly stateless. Otherwise, ensure session cookies are properly configured.",
            ))
            return findings

        for raw_cookie in set_cookie_headers:
            cookie_findings = self._analyze_cookie(raw_cookie, context.target.normalized_url)
            findings.extend(cookie_findings)

        return findings

    def _analyze_cookie(self, raw_cookie: str, url: str) -> list:
        """Analyze a single Set-Cookie header."""
        findings = []

        # Parse cookie attributes
        parts = raw_cookie.split(";")
        cookie_name = parts[0].strip().split("=")[0].strip()
        attrs_lower = {p.strip().lower(): True for p in parts[1:]}
        attrs_parts = {}
        for p in parts[1:]:
            p_stripped = p.strip()
            if "=" in p_stripped:
                k, v = p_stripped.split("=", 1)
                attrs_parts[k.strip().lower()] = v.strip()

        # Check Secure flag
        if not attrs_lower.get("secure"):
            sev = Severity.HIGH if SENSITIVE_COOKIE_NAMES.search(cookie_name) else Severity.MEDIUM
            findings.append(self._make_finding(
                title=f"Cookie Missing Secure Flag: {cookie_name}",
                category="A07",
                severity=sev,
                status=FindingStatus.CONFIRMED,
                affected_url=url,
                evidence=f"Cookie '{cookie_name}' lacks the 'Secure' attribute. Full header: {raw_cookie[:150]}",
                impact=f"Cookie may be transmitted over unencrypted HTTP connections, exposing {'session/authentication' if SENSITIVE_COOKIE_NAMES.search(cookie_name) else 'the cookie'} to interception via man-in-the-middle attacks.",
                remediation=f"Add the 'Secure' flag to all cookies, especially session and authentication cookies. Ensure the site enforces HTTPS for all connections.",
                references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-forcing_a_session_by_modifying_the_cookie"],
            ))

        # Check HttpOnly flag
        if not attrs_lower.get("httponly"):
            sev = Severity.MEDIUM if SENSITIVE_COOKIE_NAMES.search(cookie_name) else Severity.LOW
            findings.append(self._make_finding(
                title=f"Cookie Missing HttpOnly Flag: {cookie_name}",
                category="A07",
                severity=sev,
                status=FindingStatus.CONFIRMED,
                affected_url=url,
                evidence=f"Cookie '{cookie_name}' lacks the 'HttpOnly' attribute. Full header: {raw_cookie[:150]}",
                impact=f"Cookie {'is accessible via JavaScript, enabling XSS-based session hijacking' if SENSITIVE_COOKIE_NAMES.search(cookie_name) else 'is accessible via JavaScript, which could enable theft if an XSS vulnerability exists'}.",
                remediation=f"Add the 'HttpOnly' flag to session and authentication cookies {'where XSS risks exist' if not SENSITIVE_COOKIE_NAMES.search(cookie_name) else ''} to prevent JavaScript access.",
                references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/01-forcing_a_session_via_cookie_manipulation"],
            ))

        # Check SameSite attribute
        samesite = attrs_parts.get("samesite", "").lower()
        if not samesite:
            findings.append(self._make_finding(
                title=f"Cookie Missing SameSite Attribute: {cookie_name}",
                category="A07",
                severity=Severity.LOW,
                status=FindingStatus.POTENTIAL,
                affected_url=url,
                evidence=f"Cookie '{cookie_name}' has no SameSite attribute. Full header: {raw_cookie[:150]}",
                impact="Cookies without SameSite may be sent in cross-site requests, enabling Cross-Site Request Forgery (CSRF) attacks.",
                remediation="Add 'SameSite=Lax' as a minimum for most cookies. Use 'SameSite=Strict' for highly sensitive cookies like session tokens.",
                references=["https://owasp.org/www-community/controls/Preventing_Cross_Site_Request_Forgery_(CSRF)"],
            ))

        # Check for overly broad Domain attribute
        domain = attrs_parts.get("domain", "")
        if domain and domain.startswith("."):
            findings.append(self._make_finding(
                title=f"Overly Broad Cookie Domain: {cookie_name}",
                category="A07",
                severity=Severity.LOW,
                status=FindingStatus.POTENTIAL,
                affected_url=url,
                evidence=f"Cookie '{cookie_name}' has Domain='{domain}', which scopes it to the domain and all subdomains.",
                impact="Broad domain scope increases attack surface for cross-subdomain attacks and potential subdomain takeover vulnerabilities.",
                remediation=f"Limit the Domain attribute to '{domain.lstrip('.')}' if cookie is only needed on the specific domain, or ensure all subdomains are properly secured.",
                references=["https://owasp.org/www-community/controls/Preventing_Cross_Site_Request_Forgery_(CSRF)"],
            ))

        return findings
