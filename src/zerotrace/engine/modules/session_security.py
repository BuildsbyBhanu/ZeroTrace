"""Session security analysis module.

Analyzes cookie configurations and session management patterns
to identify security weaknesses.
"""

from __future__ import annotations

import re
from typing import Optional

from zerotrace.engine.base import BaseModule, FindingStatus, Severity
from zerotrace.engine.context import ScanContext


# Cookie names that should always have Secure flag
SENSITIVE_COOKIE_PATTERNS = [
    re.compile(r"(session|auth|token|jwt|refresh|access|user|login|admin|csrf|xsrf)", re.IGNORECASE),
    re.compile(r"_id\b", re.IGNORECASE),
    re.compile(r"(sid|sess)", re.IGNORECASE),
]

# Patterns indicating potentially weak session IDs
WEAK_SESSION_PATTERNS = [
    re.compile(r"^[a-f0-9]{8,16}$", re.IGNORECASE),  # Too short hex
    re.compile(r"^.{1,8}$"),  # Very short
    re.compile(r"^(seq|count|test|demo|example|default|placeholder|temp|\\d+)$", re.IGNORECASE),  # Common words
]


class SessionSecurityModule(BaseModule):
    """Analyzes session cookie security configuration."""

    name = "session-security"
    description = "Checks session cookie security, predictable IDs, and missing flags"
    owasp_category = "A07"
    severity_base = Severity.MEDIUM
    run_in_quick = True
    run_in_standard = True
    run_in_deep = True

    async def execute(self, context: ScanContext) -> list:
        """Execute session security checks."""
        findings = []
        headers = context.headers_observed or {}

        # Extract all Set-Cookie headers
        raw_cookies = self._extract_set_cookie_headers(headers)

        if not raw_cookies:
            findings.append(self._make_finding(
                title="No Session Cookies Detected",
                category="A07",
                severity=Severity.INFORMATIONAL,
                status=FindingStatus.INFORMATIONAL,
                affected_url=context.target.normalized_url,
                evidence="No Set-Cookie headers found in any response. Application may use stateless authentication or client-side storage.",
                impact="Could indicate no server-side session management, which may be intentional (JWT-based auth) or an oversight.",
                remediation="If using server-side sessions, ensure they are properly configured with secure flags. If using JWT, document the approach.",
                references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-forcing_a_session_by_modifying_the_cookie"],
            ))
            return findings

        for raw_cookie in raw_cookies:
            cookie_findings = self._analyze_cookie(raw_cookie, context.target.normalized_url)
            findings.extend(cookie_findings)

        return findings

    def _extract_set_cookie_headers(self, headers: dict) -> list:
        """Extract all Set-Cookie header values."""
        cookies = []
        for key, value in headers.items():
            if key.lower() == "set-cookie":
                if isinstance(value, list):
                    cookies.extend(value)
                else:
                    cookies.append(value)
        return cookies

    def _analyze_cookie(self, raw_cookie: str, url: str) -> list:
        """Analyze a single cookie for security issues."""
        findings = []

        parts = raw_cookie.split(";")
        name_value = parts[0].strip().split("=", 1)
        cookie_name = name_value[0].strip() if len(name_value) > 0 else ""
        cookie_value = name_value[1].strip() if len(name_value) > 1 else ""

        attrs_lower = {p.strip().lower(): True for p in parts[1:]}
        attrs_parts = {}
        for p in parts[1:]:
            p_stripped = p.strip()
            if "=" in p_stripped:
                k, v = p_stripped.split("=", 1)
                attrs_parts[k.strip().lower()] = v.strip()

        # Check if cookie is sensitive
        is_sensitive = any(p.search(cookie_name) for p in SENSITIVE_COOKIE_PATTERNS)

        # Check Secure flag
        if not attrs_lower.get("secure"):
            severity = Severity.HIGH if is_sensitive else Severity.MEDIUM
            findings.append(self._make_finding(
                title=f"Cookie Missing Secure Flag: {cookie_name or 'unnamed'}",
                category="A07",
                severity=severity,
                status=FindingStatus.CONFIRMED,
                affected_url=url,
                evidence=f"Cookie '{cookie_name}' does not have the 'Secure' attribute. Full cookie: {raw_cookie[:150]}",
                impact="Cookie may be transmitted over unencrypted HTTP connections, exposing session tokens to interception.",
                remediation="Add the 'Secure' flag to all cookies, especially session and authentication cookies. Ensure the site enforces HTTPS.",
                references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-forcing_a_session_by_modifying_the_cookie"],
            ))

        # Check HttpOnly flag on sensitive cookies only
        if is_sensitive and not attrs_lower.get("httponly"):
            findings.append(self._make_finding(
                title=f"Sensitive Cookie Not HttpOnly: {cookie_name}",
                category="A07",
                severity=Severity.HIGH,
                status=FindingStatus.CONFIRMED,
                affected_url=url,
                evidence=f"Sensitive cookie '{cookie_name}' lacks the 'HttpOnly' attribute.",
                impact="Without HttpOnly, the cookie is accessible via JavaScript, enabling XSS-based session hijacking.",
                remediation="Add the 'HttpOnly' flag to all session and authentication cookies to prevent JavaScript access.",
                references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/01-forcing_a_session_via_cookie_manipulation"],
            ))

        # Check SameSite attribute for sensitive cookies
        samesite = attrs_parts.get("samesite", "").lower()
        if not samesite and is_sensitive:
            findings.append(self._make_finding(
                title=f"Sensitive Cookie Missing SameSite: {cookie_name}",
                category="A07",
                severity=Severity.MEDIUM,
                status=FindingStatus.POTENTIAL,
                affected_url=url,
                evidence=f"Sensitive cookie '{cookie_name}' has no SameSite attribute.",
                impact="Cookies without SameSite may be sent in cross-site requests, enabling CSRF attacks.",
                remediation="Add 'SameSite=Lax' at minimum to all sensitive cookies. Use 'Strict' for highly sensitive cookies.",
                references=["https://owasp.org/www-community/controls/Preventing_Cross_Site_Request_Forgery_(CSRF)"],
            ))

        # Check for predictable/weak session IDs
        if is_sensitive and cookie_value:
            weak_findings = self._check_weak_session_id(cookie_name, cookie_value, url)
            findings.extend(weak_findings)

        return findings

    def _check_weak_session_id(self, cookie_name: str, value: str, url: str) -> list:
        """Check for predictable or weak session ID patterns."""
        findings = []

        # Skip if value looks reasonably random
        if len(value) < 8:
            findings.append(self._make_finding(
                title=f"Short Session ID: {cookie_name}",
                category="A07",
                severity=Severity.MEDIUM,
                status=FindingStatus.POTENTIAL,
                affected_url=url,
                evidence=f"Session cookie '{cookie_name}' has a very short value ({len(value)} characters).",
                impact="Short session IDs may be susceptible to brute-force guessing attacks.",
                remediation="Use cryptographically random session IDs with sufficient length (at least 128 bits / 32 hexadecimal characters).",
            ))

        for pattern in WEAK_SESSION_PATTERNS:
            if pattern.match(value):
                findings.append(self._make_finding(
                    title=f"Weak Session ID Pattern: {cookie_name}",
                    category="A07",
                    severity=Severity.MEDIUM,
                    status=FindingStatus.POTENTIAL,
                    affected_url=url,
                    evidence=f"Session cookie '{cookie_name}' has a predictable pattern: '{value}'",
                    impact="Predictable session IDs enable session prediction attacks.",
                    remediation="Use cryptographically secure random number generators for session ID creation.",
                ))
                break

        return findings