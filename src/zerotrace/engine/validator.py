"""URL validation and SSRF prevention for ZeroTrace."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

from zerotrace.logging_config import get_logger
from zerotrace.config import settings

logger = get_logger("validator")


# Default private ranges that are always blocked (cloud metadata, etc.)
BLOCKED_RANGES_ALWAYS = [
    ipaddress.ip_network("169.254.0.0/16"),  # Cloud metadata
]

# Loopback ranges - blocked by default, allowed when allow_localhost=True
LOOPBACK_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),
]

# Private RFC 1918 ranges - always blocked
PRIVATE_RANGES_ALWAYS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("172.31.0.0/16"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


class CloudMetadataError(Exception):
    """Raised when attempting to scan a cloud metadata endpoint."""
    pass


@dataclass
class ValidatedTarget:
    """A URL that has passed all validation checks."""

    original_url: str
    normalized_url: str
    base_url: str  # scheme + hostname + port
    resolved_ip: str = ""
    final_url: str = ""
    redirect_chain: list[str] = None

    def __post_init__(self):
        if self.redirect_chain is None:
            self.redirect_chain = []


class URLValidationError(Exception):
    """Raised when a URL fails validation."""

    def __init__(self, url: str, reason: str) -> None:
        self.url = url
        self.reason = reason
        super().__init__(f"URL rejected: {url} — {reason}")


class URLValidator:
    """Validates URLs before any network activity occurs."""

    def __init__(self, allow_localhost: bool | None = None) -> None:
        """Initialize the validator.
        
        Args:
            allow_localhost: If True, allows scanning localhost/127.0.0.1.
                           If None, uses the setting from config (default: False).
        """
        self.max_redirect_depth = 5
        self.allow_localhost = allow_localhost if allow_localhost is not None else settings.allow_localhost

    def _get_private_ranges(self) -> list:
        """Get the list of private ranges based on allow_localhost setting."""
        if self.allow_localhost:
            # Only block truly dangerous ranges: cloud metadata and non-loopback private
            return PRIVATE_RANGES_ALWAYS
        else:
            # Block everything including loopback (default secure behavior)
            return PRIVATE_RANGES_ALWAYS + LOOPBACK_RANGES

    async def validate(self, url: str) -> ValidatedTarget:
        """Run the full validation pipeline on a URL."""
        parsed = urlparse(url)

        # Step 1: Protocol check
        self._check_protocol(parsed.scheme)

        # Step 2: Host validation
        hostname = parsed.hostname
        if not hostname:
            raise URLValidationError(url, "No hostname found in URL")

        # Step 3: Normalize
        normalized = self._normalize_url(url, parsed)

        # Step 4: DNS resolution
        resolved_ip = await self._resolve_hostname(hostname)
        logger.info(f"Resolved {hostname} → {resolved_ip}")

        # Step 5: IP safety check
        self._check_ip_safety(resolved_ip)

        return ValidatedTarget(
            original_url=url,
            normalized_url=normalized,
            base_url=f"{parsed.scheme}://{hostname}",
            resolved_ip=resolved_ip,
            redirect_chain=[],
        )

    def _check_protocol(self, scheme: str) -> None:
        """Reject forbidden protocols."""
        lower = scheme.lower()
        forbidden = {"file", "gopher", "dict", "telnet", "ldap", "ftp", "javascript", "data", "vbscript"}
        if lower in forbidden:
            raise URLValidationError(
                f"{scheme}://...",
                f"Protocol '{scheme}' is blocked for security reasons",
            )
        if lower not in ("http", "https"):
            raise URLValidationError(
                f"{scheme}://...",
                f"Only http and https protocols are supported (got '{scheme}')",
            )

    def _normalize_url(self, url: str, parsed) -> str:
        """Normalize URL: strip fragment, normalize path, ensure trailing slash consistency."""
        normalized = parsed._replace(fragment="", query="").geturl()
        # Remove trailing slash for consistency (keep root)
        if len(normalized) > 1 and normalized.endswith("/"):
            normalized = normalized.rstrip("/")
        return normalized

    async def _resolve_hostname(self, hostname: str) -> str:
        """Resolve hostname to IP address with basic safety."""
        loop = asyncio.get_running_loop()
        try:
            # Use run_in_executor for synchronous getaddrinfo
            addr_info = await loop.run_in_executor(
                None,
                lambda: socket.getaddrinfo(hostname, 443, socket.AF_INET, socket.SOCK_STREAM)
            )
            if addr_info:
                return addr_info[0][4][0]
        except socket.gaierror as exc:
            raise URLValidationError(
                hostname, f"DNS resolution failed: {exc}"
            ) from exc
        except socket.herror as exc:
            raise URLValidationError(
                hostname, f"Hostname resolution error: {exc}"
            ) from exc
        return ""

    def _check_ip_safety(self, ip_str: str) -> None:
        """Check if resolved IP falls in any blocked range."""
        if not ip_str:
            return

        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            raise URLValidationError(ip_str, "Invalid IP address after resolution")

        # Check private/reserved ranges
        private_ranges = self._get_private_ranges()
        for network in private_ranges:
            if ip in network:
                category = "loopback" if any(ip in r for r in LOOPBACK_RANGES) else "private"
                raise URLValidationError(
                    ip_str,
                    f"{category.capitalize()}/reserved IP address blocked: {ip_str} "
                    f"(in {network}) — scan aborted for safety",
                )

        # Check cloud metadata patterns specifically
        test_url = f"http://{ip_str}"
        for pattern in METADATA_PATTERNS:
            if pattern.search(test_url):
                raise URLValidationError(
                    ip_str,
                    f"Cloud metadata endpoint blocked: {ip_str}",
                )
                # Raise CloudMetadataError for specific handling if needed
                # raise CloudMetadataError(f"Cloud metadata endpoint blocked: {ip_str}")
    
    def is_safe_target(self, url: str) -> tuple[bool, str]:
        """Lightweight synchronous check for UI-level target warnings.
        
        This is a quick regex-based check that doesn't perform DNS resolution.
        It's used to provide immediate feedback in the UI before submitting a scan.
        
        Args:
            url: The URL to check
            
        Returns:
            Tuple of (is_safe, warning_message)
        """
        return is_safe_target_fast(url, allow_localhost=self.allow_localhost)


FORBIDDEN_PROTOCOLS = {"file", "gopher", "dict", "telnet", "ldap", "ftp"}

# Cloud metadata endpoints
METADATA_PATTERNS = [
    re.compile(r"^https?://169\.254\.169\.254", re.IGNORECASE),
    re.compile(r"metadata\.google\.internal", re.IGNORECASE),
    re.compile(r"windows\.azure\.com", re.IGNORECASE),
]


def is_safe_target_fast(url: str, allow_localhost: bool = False) -> tuple[bool, str]:
    """Lightweight synchronous check for UI-level target warnings.
    
    This is a quick regex-based check that doesn't perform DNS resolution.
    It's used to provide immediate feedback in the UI before submitting a scan.
    
    Args:
        url: The URL to check
        allow_localhost: If True, allows localhost/127.0.0.1 patterns
        
    Returns:
        Tuple of (is_safe, warning_message)
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme.lower() not in ("http", "https"):
            return False, f"Unsupported protocol: {parsed.scheme}"
        hostname = parsed.hostname
        if not hostname:
            return False, "No hostname in URL"
        
        if allow_localhost:
            # Only check for dangerous patterns, allow localhost
            dangerous_patterns = [
                r"^10\.",
                r"^172\.(1[6-9]|2[0-9]|3[01])\.",  # 172.16-31.x.x
                r"^192\.168\.",
                r"^169\.254\.",  # Cloud metadata
            ]
            for pattern in dangerous_patterns:
                if re.match(pattern, hostname, re.I):
                    return False, f"Dangerous/private hostname detected: {hostname}"
            return True, ""
        else:
            # Block everything including localhost (secure default)
            if re.match(r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|localhost)", hostname, re.I):
                return False, f"Private or loopback hostname detected: {hostname}"
            # Also check for cloud metadata patterns
            if re.match(r"^169\.254\.", hostname, re.I):
                return False, f"Cloud metadata endpoint blocked: {hostname}"
            return True, ""
    except Exception as exc:
        return False, str(exc)


async def validate_target(url: str, allow_localhost: bool | None = None) -> ValidatedTarget:
    """Convenience function for use throughout the application."""
    validator = URLValidator(allow_localhost=allow_localhost)
    return await validator.validate(url)