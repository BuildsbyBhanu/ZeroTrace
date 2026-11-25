"""Scan context — shared state throughout a scan lifecycle."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from zerotrace.engine.base import ValidatedTarget


@dataclass
class AuthCredentials:
    """Encrypted authentication credentials for a scan."""

    username: str = ""
    password: str = ""
    token: str = ""
    cookie_header: str = ""
    auth_type: str = "basic"  # basic, bearer, cookie, form


@dataclass
class ScanContext:
    """Mutable shared state passed through the scan pipeline."""

    target: ValidatedTarget
    custom_modules: list[str] = field(default_factory=list)
    credentials: Optional[AuthCredentials] = None

    # Accumulated results
    findings: list = field(default_factory=list)
    discovered_urls: set = field(default_factory=set)
    headers_observed: dict = field(default_factory=dict)
    technologies: dict = field(default_factory=dict)
    response_cache: dict = field(default_factory=dict)

    # Runtime state
    request_count: int = 0
    errors: list = field(default_factory=list)

    def add_finding(self, finding) -> None:
        self.findings.append(finding)

    def add_discovered_url(self, url: str) -> None:
        self.discovered_urls.add(url)

    def inc_request_count(self, n: int = 1) -> None:
        self.request_count += n
