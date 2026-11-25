# ZeroTrace — Scanning Engine Design

## 1. Engine Architecture

The scanning engine is the heart of ZeroTrace. It orchestrates modular detection components that work together to produce a comprehensive security assessment. The engine is designed around three core principles:

1. **Modularity** — Each vulnerability check is an isolated, testable module
2. **Safety first** — Every outbound request is validated and throttled
3. **Observability** — Every action is traceable through progress events and audit logs

---

## 2. Core Components

### 2.1 URL Validator (`engine/validator.py`)

First line of defense. Runs before any network activity.

```python
class URLValidator:
    def validate(self, url: str) -> ValidatedTarget:
        # 1. Parse and normalize
        # 2. Block forbidden protocols (file://, gopher://, etc.)
        # 3. Resolve DNS and check IP against denylist
        # 4. Follow redirects with chain limit
        # 5. Return ValidatedTarget with safe base URL
```

**Denylist rules:**
- All RFC 1918 private IPs
- Loopback addresses (127.0.0.1, ::1)
- Link-local addresses (169.254.x.x, fe80::)
- Cloud metadata endpoints (169.254.169.254)
- Documentation/test reserved ranges (192.0.2.0/24, 198.51.100.0/24)

### 2.2 Scan Context (`engine/context.py`)

Shared state passed through the scan lifecycle. Immutable for read-only fields; controlled mutations for results.

```python
@dataclass
class ScanContext:
    target: ValidatedTarget
    profile: ScanProfile
    credentials: Optional[AuthCredentials] = None
    settings: ScanSettings = field(default_factory=ScanSettings)
    
    # Mutable accumulation fields
    findings: list[Finding] = field(default_factory=list)
    discovered_urls: set[str] = field(default_factory=set)
    headers_observed: dict[str, str] = field(default_factory=dict)
    technologies: dict[str, str] = field(default_factory=dict)
```

### 2.3 Rate Limiter (`engine/rate_limiter.py`)

Token-bucket algorithm controlling outbound request velocity.

```python
class RateLimiter:
    def __init__(self, requests_per_second: float = 10.0):
        self.bucket = asyncio.Semaphore(max_concurrency)
        self.tokens = requests_per_second
        self.last_refill = time.monotonic()
    
    async def acquire(self):
        """Block until a request token is available."""
```

### 2.4 Module Base Class (`engine/modules/base.py`)

All detection modules inherit from this interface.

```python
class BaseModule(ABC):
    name: str = "base"
    description: str = ""
    owasp_category: Optional[str] = None  # e.g., "A05"
    severity_base: Severity = Severity.INFO
    run_in_quick: bool = False
    run_in_standard: bool = True
    run_in_deep: bool = True
    
    async def execute(self, context: ScanContext) -> list[Finding]:
        """Run the module and return findings."""
        ...
    
    def should_run(self, profile: ScanProfile, context: ScanContext) -> bool:
        """Determine if this module should execute for the given profile."""
        if profile == ScanProfile.QUICK:
            return self.run_in_quick
        if profile == ScanProfile.STANDARD:
            return self.run_in_standard
        return self.run_in_deep
```

### 2.5 Orchestrator (`engine/orchestrator.py`)

Coordinates module execution within a single scan job.

```python
class ScanOrchestrator:
    async def run(self, context: ScanContext, progress_callback: Callable) -> ScanResult:
        # Phase 1: Pre-scan validation
        # Phase 2: Passive modules (no side effects) — run sequentially for deterministic ordering
        # Phase 3: Active modules — run concurrently with rate limiting
        # Phase 4: Post-processing — deduplication, severity scoring, categorization
        # Phase 5: Result assembly
```

**Execution order:**
1. Reconnaissance (technology fingerprinting) — sequential
2. Security Headers Analysis — sequential
3. SSL/TLS Configuration Check — sequential
4. Cookie Security Review — sequential
5. Information Disclosure Detection — concurrent (multiple URLs)
6. CORS Analysis — concurrent
7. Misconfiguration Checks — concurrent
8. Auth-based tests — sequential (session-dependent)

---

## 3. Module Catalog

### Phase 1 Modules (Quick + Standard)

| Module | Profile | Category | Description |
|--------|---------|----------|-------------|
| `ServerHeaders` | Quick+Standard | A05 | Analyze Server, X-Powered-By, Via headers for information disclosure |
| `SecurityHeaders` | Quick+Standard | A05 | Check presence and correctness of CSP, HSTS, X-Frame-Options, etc. |
| `SSLConfiguration` | Quick+Standard | A02 | TLS version, cipher suites, certificate validity, weak protocols |
| `CookieSecurity` | Quick+Standard | A07 | Secure, HttpOnly, SameSite flags on cookies |
| `Technologies` | Quick+Standard | A06 | Detect frameworks, CDNs, CMS via headers and HTML patterns |
| `InfoDisclosure` | Standard | A01/A09 | Check for exposed .env, /robots.txt, sitemap.xml, debug endpoints |
| `CORSAnalysis` | Standard | A01 | Evaluate Cross-Origin policies for misconfigurations |
| `CSPAnalysis` | Standard | A05 | Validate Content-Security-Policy strength and bypass potential |
| `MixedContent` | Standard | A02 | Detect HTTP resources loaded on HTTPS pages |
| `DirectoryListing` | Standard | A05 | Check for enabled directory browsing on common paths |

### Phase 2 Modules (Deep)

| Module | Profile | Category | Description |
|--------|---------|----------|-------------|
| `LoginFormDetection` | Deep | A07 | Identify login endpoints and form structures |
| `SessionTesting` | Deep | A07 | Verify session token properties and rotation |
| `AuthenticationBypass` | Deep | A01 | Test for IDOR and horizontal privilege escalation |
| `InputReflection` | Deep | A03 | Check for reflected input in responses (XSS indicator) |
| `ErrorHandling` | Deep | A10 | Examine error page information leakage |

---

## 4. Finding Classification

Each finding receives one of five status values:

| Status | Meaning | Display |
|--------|---------|---------|
| `CONFIRMED` | High confidence the issue exists | Red alert |
| `POTENTIAL` | Strong indicators present but needs verification | Orange warning |
| `INFORMATIONAL` | Noted behavior, not necessarily a vulnerability | Blue info |
| `NOT_TESTED` | Module was skipped or not applicable | Grey neutral |
| `REQUIRES_MANUAL_VERIFICATION` | Automated testing inconclusive | Yellow advisory |

Severity levels map to OWASP risk rating:

| Severity | Description | Example |
|----------|-------------|---------|
| Critical | Immediate exploitation possible, severe impact | SQL injection with data exfiltration |
| High | Exploitation likely, significant impact | Authentication bypass |
| Medium | Exploitation possible with effort | Missing HSTS header |
| Low | Difficult to exploit, limited impact | Verbose error messages |
| Informational | Observational finding, no direct risk | Technology version disclosure |

---

## 5. Scan Workflow Detail

```
                    ┌─────────────────────┐
                    │  User submits URL   │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  URL Validation     │
                    │  (SSRF, IP block)   │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
     ┌────────▼───────┐ ┌─────▼──────┐ ┌──────▼───────┐
     │  Passive Phase  │ │ Active Phase│ │ Auth Phase   │
     │  (sequential)   │ │(concurrent) │ │(if configured)│
     └────────┬────────┘ └─────┬──────┘ └──────┬───────┘
              │                │               │
              └────────────────┴───────────────┘
                               │
                    ┌──────────▼──────────┐
                    │  Deduplication      │
                    │  & Severity Scoring │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  Result Assembly    │
                    │  → findings list    │
                    │  → summary stats    │
                    │  → report generation│
                    └─────────────────────┘
```

### Passive Phase (Sequential, No Side Effects)
Runs in fixed order so later modules can depend on earlier results:
1. Fetch baseline response (GET /)
2. Analyze server headers → populate `context.headers_observed`
3. Analyze security headers
4. Check SSL/TLS configuration
5. Check cookie security
6. Fingerprint technologies

### Active Phase (Concurrent, Rate-Limited)
Modules run in parallel where safe:
- Multiple endpoint probes
- Multi-path information disclosure checks
- CORS test vectors
- CSP analysis variants

### Auth Phase (Sequential, Session-Aware)
Requires established session:
- Login form discovery
- Session token validation
- Authenticated endpoint probing

---

## 6. Error Handling Strategy

| Error Type | Handling |
|-----------|----------|
| Connection timeout | Retry once with doubled timeout, then mark as `TIMEOUT` finding |
| Connection refused | Log, skip module, continue scan |
| 403 Forbidden | Note as `Access Restricted` informational finding |
| 404 Not Found | Skip — no vulnerability indicator |
| 500 Internal Error | Flag as `Potential Error Handling Issue` — medium severity |
| SSL handshake failure | Critical finding — `TLS negotiation failed` |
| DNS resolution failure | Reject target before scan starts |
| Rate limit (429) | Back off exponentially, retry up to 3 times |
| Redirect loop | Abort target, log as `Redirect Loop Detected` — high severity |

---

## 7. Extensibility Points

### Adding a New Module
1. Create `src/zerotrace/engine/modules/my_module.py`
2. Inherit from `BaseModule`
3. Implement `execute()` method
4. Register in `src/zerotrace/engine/modules/__init__.py`
5. Write unit tests in `tests/test_modules/test_my_module.py`

### Adding an External Tool Integration
1. Create `src/zerotrace/engine/integrations/my_tool.py`
2. Use subprocess to invoke the tool binary
3. Parse output and map to `Finding` objects
4. Handle binary availability gracefully (skip if not installed)

### Customizing Report Templates
1. Edit files in `src/zerotrace/reporting/templates/`
2. Reports use Jinja2 — standard template syntax
3. PDF templates use PyMuPDF drawing primitives
