# ZeroTrace — Security Requirements Document

## 1. Introduction

ZeroTrace is a security tool that performs active and passive tests against web applications. The tool itself must be secured to the highest standard, because any weakness in ZeroTrace could expose users to significant risk — credential theft, SSRF abuse, or unauthorized scanning of protected systems.

This document defines the mandatory security requirements for ZeroTrace.

---

## 2. Target Validation & Authorization

### 2.1 URL Validation Pipeline

Every submitted URL passes through this validation chain before any network activity:

```
Input URL → Parse → Normalize → Validate protocol → Check target
    ↓
[REJECT] ← Check private IPs
    ↓
[REJECT] ← Check DNS rebinding
    ↓
[REJECT] ← Check redirect chains
    ↓
ALLOW → Scan proceeds
```

### 2.2 Private/Internal IP Blocking

The following address ranges are **hard-blocked** (cannot be scanned unless explicitly overridden by the user with a confirmation prompt):

| Range | Description |
|-------|-------------|
| `10.0.0.0/8` | RFC 1918 — Private |
| `172.16.0.0/12` | RFC 1918 — Private |
| `172.31.0.0/16` | RFC 1918 — Private |
| `192.168.0.0/16` | RFC 1918 — Private |
| `127.0.0.0/8` | Loopback |
| `169.254.0.0/16` | Link-local |
| `::1` | IPv6 loopback |
| `fc00::/7` | IPv6 unique local |
| `fe80::/10` | IPv6 link-local |

Implementation: Resolve hostname to IP before each request; reject if resolved IP falls in any blocked range.

### 2.3 SSRF Prevention

- No internal service discovery endpoints may be probed (e.g., `http://169.254.169.254/`, metadata endpoints)
- Cloud metadata URLs blocked: AWS (`169.254.169.254`), GCP (`metadata.google.internal`), Azure (`169.254.169.254`)
- File protocol (`file://`), `gopher://`, `dict://` — always rejected
- Internationalized domain names (IDN) converted to ASCII punycode before resolution
- All URLs normalized: trailing slashes removed, fragments stripped for scanning purposes

### 2.4 DNS Rebinding Protection

After initial DNS resolution, the scanner verifies that subsequent requests resolve to the same IP. If DNS rebinds to an internal IP during a scan:
1. Current scan is immediately cancelled
2. Alert logged to audit trail
3. User is notified

### 2.5 Redirect Handling

- Maximum redirect depth: **5 hops**
- Redirect chain logged and displayed in finding evidence
- Internal redirects allowed; external-to-internal transitions trigger warning
- Redirect targets validated through the same URL sanitizer

---

## 3. Request Safety Controls

### 3.1 Concurrency Limits

| Parameter | Default | Max Allowed | Rationale |
|-----------|---------|-------------|-----------|
| Global concurrency | 10 | 50 | Prevent overwhelming targets |
| Per-module concurrency | 5 | 20 | Module-specific rate control |
| Requests per second | 10 | 100 | Legal safe harbor threshold |

### 3.2 Timeouts

| Timeout | Default | Minimum | Max |
|---------|---------|---------|-----|
| Connection timeout | 10s | 3s | 30s |
| Read timeout | 30s | 10s | 120s |
| Total scan timeout | 600s | 60s | 1800s |
| Per-request timeout | 15s | 5s | 60s |

### 3.3 Rate Limiting

- Token bucket algorithm with configurable fill rate
- Exponential backoff on 429 responses from target
- Automatic pause-resume on connection refused/reset

### 3.4 User-Agent Spoofing

- Default UA: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) ZeroTrace/1.0 Security Scanner`
- Custom UA supported via configuration
- UA never contains "sqlmap" or other offensive scanner identifiers by default

---

## 4. Credential & Authentication Security

### 4.1 Storage

- Credentials encrypted at rest using **Fernet symmetric encryption** (`cryptography` library)
- Encryption key derived from a user-provided master password (not stored)
- Keys never written to disk or logs
- Scopes:
  - Username/password: AES-128-Fernet
  - Cookies: AES-128-Fernet
  - Tokens/API keys: AES-128-Fernet

### 4.2 Transmission

- Credentials sent only over HTTPS where possible
- Basic auth headers constructed in-memory, never persisted in raw form
- Session cookies rotated after scan completion

### 4.3 Logging

- Password fields redacted as `***REDACTED***` in all log output
- Cookie headers partially masked: only first 8 characters visible
- Audit log records authentication method used, not credentials themselves

---

## 5. Output Sanitization

### 5.1 Report Content

- HTML reports escape all user-supplied content (XSS prevention)
- Raw HTTP responses included in evidence are sanitized:
  - `<script>` tags stripped
  - Binary data encoded as base64
  - JavaScript execution blocks prevented

### 5.2 Log Files

- Structured JSON logging format
- PII scrubbing pass before file write
- Log rotation: max 50MB per file, keep 5 rotated files

---

## 6. Authentication & Authorization (Web UI)

### Phase 1 (Local Single-User)
- No multi-user authentication required
- Optional local PIN for access control
- All features available to the running user

### Phase 4 (SaaS)
- JWT-based authentication
- Role-based access control (viewer, scanner, admin)
- API key generation for programmatic access
- Session timeout after 30 minutes of inactivity

---

## 7. Audit Logging

Every significant action is logged to an immutable audit journal:

```json
{
  "timestamp": "ISO 8601",
  "action": "scan_started | scan_completed | credential_accessed | report_exported | config_changed",
  "target_url": "...",
  "profile": "...",
  "user_action": true/false,
  "result": "success | failure | error",
  "details": {}
}
```

Audit log stored at `data/audit.log.jsonl` — append-only, never truncated automatically.

---

## 8. Safe Testing Boundaries

### What IS allowed (with explicit authorization):
- Reading public HTTP/HTTPS responses
- Sending controlled probe requests (HEAD, GET, OPTIONS)
- Checking security headers and configurations
- Testing for common misconfigurations
- Submitting benign payloads to identifiable input vectors

### What is NEVER allowed:
- Brute-force authentication attempts
- SQL injection payloads that modify data
- Cross-site scripting that executes arbitrary code
- Denial-of-service style requests (heavy payloads, flood attacks)
- Any request that modifies server state without explicit user consent
- Probing non-target subdomains or related hosts

### Authorization Confirmation
Before starting any active scan (Standard, Deep, Custom), the user sees:
> "You are about to send network requests to [URL]. These requests are automated security tests that check for known vulnerability patterns. They will not damage the target but may trigger WAF alerts. Continue?"

---

## 9. Dependency Security

- Pin all dependency versions in `requirements.txt`
- Monthly review of `pip list --outdated`
- No dependencies from unknown/untrusted sources
- Supply chain verification for critical packages
- Vulnerability scanning of dependencies via `pip-audit` (optional phase 2)

---

## 10. Incident Response

If ZeroTrace detects it has been misconfigured or is being used against unintended targets:

1. Immediately halt all outbound network requests
2. Log the incident to audit trail
3. Display clear warning to user
4. Do not silently continue — require user acknowledgment
