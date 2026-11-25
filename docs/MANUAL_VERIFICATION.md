# Manual Verification Guide for allow_localhost Feature

This document provides step-by-step instructions for manually verifying the `allow_localhost` configuration option and SSRF protection behavior.

## Overview

The `allow_localhost` feature allows developers to enable local development testing while maintaining SSRF protection for production environments. This is a security-critical feature that requires careful verification.

## Quick Test Commands

```bash
# 1. Start a weak security test server on port 8889
cd K:/ZeroTrace
python -c "from zerotrace.test_server import start_test_server; import time; t, s = start_test_server(8889, False); time.sleep(30)"

# 2. Set environment variable (in another terminal)
set ZEROTRACE_ALLOW_LOCALHOST=true

# 3. Run tests
python -m pytest tests/test_local_scan_integration.py tests/test_validator.py -v
```

## Verification Steps

### 1. SSRF Protection - Default Behavior (allow_localhost=false)

**Expected**: All localhost/127.x.x.x requests should be blocked.

```bash
# Without setting ZEROTRACE_ALLOW_LOCALHOST=true
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target_url":"http://127.0.0.1:8889/","profile":"quick"}'

# Check scan progress - should show failed with SSRF error
curl http://localhost:8000/api/v1/scans/{scan_id}/progress
```

**Expected response**: `{"status": "failed", "error_message": "Loopback/reserved IP..."}`

### 2. Cloud Metadata Always Blocked

**Expected**: 169.254.169.254 is ALWAYS blocked even with allow_localhost=true.

```bash
# Even with ZEROTRACE_ALLOW_LOCALHOST=true
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target_url":"http://169.254.169.254/latest/meta-data/","profile":"quick"}'
```

**Expected response**: Scan fails with "Cloud metadata endpoint blocked"

### 3. Private LAN Always Blocked

**Expected**: 10.x, 172.16-31.x, 192.168.x are ALWAYS blocked.

```bash
# Test private IP ranges
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target_url":"http://192.168.1.1/","profile":"quick"}'
```

### 4. Localhost Allowed with allow_localhost=true

**Expected**: Scans can proceed against localhost.

```bash
# Set environment variable
set ZEROTRACE_ALLOW_LOCALHOST=true

# Start server
python -c "from zerotrace.test_server import start_test_server; import time; t, s = start_test_server(8889, False); time.sleep(30)"

# Create scan
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target_url":"http://127.0.0.1:8889/","profile":"quick"}'

# Verify scan completes and finds missing security headers
curl http://localhost:8000/scan/{scan_id}
```

## Expected Findings for Weak Server (port 8889)

When scanning http://127.0.0.1:8889/ with a "quick" profile, you should see:

1. **Missing X-Frame-Options** (Category: A05) - Medium severity
2. **Missing Strict-Transport-Security** (Category: A02) - Medium severity  
3. **Missing Content-Security-Policy** (Category: A05) - Medium severity
4. **Server Version Disclosure** (Category: A05) - Low severity
5. **X-Powered-By Header Disclosure** (Category: A05) - Low severity

## Test URLs to Try

| URL | Expected Result |
|-----|-----------------|
| http://localhost:8889/ | ✓ Allowed when allow_localhost=true |
| http://127.0.0.1:8889/ | ✓ Allowed when allow_localhost=true |
| http://127.0.0.1:8889/ | ✗ Blocked when allow_localhost=false |
| http://169.254.169.254/ | ✗ Always blocked |
| http://10.0.0.1/ | ✗ Always blocked |
| http://192.168.1.1/ | ✗ Always blocked |
| http://172.16.0.1/ | ✗ Always blocked |

## Security Verification Checklist

- [ ] Default behavior blocks localhost
- [ ] Cloud metadata (169.254.169.254) always blocked
- [ ] Private LAN IPs always blocked
- [ ] allow_localhost=true permits localhost scans
- [ ] Error messages clearly indicate SSRF prevention
- [ ] UI displays error messages on failed scans
- [ ] No false positives for public URLs
- [ ] Tests pass: 187 passed

## Running the Full Test Suite

```bash
cd K:/ZeroTrace
python -m pytest tests/ -v --tb=short
```

Expected: 187 passed, 2 warnings

## Key Files Modified

1. `src/zerotrace/config.py` - Added `allow_localhost: bool = False`
2. `src/zerotrace/engine/validator.py` - SSRF protection with allow_localhost support
3. `src/zerotrace/templates/scan.html` - Error message display
4. `.env.example` - Configuration documentation
5. `tests/test_validator.py` - 24 new SSRF tests
6. `tests/test_local_scan_integration.py` - 12 integration tests

## Security Model

```
                    allow_localhost
                         |
        ┌───────────────┼───────────────┐
        │               │               │
       FALSE          TRUE            (default)
        │               │               
        ▼               ▼               
  Block all        Allow localhost    Secure default
  private IPs      only               (production-safe)
    │               │               
    └──────┬────────┘               
           │                         
           ▼                         
    ┌─────────────┐                  
    │ ALWAY(S)    │                  
    │ NEVER       │                  
    │ ALLOW:      │                  
    │ - Cloud     │                  
    │   metadata  │                  
    │   (169.254  │                  
    │   .169.254) │                  
    │ - Private   │                  
    │   LAN       │                  
    │   (10.x,    │                  
    │   172.16-31 │                  
    │   .x,       │                  
    │   192.168.x │                  
    │   .x)       │                  
    └─────────────┘
```

## Conclusion

The `allow_localhost` feature provides a secure-by-default configuration with opt-in capability for development testing. All production environments should leave `ZEROTRACE_ALLOW_LOCALHOST=false` (the default).