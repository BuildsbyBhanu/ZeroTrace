# Phase 2 Slice 2 — Implementation Plan

## Goals
1. Improve findings quality in existing modules (headers.py, ssl_tls.py, cookies.py, recon.py)
2. Add exactly 2 new passive modules
3. Improve HTML reporting templates
4. Ensure all tests pass

## Tasks

### Task 1: Improve Existing Findings Quality
**Action**: Review and improve titles, evidence, and remediation advice in existing modules.
- headers.py: More specific titles, better remediation steps
- ssl_tls.py: Clearer severity descriptions
- cookies.py: Better cookie analysis detection
- recon.py: Improved information disclosure reporting

### Task 2: Add 2 New Passive Modules

#### Module 2a: Information Disclosure Module (`info_disclosure.py`)
- Check for server error pages that reveal internal paths
- Detect debug mode indicators in responses
- Identify version numbers in HTML meta tags or JavaScript
- Check for exposed backup files (.bak, .old, ~)
- **Safe, passive, limited requests (max 5)**

#### Module 2b: Session Security Module (`session_security.py`)
- Analyze session cookie patterns
- Check for predictable session ID formats
- Detect missing secure session configuration
- Identify default/weak session names
- **Safe, passive, uses existing header data**

### Task 3: Improve Reporting Templates
- Update `results.html` with cleaner layout
- Improve severity badge styling
- Enhance `report.html` CLI export template
- Apply better-ui, better-layout, better-typography guidelines

### Task 4: Testing
- Write tests for new Information Disclosure module
- Write tests for new Session Security module
- Run full test suite to verify no regressions

## Constraints
- No external/public website scanning
- Only safe local targets
- Keep request limits strict
- Maintain existing test compatibility
