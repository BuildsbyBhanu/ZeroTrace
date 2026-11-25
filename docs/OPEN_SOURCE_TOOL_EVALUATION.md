# ZeroTrace — Open Source Tool Evaluation

## 1. Evaluation Purpose

Evaluate third-party open-source security tools for potential integration into ZeroTrace's scanning engine. Integration is optional — native modules are preferred where they provide equivalent coverage, and external tools are integrated only when they offer capabilities that are impractical to build from scratch.

---

## 2. Tool-by-Tool Analysis

### 2.1 OWASP ZAP (Zed Attack Proxy)

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Full-scope web application security scanner |
| **License** | Apache 2.0 (permissive) |
| **Language** | Java |
| **Windows Support** | Requires JRE; command-line mode available |
| **Capabilities** | Spidering, active scanning, fuzzing, extension system, AWVS-like coverage |
| **Limitations** | Heavy resource usage, slow startup, requires Java runtime, CLI automation is complex |
| **Integration Complexity** | High — spawn as subprocess, parse XML/JSON output, manage lifecycle |
| **Verdict** | **Not integrated in Phase 1.** Too heavy for a lightweight local tool. Architecture supports future integration via subprocess bridge, but native Python modules cover Phase 1 scope adequately. Worth revisiting for Deep Scan if native modules prove insufficient. |

### 2.2 Nuclei (ProjectDiscovery)

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Template-based vulnerability scanner |
| **License** | GPL v3 |
| **Language** | Go |
| **Windows Support** | Pre-built binary available for Windows |
| **Capabilities** | 10,000+ community templates, rapid detection, YAML templating, high performance |
| **Limitations** | GPL license compatibility concerns for commercial SaaS, template management overhead, requires internet for template updates |
| **Integration Complexity** | Medium — call as subprocess, parse JSON output, map findings to ZeroTrace schema |
| **Verdict** | **Recommended for Phase 2.** Nuclei's template ecosystem provides coverage that would take months to replicate. GPL v3 is acceptable for the standalone tool; if proprietary SaaS deployment emerges, a Docker-sidecar approach isolates the license boundary. Priority integration target after MVP. |

### 2.3 Nmap

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Network discovery and port scanning |
| **License** | Custom (free for most uses, not OSS strictly) |
| **Language** | C |
| **Windows Support** | Native Windows binary available |
| **Capabilities** | Port scanning, OS detection, scriptable NSE scripts |
| **Limitations** | Not web-application focused, aggressive scanning may alert WAFs, license ambiguity |
| **Integration Complexity** | Low-Medium |
| **Verdict** | **Not integrated.** ZeroTrace focuses on application-layer (L7) testing, not network-layer reconnaissance. Port scanning is outside scope and can trigger false-positive legal issues. The "reconnaissance" module instead gathers information from HTTP response headers and TLS fingerprints, which is safer and more relevant. |

### 2.4 testssl.sh

| Attribute | Detail |
|-----------|--------|
| **Purpose** | SSL/TLS configuration testing |
| **License** | GPL v2 |
| **Language** | Bash |
| **Windows Support** | ❌ Requires Unix shell — **incompatible with Windows natively** |
| **Capabilities** | Comprehensive TLS 1.0–1.3 testing, certificate analysis, cipher suite evaluation |
| **Limitations** | Shell-dependent, no Windows native support, GPL v2 |
| **Integration Complexity** | High (requires WSL or Cygwin on Windows) |
| **Verdict** | **Not integrated for Phase 1.** testssl.sh cannot run natively on Windows. Python-native TLS checking using the `ssl` module and `cryptography` library covers the same ground for Phase 1. Re-evaluate if WSL becomes part of the development strategy. |

### 2.5 Semgrep

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Static analysis (SAST) for multiple languages |
| **License** | LGPL v2.1 / EE |
| **Language** | OCaml (compiled binary) |
| **Windows Support** | Pre-built binaries available |
| **Capabilities** | Pattern matching, rule-based vulnerability detection, source-code analysis |
| **Limitations** | Requires source code access — incompatible with black-box scanning model |
| **Integration Complexity** | Medium |
| **Verdict** | **Out of scope.** Semgrep is a SAST tool requiring source code. ZeroTrace is explicitly a black-box DAST platform. Future architecture note: if a "Hybrid Scan" mode is added later, Semgrep could integrate as a supplementary module. Exclude from current roadmap. |

### 2.6 Trivy

| Attribute | Detail |
|-----------|--------|
| **Purpose** | Container and filesystem vulnerability scanner |
| **License** | GPL v2 |
| **Language** | Go |
| **Windows Support** | Pre-built binary available |
| **Capabilities** | CVE database, SBOM generation, container image scanning |
| **Limitations** | Focuses on infrastructure/container vulnerabilities, not web app vulnerabilities |
| **Integration Complexity** | Low |
| **Verdict** | **Out of scope.** Trivy scans deployed artifacts, not running web applications. Could be a complementary tool in a future "deployment assessment" workflow, but irrelevant to current product scope. |

---

## 3. Recommended Integration Strategy

```
Phase 1 (MVP):
├── Pure Python native modules
├── Python ssl/certifi for TLS checks
└── No external tool dependencies

Phase 2 (Enhanced Coverage):
├── Nuclei integration (subprocess bridge)
├── Optional: OWASP ZAP via Docker sidecar
└── Python native modules remain primary

Phase 3+ (Advanced):
├── Template marketplace (Nuclei-compatible custom templates)
├── CI/CD pipeline integration
└── Plugin system for third-party tool adapters
```

---

## 4. Why External Tools Are Deferred

1. **Dependency bloat** — Each external tool adds installation complexity, version management, and platform-specific concerns
2. **Windows friction** — testssl.sh fails natively; ZAP requires Java; all require download/manage cycles
3. **Legal clarity** — GPL tools in a potentially commercial product create licensing ambiguity
4. **Self-reliance** — Building native modules gives full control over output format, behavior, and safety guarantees
5. **Performance** — Python-native async scanning is faster than spawning and managing external processes for each module

The architecture leaves the door open for integration via a clean subprocess interface, but the MVP delivers value without any external binary dependencies beyond Python packages.
