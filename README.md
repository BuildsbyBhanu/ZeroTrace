# ZeroTrace
<<<<<<< HEAD
Automated Web Application Vulnerability Assessment Tool
=======

**Automated Web Application Security Assessment Platform**

A professional-grade security scanner with a web UI and CLI, built entirely in Python. Designed for beginners through professionals, scanning websites for OWASP Top 10 vulnerabilities with clear, actionable reports.

---

## Quick Start

### Prerequisites

- Python 3.10+
- Git

### Installation

```bash
cd K:\ZeroTrace
pip install -e ".[dev]"
```

### Initialize Database

```bash
make init-db
```

### Run the Server

```bash
make dev-server
```

Then open **[http://localhost:8000](http://localhost:8000)** in your browser.

API documentation is available at **[http://localhost:8000/docs](http://localhost:8000/docs)**.

### Use the CLI

⚠️ **Only scan systems you own or have explicit permission to test. Unauthorized scanning is illegal.**

```bash
# Safe local examples (authorized targets only)
zerotrace scan http://localhost:8080 --profile quick
zerotrace scan http://127.0.0.1:3000 --profile standard --output json
zerotrace scan file:///path/to/local/webapp --profile deep --output html

# API endpoint examples
# POST /api/v1/scans with {"target_url": "http://localhost:8080", "profile": "quick"}
```

---

## Project Structure

```
K:\ZeroTrace\
├── src/zerotrace/    # Main application (FastAPI backend + engine)
├── cli/              # Command-line interface (Typer)
├── tests/            # Test suite
├── docs/             # Design documents
├── data/             # Runtime data (gitignored)
├── deploy/           # Docker & deployment configs
└── scripts/          # Utility scripts
```

See [docs/PROJECT_STRUCTURE.md](docs/PROJECT_STRUCTURE.md) for the full layout.

---

## Scanning Profiles

| Profile | Coverage | Best For |
|---------|----------|----------|
| **Quick** | Headers, SSL/TLS, cookies, basic recon | Fast health checks |
| **Standard** | Quick + OWASP common vulns, disclosure, misconfigs | Regular assessments |
| **Deep** | Standard + authenticated testing, deeper analysis | Thorough pen tests |
| **Custom** | Pick individual modules | Targeted scans |

---

## Key Design Decisions

- **Pure Python stack** — No external binary dependencies for Phase 1
- **SQLite for development** — Zero configuration; migrates to PostgreSQL for production
- **HTMX frontend** — No npm build step required; modern reactive UX
- **Modular engine** — Each vulnerability check is an isolated, testable module
- **Safety-first scanning** — SSRF prevention, private IP blocking, rate limiting built in

---

## Security Policy

ZeroTrace performs automated security testing. Always ensure you have **explicit authorization** before scanning any target. Never scan systems you do not own or have permission to test.

See [docs/SECURITY_REQUIREMENTS.md](docs/SECURITY_REQUIREMENTS.md) for detailed safety guarantees.

---

## Documentation

| Document | Description |
|----------|-------------|
| [Product Requirements](docs/PRODUCT_REQUIREMENTS.md) | What ZeroTrace does and who it's for |
| [Technical Architecture](docs/TECHNICAL_ARCHITECTURE.md) | System design and component overview |
| [Tech Stack Evaluation](docs/TECH_STACK_EVALUATION.md) | Technology choices and rationale |
| [Security Requirements](docs/SECURITY_REQUIREMENTS.md) | Safety, authorization, and data protection rules |
| [Scanning Engine Design](docs/SCANNING_ENGINE_DESIGN.md) | How the engine works internally |
| [Development Roadmap](docs/DEVELOPMENT_ROADMAP.md) | Phased implementation plan |
| [Open Source Tool Evaluation](docs/OPEN_SOURCE_TOOL_EVALUATION.md) | Third-party tool assessment |

---

## License

MIT
>>>>>>> 4b987c3 (ZeroTrace v0.1.0 - OWASP Top 10 Security Scanner)
