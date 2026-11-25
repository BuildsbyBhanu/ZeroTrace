# ZeroTrace — Project Structure

## 1. Root Layout

All paths are relative to `K:\ZeroTrace`.

```
K:\ZeroTrace\
│
├── .gitignore                  # Version control ignore rules
├── .env.example                # Environment variable template
├── pyproject.toml              # Python project config (deps, tools, metadata)
├── requirements.txt            # Frozen dependency list
├── Makefile                    # Common development commands
│
├── README.md                   # Project overview and quick start
├── CHANGELOG.md                # Release history
│
├── docs/                       # Planning and design documents
│   ├── PRODUCT_REQUIREMENTS.md
│   ├── TECHNICAL_ARCHITECTURE.md
│   ├── TECH_STACK_EVALUATION.md
│   ├── SECURITY_REQUIREMENTS.md
│   ├── DEVELOPMENT_ROADMAP.md
│   ├── PROJECT_STRUCTURE.md     ← this file
│   ├── SCANNING_ENGINE_DESIGN.md
│   └── OPEN_SOURCE_TOOL_EVALUATION.md
│
├── src/                        # Application source code
│   └── zerotrace/
│       │
│       ├── __init__.py
│       │
│       ├── main.py             # Application entry point (FastAPI app factory)
│       ├── config.py           # Settings via pydantic-settings
│       ├── logging_config.py   # Structured logging setup
│       │
│       ├── api/                # HTTP API layer
│       │   ├── __init__.py
│       │   ├── router.py       # API route dispatcher
│       │   ├── routes/
│       │   │   ├── scans.py    # /scans endpoints
│       │   │   ├── targets.py  # /targets endpoints
│       │   │   ├── reports.py  # /reports endpoints
│       │   │   ├── config.py   # /config endpoints
│       │   │   └── ws.py       # WebSocket progress stream
│       │   └── dependencies.py # Shared dependency injection
│       │
│       ├── schemas/            # Pydantic request/response models
│       │   ├── __init__.py
│       │   ├── scan.py         # ScanRequest, ScanResult
│       │   ├── finding.py      # Finding, FindingList
│       │   ├── target.py       # TargetCreate, TargetResponse
│       │   └── report.py       # ReportFormat enum, export params
│       │
│       ├── templates/          # HTML templates (Jinja2 + HTMX)
│       │   ├── base.html       # Root layout with nav
│       │   ├── index.html      # Landing / scan submission page
│       │   ├── scan_progress.html
│       │   ├── findings.html   # Results dashboard
│       │   ├── finding_detail.html
│       │   └── components/     # Reusable partials
│       │       ├── severity_badge.html
│       │           ├── module_status.html
│       │
│       ├── static/             # Static assets
│       │   ├── css/
│       │   │   └── app.css     # Compiled Tailwind output
│       │   ├── js/
│       │   │   └── app.js      # HTMX wiring, custom JS
│       │   └── images/
│       │
│       ├── engine/             # Core scanning engine
│       │   ├── __init__.py
│       │   ├── orchestrator.py # Scan job coordinator
│       │   ├── context.py      # ScanContext — shared state per scan
│       │   ├── validator.py    # URL validation, SSRF prevention
│       │   ├── rate_limiter.py # Request throttling
│       │   └── modules/        # Detection modules
│       │       ├── __init__.py
│       │       ├── base.py     # BaseModule abstract class
│       │       ├── recon.py    # Technology fingerprinting
│       │       ├── headers.py  # Security header analysis
│       │       ├── ssl_tls.py  # Certificate and TLS checks
│       │       ├── cookies.py  # Cookie security review
│       │       ├── information_disclosure.py
│       │       ├── misconfiguration.py
│       │       ├── cors.py
│       │       ├── csp.py
│       │       └── integrations/
│       │           └── nucle.py  # Nuclei bridge (Phase 2)
│       │
│       ├── database/           # Data persistence
│       │   ├── __init__.py
│       │   ├── connection.py   # Engine + session factory
│       │   ├── models/
│       │   │   ├── __init__.py
│       │   │   ├── scan.py     # Scan ORM model
│       │   │   ├── finding.py  # Finding ORM model
│       │   │   ├── target.py   # Target ORM model
│       │   │   └── credential.py
│       │   └── migrations/     # Alembic migrations
│       │       ├── env.py
│       │       └── versions/
│       │
│       ├── reporting/          # Report generation
│       │   ├── __init__.py
│       │   ├── html_report.py  # Jinja2 → HTML
│       │   ├── pdf_report.py   # PyMuPDF PDF generation
│       │   ├── json_report.py  # Structured JSON export
│       │   └── templates/      # Report-specific templates
│       │       ├── html/
│       │       └── pdf/
│       │
│       └── crypto/             # Encryption utilities
│           ├── __init__.py
│           └── credentials.py  # Fernet encryption/decryption
│
├── cli/                        # CLI application
│   ├── __init__.py
│   └── main.py                 # Typer CLI entry point
│
├── tests/                      # Test suite
│   ├── __init__.py
│   ├── conftest.py             # Shared fixtures
│   ├── test_validation.py
│   ├── test_engine.py
│   ├── test_modules/
│   │   ├── test_headers.py
│   │   ├── test_ssl_tls.py
│   │   └── test_cookies.py
│   ├── test_api/
│   │   ├── test_scans.py
│   │   └── test_reports.py
│   └── test_reporting.py
│
├── data/                       # Runtime data (gitignored)
│   ├── zerotrace.db            # SQLite database
│   ├── audit.log.jsonl         # Immutable audit log
│   ├── reports/                # Generated report files
│   └── cache/                  # Scan result cache
│
├── scripts/                    # Utility scripts
│   ├── init_db.py              # Database initialization
│   ├── seed_test_data.py       # Test fixture population
│   └── generate_cert.py        # Self-signed cert for local testing
│
└── deploy/                     # Deployment configs
    ├── Dockerfile              # Multi-stage container build
    ├── docker-compose.yml      # Dev stack (app + postgres)
    └── nginx.conf              # Reverse proxy config (future)
```

---

## 2. Directory Responsibilities

| Directory | Responsibility |
|-----------|---------------|
| `src/zerotrace/api/` | HTTP request handling, routing, response serialization |
| `src/zerotrace/schemas/` | Type-safe request/response contracts (Pydantic models) |
| `src/zerotrace/templates/` | Server-rendered HTML pages with HTMX enhancements |
| `src/zerotrace/static/` | CSS, JavaScript, and image assets served by FastAPI |
| `src/zerotrace/engine/` | Core scanning logic — orchestrator, validators, modules |
| `src/zerotrace/engine/modules/` | Individual detection capabilities, each a pluggable class |
| `src/zerotrace/database/` |ORM models, connection management, schema migrations |
| `src/zerotrace/reporting/` | Report rendering across HTML, PDF, and JSON formats |
| `src/zerotrace/crypto/` | Credential encryption utilities — isolated security boundary |
| `cli/` | Command-line interface — reuses engine, independent entry point |
| `tests/` | All test code — mirrors source structure for discoverability |
| `data/` | Runtime-generated files — excluded from version control |
| `scripts/` | One-off utility scripts — not part of the application |
| `deploy/` | Infrastructure-as-code artifacts — container and proxy configs |
| `docs/` | Human-readable planning and design documentation |

---

## 3. Key Design Decisions Reflected in Structure

1. **`src/` namespace packaging** — Clean import path (`from zerotrace.engine.orchestrator import ...`), installable as a package.

2. **`engine/modules/` flat structure** — Each module is independently testable and swappable. Adding a new detector means adding one file and registering it in `__init__.py`.

3. **`crypto/` isolated boundary** — Encryption lives in its own module so credential handling is auditable and contained.

4. **`data/` gitignored** — Database, logs, and generated reports never enter version control.

5. **`cli/` separate from `src/`** — CLI is a distinct entry point sharing the engine, allowing the same code to power both interfaces without coupling.

6. **`templates/` and `static/` co-located** — FastAPI serves them directly; no build step needed for Phase 1.
