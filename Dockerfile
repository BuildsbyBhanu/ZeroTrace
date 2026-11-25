# Multi-stage Dockerfile for ZeroTrace
# Build stage
FROM python:3.12-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml ./
COPY README.md ./

# Create virtual environment and install dependencies
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --upgrade pip && \
    pip install --no-cache-dir ".[dev]"

# Runtime stage
FROM python:3.12-slim as runtime

WORKDIR /app

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash zerotrace

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code
COPY --chown=zerotrace:zerotrace src/ ./src/
COPY --chown=zerotrace:zerotrace cli/ ./cli/
COPY --chown=zerotrace:zerotrace alembic/ ./alembic/
COPY --chown=zerotrace:zerotrace migrations/ ./migrations/
COPY --chown=zerotrace:zerotrace pyproject.toml ./
COPY --chown=zerotrace:zerotrace .env.example .env.example 2>/dev/null || true

# Create necessary directories
RUN mkdir -p /app/data/reports /app/data/cache

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV ZEROTRACE_LOG_FORMAT=text

# Expose default port
EXPOSE 8000

# Switch to non-root user
USER zerotrace

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Default command
CMD ["python", "-m", "zerotrace.main"]