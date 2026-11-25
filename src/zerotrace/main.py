"""FastAPI application factory for ZeroTrace."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from zerotrace.config import settings
from zerotrace.logging_config import setup_logging


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan: startup and shutdown events."""
    # Startup
    setup_logging()
    from zerotrace.logging_config import get_logger
    from zerotrace.database import init_db, shutdown_db

    logger = get_logger("app")
    logger.info("ZeroTrace starting up", extra={"version": settings.app_version})
    logger.info(
        "Database URL: %s",
        settings.database_url.split("@")[-1] if "@" in settings.database_url else settings.database_url,
    )

    # Initialize database tables
    await init_db()

    yield

    # Shutdown
    logger.info("ZeroTrace shutting down")
    await shutdown_db()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="Automated Web Application Security Assessment Platform",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"] if settings.debug else [],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Import routes here to avoid circular imports
    from zerotrace.api.router import api_router, html_router

    # Include HTML routes at root level (no prefix)
    app.include_router(html_router)

    # Include API routes under /api/v1 prefix
    app.include_router(api_router, prefix="/api/v1")

    @app.get("/health")
    async def health_check():
        return {"status": "healthy", "service": settings.app_name, "version": settings.app_version}

    return app


# Module-level app instance (used by uvicorn directly)
app = create_app()