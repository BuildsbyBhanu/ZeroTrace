"""FastAPI dependencies for ZeroTrace API."""

from __future__ import annotations

from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession

from zerotrace.database import get_session


# Status label mappings for human-readable display
STATUS_LABELS = {
    "confirmed": "Confirmed",
    "potential": "Potential",
    "informational": "Informational",
    "requires_manual_verification": "Requires Manual Verification",
}


def get_status_labels() -> str:
    """Return a comma-separated list of available status labels."""
    return ", ".join(STATUS_LABELS.values())


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields an async DB session."""
    async with get_session() as session:
        yield session
