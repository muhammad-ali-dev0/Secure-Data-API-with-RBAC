"""
Health check endpoints — used by load balancers, Kubernetes probes, and monitoring.

/health/live  — liveness: is the process running?
/health/ready — readiness: is the app ready to serve traffic? (DB connected?)
/health       — full status with version info
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db

router = APIRouter()


class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str
    timestamp: datetime
    database: str


@router.get("/live", status_code=200, summary="Liveness probe")
async def liveness():
    return {"status": "alive"}


@router.get("/ready", status_code=200, summary="Readiness probe")
async def readiness(db: AsyncSession = Depends(get_db)):
    try:
        await db.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception:
        db_status = "unreachable"

    return {"status": "ready" if db_status == "connected" else "degraded", "database": db_status}


@router.get("", response_model=HealthResponse, summary="Full health status")
async def health(db: AsyncSession = Depends(get_db)):
    try:
        await db.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception:
        db_status = "unreachable"

    return HealthResponse(
        status="healthy" if db_status == "connected" else "degraded",
        version=settings.API_VERSION,
        environment=settings.ENVIRONMENT,
        timestamp=datetime.now(timezone.utc),
        database=db_status,
    )
