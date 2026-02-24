"""
Analytics router — tenant-scoped data access with role-based permissions.

Permission matrix:
  GET  /analytics/events          → analyst, admin, super_admin
  POST /analytics/events          → analyst, admin, super_admin
  GET  /analytics/metrics/summary → viewer and above (own tenant only)
  POST /analytics/query           → analyst+ (complex aggregations)
  GET  /analytics/export          → analyst+ (Permission.EXPORT_DATA)
"""

import random
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.limiter import get_role_limit, limiter
from app.core.logging import get_logger
from app.core.security import (
    Permission,
    Role,
    TokenPayload,
    get_current_user,
    require_permission,
    require_same_tenant,
)
from app.models.analytics import AnalyticsEvent

router = APIRouter()
logger = get_logger(__name__)


# ── Schemas ────────────────────────────────────────────────────────────────────
class EventIn(BaseModel):
    event_type: str = Field(..., max_length=100)
    user_identifier: str = Field(..., max_length=255)
    session_id: str | None = None
    value: float | None = None
    source: str | None = None
    occurred_at: datetime | None = None


class EventOut(BaseModel):
    id: str
    tenant_id: str
    event_type: str
    user_identifier: str
    value: float | None
    source: str | None
    occurred_at: datetime

    model_config = {"from_attributes": True}


class MetricsSummary(BaseModel):
    tenant_id: str
    period: str
    total_events: int
    unique_users: int
    top_event_types: list[dict]
    generated_at: datetime


class QueryRequest(BaseModel):
    event_type: str | None = None
    start_date: datetime | None = None
    end_date: datetime | None = None
    group_by: str = Field(default="event_type", pattern="^(event_type|source|day)$")
    limit: int = Field(default=100, ge=1, le=10_000)


class QueryResult(BaseModel):
    query: dict
    results: list[dict]
    row_count: int
    tenant_id: str
    executed_at: datetime


# ── Endpoints ──────────────────────────────────────────────────────────────────
@router.get(
    "/events",
    response_model=list[EventOut],
    summary="List recent analytics events for the current tenant",
)
@limiter.limit(get_role_limit)
async def list_events(
    request: Request,
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=1000),
    event_type: str | None = None,
    current_user: TokenPayload = Depends(
        require_permission(Permission.READ_TENANT_DATA)
    ),
    db: AsyncSession = Depends(get_db),
):
    # Always scope to current user's tenant — core isolation guarantee
    query = (
        select(AnalyticsEvent)
        .where(AnalyticsEvent.tenant_id == current_user.tenant_id)
        .order_by(AnalyticsEvent.occurred_at.desc())
        .offset(skip)
        .limit(limit)
    )

    if event_type:
        query = query.where(AnalyticsEvent.event_type == event_type)

    result = await db.execute(query)
    events = result.scalars().all()

    logger.info(
        "analytics.events_listed",
        user_id=current_user.sub,
        tenant_id=current_user.tenant_id,
        count=len(events),
        filter_event_type=event_type,
    )

    return events


@router.post(
    "/events",
    response_model=EventOut,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest a new analytics event",
)
@limiter.limit(get_role_limit)
async def create_event(
    request: Request,
    body: EventIn,
    current_user: TokenPayload = Depends(
        require_permission(Permission.RUN_QUERIES)
    ),
    db: AsyncSession = Depends(get_db),
):
    event = AnalyticsEvent(
        tenant_id=current_user.tenant_id,
        event_type=body.event_type,
        user_identifier=body.user_identifier,
        session_id=body.session_id,
        value=body.value,
        source=body.source,
        occurred_at=body.occurred_at or datetime.now(timezone.utc),
    )
    db.add(event)
    await db.flush()

    logger.info(
        "analytics.event_created",
        event_id=event.id,
        event_type=event.event_type,
        tenant_id=event.tenant_id,
        user_id=current_user.sub,
    )
    return event


@router.get(
    "/metrics/summary",
    response_model=MetricsSummary,
    summary="Get aggregated metrics summary (all roles)",
)
@limiter.limit(get_role_limit)
async def metrics_summary(
    request: Request,
    period: str = Query(default="30d", pattern="^(7d|30d|90d)$"),
    current_user: TokenPayload = Depends(get_current_user),  # all roles allowed
    db: AsyncSession = Depends(get_db),
):
    tenant_id = current_user.tenant_id

    # Count total events and unique users
    count_result = await db.execute(
        select(
            func.count(AnalyticsEvent.id).label("total"),
            func.count(func.distinct(AnalyticsEvent.user_identifier)).label("unique_users"),
        ).where(AnalyticsEvent.tenant_id == tenant_id)
    )
    counts = count_result.one()

    # Top event types
    top_result = await db.execute(
        select(
            AnalyticsEvent.event_type,
            func.count(AnalyticsEvent.id).label("count"),
        )
        .where(AnalyticsEvent.tenant_id == tenant_id)
        .group_by(AnalyticsEvent.event_type)
        .order_by(func.count(AnalyticsEvent.id).desc())
        .limit(5)
    )
    top_types = [{"event_type": r.event_type, "count": r.count} for r in top_result]

    return MetricsSummary(
        tenant_id=tenant_id,
        period=period,
        total_events=counts.total,
        unique_users=counts.unique_users,
        top_event_types=top_types,
        generated_at=datetime.now(timezone.utc),
    )


@router.post(
    "/query",
    response_model=QueryResult,
    summary="Run an aggregation query (analyst+ only)",
)
@limiter.limit(get_role_limit)
async def run_query(
    request: Request,
    body: QueryRequest,
    current_user: TokenPayload = Depends(
        require_permission(Permission.RUN_QUERIES)
    ),
    db: AsyncSession = Depends(get_db),
):
    logger.info(
        "analytics.query_started",
        user_id=current_user.sub,
        tenant_id=current_user.tenant_id,
        query=body.model_dump(exclude_none=True),
    )

    # Build dynamic query — always tenant-scoped
    stmt = (
        select(
            AnalyticsEvent.event_type,
            AnalyticsEvent.source,
            func.count(AnalyticsEvent.id).label("count"),
            func.avg(AnalyticsEvent.value).label("avg_value"),
        )
        .where(AnalyticsEvent.tenant_id == current_user.tenant_id)
        .group_by(AnalyticsEvent.event_type, AnalyticsEvent.source)
        .order_by(func.count(AnalyticsEvent.id).desc())
        .limit(body.limit)
    )

    if body.event_type:
        stmt = stmt.where(AnalyticsEvent.event_type == body.event_type)
    if body.start_date:
        stmt = stmt.where(AnalyticsEvent.occurred_at >= body.start_date)
    if body.end_date:
        stmt = stmt.where(AnalyticsEvent.occurred_at <= body.end_date)

    result = await db.execute(stmt)
    rows = result.all()

    results = [
        {
            "event_type": r.event_type,
            "source": r.source,
            "count": r.count,
            "avg_value": round(r.avg_value, 4) if r.avg_value else None,
        }
        for r in rows
    ]

    logger.info(
        "analytics.query_completed",
        user_id=current_user.sub,
        tenant_id=current_user.tenant_id,
        row_count=len(results),
    )

    return QueryResult(
        query=body.model_dump(exclude_none=True),
        results=results,
        row_count=len(results),
        tenant_id=current_user.tenant_id,
        executed_at=datetime.now(timezone.utc),
    )


@router.get(
    "/export",
    summary="Export analytics data as NDJSON (analyst+ only)",
)
@limiter.limit("10/minute")   # strict — exports are expensive
async def export_data(
    request: Request,
    current_user: TokenPayload = Depends(
        require_permission(Permission.EXPORT_DATA)
    ),
    db: AsyncSession = Depends(get_db),
):
    from fastapi.responses import StreamingResponse

    logger.warning(  # warning level — data exports are high-sensitivity
        "analytics.export_started",
        user_id=current_user.sub,
        tenant_id=current_user.tenant_id,
        role=current_user.role,
    )

    # Stream large datasets rather than loading into memory
    async def generate_ndjson():
        import json
        batch_size = 500
        offset = 0
        while True:
            result = await db.execute(
                select(AnalyticsEvent)
                .where(AnalyticsEvent.tenant_id == current_user.tenant_id)
                .order_by(AnalyticsEvent.occurred_at)
                .offset(offset)
                .limit(batch_size)
            )
            batch = result.scalars().all()
            if not batch:
                break
            for event in batch:
                yield json.dumps({
                    "id": event.id,
                    "event_type": event.event_type,
                    "user_identifier": event.user_identifier,
                    "value": event.value,
                    "source": event.source,
                    "occurred_at": event.occurred_at.isoformat(),
                }) + "\n"
            offset += batch_size

    return StreamingResponse(
        generate_ndjson(),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": f"attachment; filename=export_{current_user.tenant_id}.ndjson"},
    )
