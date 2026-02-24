"""
Rate limiting via slowapi (Starlette-compatible Limits wrapper).

Strategy:
  - Global fallback: 30 requests/minute for unauthenticated endpoints
  - Per-role limits: viewer=60, analyst=200, admin=500 req/min
  - Key function: tenant_id + user_id → fair per-user limiting
  - Redis backend recommended for multi-instance deployments
    (swap InMemoryRateLimiter for RedisRateLimiter)

Usage in routes:
    @router.get("/data")
    @limiter.limit(get_role_limit)          # dynamic per-role limit
    async def get_data(request: Request, ...):
        ...

    @router.post("/auth/login")
    @limiter.limit("10/minute")             # fixed limit for auth endpoints
    async def login(request: Request, ...):
        ...
"""

from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


def get_tenant_user_key(request: Request) -> str:
    """
    Rate limit key: combines tenant + user for fair multi-tenant limiting.
    Falls back to IP address for unauthenticated requests.
    """
    tenant_id = getattr(request.state, "tenant_id", None)
    user_id = getattr(request.state, "user_id", None)

    if tenant_id and user_id:
        return f"tenant:{tenant_id}:user:{user_id}"

    # Unauthenticated — limit by IP
    return get_remote_address(request)


def get_role_limit(request: Request) -> str:
    """
    Dynamic rate limit resolver — returns different limits based on user role.
    Called by slowapi for each request decorated with @limiter.limit(get_role_limit).
    """
    role = getattr(request.state, "user_role", None)

    limit_map = {
        "viewer": settings.RATE_LIMIT_VIEWER,
        "analyst": settings.RATE_LIMIT_ANALYST,
        "admin": settings.RATE_LIMIT_ADMIN,
        "super_admin": "10000/minute",   # effectively unlimited
    }

    resolved = limit_map.get(role, settings.RATE_LIMIT_DEFAULT)
    logger.debug("rate_limit.resolved", role=role, limit=resolved)
    return resolved


# Primary limiter instance — imported across all routers
limiter = Limiter(
    key_func=get_tenant_user_key,
    default_limits=[settings.RATE_LIMIT_DEFAULT],
    # For Redis in production:
    # storage_uri="redis://redis:6379",
)
