"""
Secure Data API — Multi-Tenant Analytics Platform
JWT Authentication · RBAC · Rate Limiting · Structured Logging
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.core.config import settings
from app.core.database import init_db
from app.core.limiter import limiter
from app.core.logging import get_logger, setup_logging
from app.middleware.audit import AuditLogMiddleware
from app.middleware.tenant import TenantMiddleware
from app.routers import analytics, auth, health, users

setup_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle management."""
    logger.info("api.startup", version=settings.API_VERSION, env=settings.ENVIRONMENT)
    await init_db()
    logger.info("api.database_ready")
    yield
    logger.info("api.shutdown")


app = FastAPI(
    title="Secure Data API",
    description="""
## Multi-Tenant Analytics Platform API

A production-grade REST API demonstrating enterprise security patterns:

- **JWT Authentication** — Access + refresh token flow with rotation
- **Role-Based Access Control** — Hierarchical permissions (viewer → analyst → admin → super_admin)
- **Rate Limiting** — Per-tenant, per-role sliding window limits
- **Structured Logging** — JSON audit logs for every sensitive operation
- **Multi-Tenancy** — Complete data isolation between tenants

### Roles & Permissions

| Role | Rate Limit | Permissions |
|------|-----------|-------------|
| `viewer` | 60/min | Read own tenant data |
| `analyst` | 200/min | Read + aggregate queries |
| `admin` | 500/min | User management within tenant |
| `super_admin` | unlimited | Cross-tenant access |
    """,
    version=settings.API_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── Middleware (order matters — outermost runs first) ─────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(AuditLogMiddleware)
app.add_middleware(TenantMiddleware)

# ── Rate limit error handler ───────────────────────────────────────────────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# ── Global exception handler ───────────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(
        "api.unhandled_exception",
        path=request.url.path,
        method=request.method,
        error=str(exc),
        exc_info=True,
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "request_id": request.state.request_id},
    )


# ── Routers ────────────────────────────────────────────────────────────────────
app.include_router(health.router, prefix="/health", tags=["Health"])
app.include_router(auth.router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(users.router, prefix="/api/v1/users", tags=["Users"])
app.include_router(analytics.router, prefix="/api/v1/analytics", tags=["Analytics"])
