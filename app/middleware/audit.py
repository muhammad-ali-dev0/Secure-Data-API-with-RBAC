"""
Audit log middleware — captures every inbound request and outbound response.

Emits a structured log entry for every request containing:
  - request_id (UUID, injected into request.state for downstream use)
  - method, path, status_code, duration_ms
  - tenant_id, user_id (if authenticated — set by TenantMiddleware)
  - client_ip, user_agent

In production, ship these JSON logs to your SIEM (Datadog, Splunk, CloudWatch).
Sensitive endpoints (auth, user creation) emit additional audit events.
"""

import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.logging import get_logger

logger = get_logger(__name__)

# Paths to skip from access logs (reduce noise)
SKIP_PATHS = {"/health", "/health/live", "/health/ready", "/docs", "/redoc", "/openapi.json"}


class AuditLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        # Inject a unique request ID traceable through all log entries
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id

        start_time = time.perf_counter()
        response = await call_next(request)
        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        # Propagate request_id to response headers for client-side tracing
        response.headers["X-Request-ID"] = request_id

        if request.url.path in SKIP_PATHS:
            return response

        # Pull identity context set by TenantMiddleware (may be None for unauth requests)
        tenant_id = getattr(request.state, "tenant_id", None)
        user_id = getattr(request.state, "user_id", None)
        user_role = getattr(request.state, "user_role", None)

        log_level = "warning" if response.status_code >= 400 else "info"
        log_fn = getattr(logger, log_level)

        log_fn(
            "http.request",
            request_id=request_id,
            method=request.method,
            path=request.url.path,
            query=str(request.query_params) or None,
            status_code=response.status_code,
            duration_ms=duration_ms,
            tenant_id=tenant_id,
            user_id=user_id,
            user_role=user_role,
            client_ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )

        return response
