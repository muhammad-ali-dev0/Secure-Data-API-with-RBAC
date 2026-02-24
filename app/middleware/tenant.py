"""
Tenant middleware — extracts JWT claims into request.state early in the pipeline.

This runs before route handlers so that:
  1. AuditLogMiddleware can log tenant/user context on every request
  2. Rate limiter can apply per-user limits via get_tenant_user_key()
  3. Routes can access request.state.tenant_id without re-decoding the token

Note: This middleware does NOT enforce authentication — that's done by the
      get_current_user dependency in individual routes. This only extracts
      context if a valid token is present.
"""

from jose import JWTError, jwt
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.config import settings


class TenantMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        # Default state — unauthenticated
        request.state.tenant_id = None
        request.state.user_id = None
        request.state.user_role = None

        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            try:
                payload = jwt.decode(
                    token,
                    settings.JWT_SECRET_KEY,
                    algorithms=[settings.JWT_ALGORITHM],
                )
                request.state.tenant_id = payload.get("tenant_id")
                request.state.user_id = payload.get("sub")
                request.state.user_role = payload.get("role")
            except JWTError:
                # Invalid token — don't set state, let route dependencies handle auth
                pass

        return await call_next(request)
