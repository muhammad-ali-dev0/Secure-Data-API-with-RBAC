"""
Security core: JWT creation/validation, password hashing, RBAC permissions.

Architecture:
  - Access tokens (15 min) — short-lived, stateless, carried in Authorization header
  - Refresh tokens (7 days) — longer-lived, stored in DB, rotated on use
  - Roles are hierarchical: super_admin > admin > analyst > viewer
  - Permissions are additive — higher roles inherit all lower permissions
"""

from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import ExpiredSignatureError, JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.core.logging import get_logger

logger = get_logger(__name__)

# ── Password hashing ───────────────────────────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer()


def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# ── Roles & Permissions ────────────────────────────────────────────────────────
class Role(str, Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"


class Permission(str, Enum):
    # Data permissions
    READ_OWN_DATA = "read:own_data"
    READ_TENANT_DATA = "read:tenant_data"
    READ_ALL_DATA = "read:all_data"
    # Analytics permissions
    RUN_QUERIES = "analytics:run_queries"
    EXPORT_DATA = "analytics:export"
    # User management
    MANAGE_TENANT_USERS = "users:manage_tenant"
    MANAGE_ALL_USERS = "users:manage_all"
    # Admin
    VIEW_AUDIT_LOGS = "admin:audit_logs"
    MANAGE_TENANTS = "admin:manage_tenants"


# Hierarchical permission mapping — higher roles include all lower permissions
ROLE_PERMISSIONS: dict[Role, set[Permission]] = {
    Role.VIEWER: {
        Permission.READ_OWN_DATA,
    },
    Role.ANALYST: {
        Permission.READ_OWN_DATA,
        Permission.READ_TENANT_DATA,
        Permission.RUN_QUERIES,
        Permission.EXPORT_DATA,
    },
    Role.ADMIN: {
        Permission.READ_OWN_DATA,
        Permission.READ_TENANT_DATA,
        Permission.RUN_QUERIES,
        Permission.EXPORT_DATA,
        Permission.MANAGE_TENANT_USERS,
        Permission.VIEW_AUDIT_LOGS,
    },
    Role.SUPER_ADMIN: {p for p in Permission},  # all permissions
}


def has_permission(role: Role, permission: Permission) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, set())


# ── Token schemas ──────────────────────────────────────────────────────────────
class TokenPayload(BaseModel):
    sub: str           # user_id
    tenant_id: str
    role: Role
    jti: str           # JWT ID — used for refresh token rotation
    exp: datetime
    iat: datetime
    token_type: str    # "access" or "refresh"


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int    # access token TTL in seconds


# ── Token creation ─────────────────────────────────────────────────────────────
def create_token(
    user_id: str,
    tenant_id: str,
    role: Role,
    token_type: str = "access",
) -> tuple[str, str]:
    """
    Create a signed JWT. Returns (encoded_token, jti).
    jti (JWT ID) is stored in DB for refresh tokens to enable rotation/revocation.
    """
    now = datetime.now(timezone.utc)
    jti = str(uuid4())

    if token_type == "access":
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    else:
        expire = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    payload = {
        "sub": str(user_id),
        "tenant_id": tenant_id,
        "role": role.value,
        "jti": jti,
        "exp": expire,
        "iat": now,
        "token_type": token_type,
    }

    token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return token, jti


def create_token_pair(user_id: str, tenant_id: str, role: Role) -> TokenPair:
    access_token, _ = create_token(user_id, tenant_id, role, "access")
    refresh_token, _ = create_token(user_id, tenant_id, role, "refresh")
    return TokenPair(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


# ── Token validation ───────────────────────────────────────────────────────────
def decode_token(token: str) -> TokenPayload:
    """Decode and validate a JWT. Raises HTTPException on any failure."""
    try:
        payload: dict[str, Any] = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        return TokenPayload(**payload)

    except ExpiredSignatureError:
        logger.warning("auth.token_expired")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except JWTError as e:
        logger.warning("auth.token_invalid", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ── FastAPI dependencies ───────────────────────────────────────────────────────
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> TokenPayload:
    """
    Dependency: validates Bearer token and returns the decoded payload.
    Inject this into any route that requires authentication.
    """
    payload = decode_token(credentials.credentials)

    if payload.token_type != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh tokens cannot be used for API access",
        )

    # Optionally verify user still exists and is active in DB
    # (skip for pure stateless JWT; add for revocation support)
    return payload


def require_role(*allowed_roles: Role):
    """
    Dependency factory: raises 403 if the authenticated user's role
    is not in the allowed set.

    Usage:
        @router.get("/admin-only")
        async def admin_endpoint(user = Depends(require_role(Role.ADMIN, Role.SUPER_ADMIN))):
            ...
    """
    async def _check(current_user: TokenPayload = Depends(get_current_user)) -> TokenPayload:
        if current_user.role not in allowed_roles:
            logger.warning(
                "auth.forbidden",
                user_id=current_user.sub,
                user_role=current_user.role,
                required_roles=[r.value for r in allowed_roles],
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{current_user.role}' is not authorized for this resource",
            )
        return current_user

    return _check


def require_permission(permission: Permission):
    """
    Dependency factory: raises 403 if the user's role lacks a specific permission.

    Usage:
        @router.post("/export")
        async def export(user = Depends(require_permission(Permission.EXPORT_DATA))):
            ...
    """
    async def _check(current_user: TokenPayload = Depends(get_current_user)) -> TokenPayload:
        if not has_permission(current_user.role, permission):
            logger.warning(
                "auth.permission_denied",
                user_id=current_user.sub,
                user_role=current_user.role,
                required_permission=permission.value,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission.value}' required",
            )
        return current_user

    return _check


def require_same_tenant(current_user: TokenPayload, target_tenant_id: str) -> None:
    """
    Validate that a user can only access resources within their own tenant,
    unless they are a super_admin.
    """
    if current_user.role == Role.SUPER_ADMIN:
        return  # super_admin bypasses tenant isolation
    if current_user.tenant_id != target_tenant_id:
        logger.warning(
            "auth.cross_tenant_access_denied",
            user_id=current_user.sub,
            user_tenant=current_user.tenant_id,
            target_tenant=target_tenant_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cross-tenant data access is not permitted",
        )
