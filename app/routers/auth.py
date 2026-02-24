"""
Authentication router — JWT login, token refresh, registration.

Endpoints:
  POST /api/v1/auth/register   — create account (viewer role by default)
  POST /api/v1/auth/login      — exchange credentials for token pair
  POST /api/v1/auth/refresh    — get new access token using refresh token
  POST /api/v1/auth/logout     — client-side token invalidation hint
  GET  /api/v1/auth/me         — return current user profile
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.core.limiter import limiter
from app.core.logging import get_logger
from app.core.security import (
    Role,
    TokenPair,
    TokenPayload,
    create_token_pair,
    decode_token,
    get_current_user,
)
from app.services.user_service import (
    InvalidCredentialsError,
    TenantNotFoundError,
    UserAlreadyExistsError,
    authenticate_user,
    create_tenant,
    create_user,
    get_tenant_by_slug,
    get_user_by_id,
)

router = APIRouter()
logger = get_logger(__name__)


# ── Request / Response schemas ─────────────────────────────────────────────────
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, description="Minimum 8 characters")
    full_name: str = Field(..., min_length=2, max_length=150)
    tenant_slug: str = Field(..., description="Tenant to join (must already exist)")

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class UserProfile(BaseModel):
    id: str
    email: str
    full_name: str
    role: str
    tenant_id: str
    is_active: bool

    model_config = {"from_attributes": True}


class RegisterResponse(BaseModel):
    user: UserProfile
    tokens: TokenPair
    message: str = "Account created successfully"


# ── Endpoints ──────────────────────────────────────────────────────────────────
@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
)
@limiter.limit("5/minute")   # strict limit — prevent account farming
async def register(
    request: Request,
    body: RegisterRequest,
    db: AsyncSession = Depends(get_db),
):
    # Resolve tenant
    tenant = await get_tenant_by_slug(db, body.tenant_slug)
    if not tenant:
        # Auto-create tenant in dev; in prod this would be a separate admin flow
        tenant = await create_tenant(db, name=body.tenant_slug.title(), slug=body.tenant_slug)

    try:
        user = await create_user(
            db=db,
            email=body.email,
            password=body.password,
            full_name=body.full_name,
            tenant_id=tenant.id,
            role=Role.VIEWER,
        )
    except UserAlreadyExistsError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists",
        )

    tokens = create_token_pair(
        user_id=user.id,
        tenant_id=user.tenant_id,
        role=user.role,
    )

    return RegisterResponse(
        user=UserProfile(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            role=user.role.value,
            tenant_id=user.tenant_id,
            is_active=user.is_active,
        ),
        tokens=tokens,
    )


@router.post(
    "/login",
    response_model=TokenPair,
    summary="Authenticate and receive JWT token pair",
)
@limiter.limit("10/minute")  # brute-force protection
async def login(
    request: Request,
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    try:
        user = await authenticate_user(db, body.email, body.password)
    except InvalidCredentialsError:
        # Generic message — don't reveal whether email exists
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return create_token_pair(
        user_id=user.id,
        tenant_id=user.tenant_id,
        role=user.role,
    )


@router.post(
    "/refresh",
    response_model=TokenPair,
    summary="Exchange a refresh token for a new token pair",
)
@limiter.limit("20/minute")
async def refresh_token(
    request: Request,
    body: RefreshRequest,
    db: AsyncSession = Depends(get_db),
):
    payload = decode_token(body.refresh_token)

    if payload.token_type != "refresh":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provided token is not a refresh token",
        )

    # Verify user still exists and is active
    user = await get_user_by_id(db, payload.sub)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive or does not exist",
        )

    logger.info("auth.token_refreshed", user_id=user.id, tenant_id=user.tenant_id)

    # Issue new token pair (refresh token rotation)
    return create_token_pair(
        user_id=user.id,
        tenant_id=user.tenant_id,
        role=user.role,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT, summary="Logout (client-side)")
async def logout(current_user: TokenPayload = Depends(get_current_user)):
    """
    Stateless JWT logout hint. The client should discard stored tokens.

    For true server-side revocation, maintain a token blocklist in Redis:
      redis.setex(f"revoked:{payload.jti}", ttl=token_remaining_ttl, value=1)
    Then check this blocklist in decode_token().
    """
    logger.info("auth.logout", user_id=current_user.sub)
    return None


@router.get("/me", response_model=UserProfile, summary="Get current user profile")
async def get_me(
    current_user: TokenPayload = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    user = await get_user_by_id(db, current_user.sub)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    return UserProfile(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role.value,
        tenant_id=user.tenant_id,
        is_active=user.is_active,
    )
