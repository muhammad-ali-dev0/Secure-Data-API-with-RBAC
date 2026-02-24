"""
Users router — user management with RBAC enforcement.

Permission matrix:
  GET  /users/             → admin, super_admin (list tenant users)
  GET  /users/{id}         → self OR admin/super_admin
  PUT  /users/{id}/role    → admin (own tenant), super_admin (any tenant)
  DELETE /users/{id}       → admin (own tenant), super_admin (any tenant)
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
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
    require_role,
    require_same_tenant,
)
from app.services.user_service import (
    UserNotFoundError,
    deactivate_user,
    get_user_by_id,
    list_tenant_users,
    update_user_role,
)

router = APIRouter()
logger = get_logger(__name__)


# ── Schemas ────────────────────────────────────────────────────────────────────
class UserSummary(BaseModel):
    id: str
    email: str
    full_name: str
    role: str
    tenant_id: str
    is_active: bool

    model_config = {"from_attributes": True}


class UpdateRoleRequest(BaseModel):
    role: Role


class UserListResponse(BaseModel):
    users: list[UserSummary]
    count: int
    tenant_id: str


# ── Endpoints ──────────────────────────────────────────────────────────────────
@router.get(
    "/",
    response_model=UserListResponse,
    summary="List all users in the current tenant",
)
@limiter.limit(get_role_limit)
async def list_users(
    request: Request,
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    current_user: TokenPayload = Depends(
        require_role(Role.ADMIN, Role.SUPER_ADMIN)
    ),
    db: AsyncSession = Depends(get_db),
):
    # Admins see their own tenant; super_admin can pass tenant_id as query param
    tenant_id = current_user.tenant_id
    users = await list_tenant_users(db, tenant_id=tenant_id, skip=skip, limit=limit)

    logger.info(
        "users.listed",
        requester_id=current_user.sub,
        tenant_id=tenant_id,
        count=len(users),
    )

    return UserListResponse(
        users=[
            UserSummary(
                id=u.id,
                email=u.email,
                full_name=u.full_name,
                role=u.role.value,
                tenant_id=u.tenant_id,
                is_active=u.is_active,
            )
            for u in users
        ],
        count=len(users),
        tenant_id=tenant_id,
    )


@router.get(
    "/{user_id}",
    response_model=UserSummary,
    summary="Get a specific user (self or admin)",
)
@limiter.limit(get_role_limit)
async def get_user(
    request: Request,
    user_id: str,
    current_user: TokenPayload = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # Users can view their own profile; admins can view anyone in their tenant
    is_self = current_user.sub == user_id
    is_admin = current_user.role in (Role.ADMIN, Role.SUPER_ADMIN)

    if not is_self and not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only view your own profile",
        )

    user = await get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Admins can only view users in their own tenant (super_admin exempt)
    require_same_tenant(current_user, user.tenant_id)

    return UserSummary(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role.value,
        tenant_id=user.tenant_id,
        is_active=user.is_active,
    )


@router.put(
    "/{user_id}/role",
    response_model=UserSummary,
    summary="Update a user's role (admin only)",
)
@limiter.limit(get_role_limit)
async def update_role(
    request: Request,
    user_id: str,
    body: UpdateRoleRequest,
    current_user: TokenPayload = Depends(
        require_permission(Permission.MANAGE_TENANT_USERS)
    ),
    db: AsyncSession = Depends(get_db),
):
    # Prevent privilege escalation — admins cannot promote to super_admin
    if body.role == Role.SUPER_ADMIN and current_user.role != Role.SUPER_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only super_admin can assign the super_admin role",
        )

    try:
        user = await update_user_role(db, user_id, body.role, updated_by=current_user.sub)
    except UserNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    require_same_tenant(current_user, user.tenant_id)

    return UserSummary(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role.value,
        tenant_id=user.tenant_id,
        is_active=user.is_active,
    )


@router.delete(
    "/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Deactivate a user (admin only)",
)
@limiter.limit(get_role_limit)
async def delete_user(
    request: Request,
    user_id: str,
    current_user: TokenPayload = Depends(
        require_permission(Permission.MANAGE_TENANT_USERS)
    ),
    db: AsyncSession = Depends(get_db),
):
    # Prevent self-deactivation
    if current_user.sub == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot deactivate your own account",
        )

    try:
        user = await deactivate_user(db, user_id, deactivated_by=current_user.sub)
    except UserNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    require_same_tenant(current_user, user.tenant_id)
    return None
