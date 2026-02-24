"""
User service — business logic for user and tenant management.

Services sit between routers (HTTP layer) and models (data layer).
They handle business rules, data transformation, and complex queries.
"""

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.logging import get_logger
from app.core.security import Role, hash_password, verify_password
from app.models.user import Tenant, User

logger = get_logger(__name__)


class UserNotFoundError(Exception):
    pass


class UserAlreadyExistsError(Exception):
    pass


class TenantNotFoundError(Exception):
    pass


class InvalidCredentialsError(Exception):
    pass


# ── Tenant operations ──────────────────────────────────────────────────────────
async def get_tenant_by_slug(db: AsyncSession, slug: str) -> Tenant | None:
    result = await db.execute(select(Tenant).where(Tenant.slug == slug))
    return result.scalar_one_or_none()


async def create_tenant(db: AsyncSession, name: str, slug: str) -> Tenant:
    tenant = Tenant(name=name, slug=slug)
    db.add(tenant)
    await db.flush()
    logger.info("tenant.created", tenant_id=tenant.id, name=name)
    return tenant


# ── User CRUD ──────────────────────────────────────────────────────────────────
async def get_user_by_id(db: AsyncSession, user_id: str) -> User | None:
    result = await db.execute(
        select(User)
        .options(selectinload(User.tenant))
        .where(User.id == user_id)
    )
    return result.scalar_one_or_none()


async def get_user_by_email(db: AsyncSession, email: str) -> User | None:
    result = await db.execute(select(User).where(User.email == email.lower()))
    return result.scalar_one_or_none()


async def list_tenant_users(
    db: AsyncSession,
    tenant_id: str,
    skip: int = 0,
    limit: int = 50,
) -> list[User]:
    result = await db.execute(
        select(User)
        .where(User.tenant_id == tenant_id, User.is_active == True)  # noqa: E712
        .offset(skip)
        .limit(limit)
        .order_by(User.created_at.desc())
    )
    return list(result.scalars().all())


async def create_user(
    db: AsyncSession,
    email: str,
    password: str,
    full_name: str,
    tenant_id: str,
    role: Role = Role.VIEWER,
) -> User:
    # Check for existing email (case-insensitive)
    existing = await get_user_by_email(db, email)
    if existing:
        raise UserAlreadyExistsError(f"Email {email} is already registered")

    user = User(
        email=email.lower().strip(),
        hashed_password=hash_password(password),
        full_name=full_name,
        tenant_id=tenant_id,
        role=role,
    )
    db.add(user)
    await db.flush()

    logger.info(
        "user.created",
        user_id=user.id,
        email=user.email,
        tenant_id=tenant_id,
        role=role.value,
    )
    return user


async def authenticate_user(db: AsyncSession, email: str, password: str) -> User:
    """Verify credentials. Always verify hash even on miss to prevent timing attacks."""
    user = await get_user_by_email(db, email)

    # Constant-time comparison even when user doesn't exist
    dummy_hash = "$2b$12$invalidhashtopreventtimingattacksXXXXXXXXXXXXXXXX"
    password_correct = verify_password(password, user.hashed_password if user else dummy_hash)

    if not user or not password_correct or not user.is_active:
        logger.warning("auth.login_failed", email=email, reason="invalid_credentials")
        raise InvalidCredentialsError("Invalid email or password")

    # Update last login timestamp
    user.last_login_at = datetime.now(timezone.utc)
    logger.info("auth.login_success", user_id=user.id, tenant_id=user.tenant_id)
    return user


async def update_user_role(
    db: AsyncSession,
    user_id: str,
    new_role: Role,
    updated_by: str,
) -> User:
    user = await get_user_by_id(db, user_id)
    if not user:
        raise UserNotFoundError(f"User {user_id} not found")

    old_role = user.role
    user.role = new_role

    logger.info(
        "user.role_changed",
        user_id=user_id,
        old_role=old_role.value,
        new_role=new_role.value,
        changed_by=updated_by,
    )
    return user


async def deactivate_user(db: AsyncSession, user_id: str, deactivated_by: str) -> User:
    user = await get_user_by_id(db, user_id)
    if not user:
        raise UserNotFoundError(f"User {user_id} not found")

    user.is_active = False
    logger.warning(
        "user.deactivated",
        user_id=user_id,
        deactivated_by=deactivated_by,
    )
    return user
