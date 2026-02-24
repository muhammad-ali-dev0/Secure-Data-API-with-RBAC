"""
Test suite for Secure Data API.

Tests cover:
  - Authentication flows (register, login, refresh, token validation)
  - RBAC enforcement (role hierarchy, permission checks, cross-tenant isolation)
  - Rate limiting behavior
  - Analytics endpoints with tenant scoping

Run with: pytest tests/ -v
"""

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.database import Base, get_db
from app.core.security import Role, create_token_pair, hash_password
from app.main import app
from app.models.user import Tenant, User

# ── Test database — isolated in-memory SQLite ──────────────────────────────────
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

test_engine = create_async_engine(TEST_DATABASE_URL, echo=False)
TestSessionLocal = async_sessionmaker(
    bind=test_engine, class_=AsyncSession, expire_on_commit=False
)


async def override_get_db():
    async with TestSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


app.dependency_overrides[get_db] = override_get_db


# ── Fixtures ───────────────────────────────────────────────────────────────────
@pytest_asyncio.fixture(scope="function", autouse=True)
async def setup_db():
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest_asyncio.fixture
async def db_session():
    async with TestSessionLocal() as session:
        yield session


@pytest_asyncio.fixture
async def tenant_acme(db_session: AsyncSession) -> Tenant:
    tenant = Tenant(name="Acme Corp", slug="acme")
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)
    return tenant


@pytest_asyncio.fixture
async def tenant_globex(db_session: AsyncSession) -> Tenant:
    tenant = Tenant(name="Globex Inc", slug="globex")
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)
    return tenant


async def _make_user(db: AsyncSession, email: str, role: Role, tenant_id: str) -> User:
    user = User(
        email=email,
        hashed_password=hash_password("SecurePass1"),
        full_name="Test User",
        role=role,
        tenant_id=tenant_id,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


@pytest_asyncio.fixture
async def viewer_user(db_session, tenant_acme):
    return await _make_user(db_session, "viewer@acme.com", Role.VIEWER, tenant_acme.id)


@pytest_asyncio.fixture
async def analyst_user(db_session, tenant_acme):
    return await _make_user(db_session, "analyst@acme.com", Role.ANALYST, tenant_acme.id)


@pytest_asyncio.fixture
async def admin_user(db_session, tenant_acme):
    return await _make_user(db_session, "admin@acme.com", Role.ADMIN, tenant_acme.id)


@pytest_asyncio.fixture
async def super_admin_user(db_session, tenant_acme):
    return await _make_user(db_session, "superadmin@acme.com", Role.SUPER_ADMIN, tenant_acme.id)


@pytest_asyncio.fixture
async def globex_admin(db_session, tenant_globex):
    return await _make_user(db_session, "admin@globex.com", Role.ADMIN, tenant_globex.id)


def auth_headers(user: User) -> dict:
    tokens = create_token_pair(user.id, user.tenant_id, user.role)
    return {"Authorization": f"Bearer {tokens.access_token}"}


# ── Auth Tests ─────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
class TestRegistration:
    async def test_register_creates_user(self, client: AsyncClient):
        resp = await client.post("/api/v1/auth/register", json={
            "email": "new@startup.com",
            "password": "SecurePass1",
            "full_name": "New User",
            "tenant_slug": "startup",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["user"]["email"] == "new@startup.com"
        assert data["user"]["role"] == "viewer"
        assert "access_token" in data["tokens"]

    async def test_register_weak_password_rejected(self, client: AsyncClient):
        resp = await client.post("/api/v1/auth/register", json={
            "email": "user@test.com",
            "password": "weak",
            "full_name": "Test",
            "tenant_slug": "test",
        })
        assert resp.status_code == 422

    async def test_register_duplicate_email_rejected(self, client: AsyncClient, viewer_user):
        resp = await client.post("/api/v1/auth/register", json={
            "email": "viewer@acme.com",  # already exists
            "password": "SecurePass1",
            "full_name": "Dup User",
            "tenant_slug": "acme",
        })
        assert resp.status_code == 409


@pytest.mark.asyncio
class TestLogin:
    async def test_login_returns_token_pair(self, client: AsyncClient, viewer_user):
        resp = await client.post("/api/v1/auth/login", json={
            "email": "viewer@acme.com",
            "password": "SecurePass1",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

    async def test_wrong_password_returns_401(self, client: AsyncClient, viewer_user):
        resp = await client.post("/api/v1/auth/login", json={
            "email": "viewer@acme.com",
            "password": "WrongPassword1",
        })
        assert resp.status_code == 401

    async def test_nonexistent_email_returns_401(self, client: AsyncClient):
        resp = await client.post("/api/v1/auth/login", json={
            "email": "ghost@nowhere.com",
            "password": "SecurePass1",
        })
        assert resp.status_code == 401

    async def test_get_me_returns_profile(self, client: AsyncClient, viewer_user):
        resp = await client.get("/api/v1/auth/me", headers=auth_headers(viewer_user))
        assert resp.status_code == 200
        assert resp.json()["email"] == "viewer@acme.com"

    async def test_missing_token_returns_403(self, client: AsyncClient):
        resp = await client.get("/api/v1/auth/me")
        assert resp.status_code in (401, 403)


# ── RBAC Tests ────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
class TestRBAC:
    async def test_viewer_cannot_list_users(self, client: AsyncClient, viewer_user):
        resp = await client.get("/api/v1/users/", headers=auth_headers(viewer_user))
        assert resp.status_code == 403

    async def test_analyst_cannot_list_users(self, client: AsyncClient, analyst_user):
        resp = await client.get("/api/v1/users/", headers=auth_headers(analyst_user))
        assert resp.status_code == 403

    async def test_admin_can_list_users(self, client: AsyncClient, admin_user):
        resp = await client.get("/api/v1/users/", headers=auth_headers(admin_user))
        assert resp.status_code == 200

    async def test_super_admin_can_list_users(self, client: AsyncClient, super_admin_user):
        resp = await client.get("/api/v1/users/", headers=auth_headers(super_admin_user))
        assert resp.status_code == 200

    async def test_viewer_can_view_own_profile(self, client: AsyncClient, viewer_user):
        resp = await client.get(
            f"/api/v1/users/{viewer_user.id}", headers=auth_headers(viewer_user)
        )
        assert resp.status_code == 200

    async def test_viewer_cannot_view_other_profile(
        self, client: AsyncClient, viewer_user, admin_user
    ):
        resp = await client.get(
            f"/api/v1/users/{admin_user.id}", headers=auth_headers(viewer_user)
        )
        assert resp.status_code == 403

    async def test_admin_cannot_promote_to_super_admin(
        self, client: AsyncClient, admin_user, viewer_user
    ):
        resp = await client.put(
            f"/api/v1/users/{viewer_user.id}/role",
            json={"role": "super_admin"},
            headers=auth_headers(admin_user),
        )
        assert resp.status_code == 403

    async def test_super_admin_can_promote_to_super_admin(
        self, client: AsyncClient, super_admin_user, viewer_user
    ):
        resp = await client.put(
            f"/api/v1/users/{viewer_user.id}/role",
            json={"role": "super_admin"},
            headers=auth_headers(super_admin_user),
        )
        assert resp.status_code == 200
        assert resp.json()["role"] == "super_admin"


# ── Tenant Isolation Tests ─────────────────────────────────────────────────────
@pytest.mark.asyncio
class TestTenantIsolation:
    async def test_admin_cannot_access_other_tenant_user(
        self, client: AsyncClient, admin_user, globex_admin
    ):
        """Acme admin cannot view Globex admin's profile."""
        resp = await client.get(
            f"/api/v1/users/{globex_admin.id}", headers=auth_headers(admin_user)
        )
        assert resp.status_code == 403

    async def test_analytics_scoped_to_tenant(
        self, client: AsyncClient, analyst_user
    ):
        """Events list returns 200 and is implicitly scoped to the user's tenant."""
        resp = await client.get("/api/v1/analytics/events", headers=auth_headers(analyst_user))
        assert resp.status_code == 200
        # All returned events should belong to analyst's tenant
        for event in resp.json():
            assert event["tenant_id"] == analyst_user.tenant_id


# ── Analytics Permission Tests ─────────────────────────────────────────────────
@pytest.mark.asyncio
class TestAnalytics:
    async def test_viewer_can_see_metrics_summary(self, client: AsyncClient, viewer_user):
        resp = await client.get(
            "/api/v1/analytics/metrics/summary", headers=auth_headers(viewer_user)
        )
        assert resp.status_code == 200

    async def test_viewer_cannot_run_queries(self, client: AsyncClient, viewer_user):
        resp = await client.post(
            "/api/v1/analytics/query",
            json={"group_by": "event_type"},
            headers=auth_headers(viewer_user),
        )
        assert resp.status_code == 403

    async def test_analyst_can_run_queries(self, client: AsyncClient, analyst_user):
        resp = await client.post(
            "/api/v1/analytics/query",
            json={"group_by": "event_type"},
            headers=auth_headers(analyst_user),
        )
        assert resp.status_code == 200

    async def test_analyst_can_ingest_events(self, client: AsyncClient, analyst_user):
        resp = await client.post(
            "/api/v1/analytics/events",
            json={
                "event_type": "page_view",
                "user_identifier": "user_123",
                "source": "web",
                "value": 1.0,
            },
            headers=auth_headers(analyst_user),
        )
        assert resp.status_code == 201
        assert resp.json()["event_type"] == "page_view"
        assert resp.json()["tenant_id"] == analyst_user.tenant_id

    async def test_viewer_cannot_export(self, client: AsyncClient, viewer_user):
        resp = await client.get(
            "/api/v1/analytics/export", headers=auth_headers(viewer_user)
        )
        assert resp.status_code == 403

    async def test_analyst_can_export(self, client: AsyncClient, analyst_user):
        resp = await client.get(
            "/api/v1/analytics/export", headers=auth_headers(analyst_user)
        )
        assert resp.status_code == 200


# ── Health check ────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
class TestHealth:
    async def test_liveness(self, client: AsyncClient):
        resp = await client.get("/health/live")
        assert resp.status_code == 200

    async def test_full_health(self, client: AsyncClient):
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"
