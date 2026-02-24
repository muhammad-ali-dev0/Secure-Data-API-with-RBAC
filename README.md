# 🔐 Secure Data API — Multi-Tenant Analytics Platform

 REST API demonstrating enterprise security engineering patterns: JWT authentication with token rotation, hierarchical role-based access control, per-role rate limiting, structured audit logging, and complete multi-tenant data isolation.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         FastAPI Application                      │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────┐    │
│  │  CORSMiddle  │  │ TenantMiddle │  │  AuditLogMiddle    │    │
│  │  -ware       │→ │  -ware       │→ │  -ware             │    │
│  │              │  │ (JWT extract)│  │ (structured logs)  │    │
│  └──────────────┘  └──────────────┘  └────────────────────┘    │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                      Routers                              │   │
│  │  /auth   /users   /analytics   /health                   │   │
│  │                                                           │   │
│  │  ┌──────────────────┐   ┌──────────────────────────┐    │   │
│  │  │  Rate Limiter    │   │  RBAC Dependencies        │    │   │
│  │  │  (per-role)      │   │  require_role()           │    │   │
│  │  │  slowapi         │   │  require_permission()     │    │   │
│  │  └──────────────────┘   └──────────────────────────┘    │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────┐   ┌──────────────────────────────┐   │
│  │   Services Layer     │   │   SQLAlchemy Async ORM        │   │
│  │   (business logic)   │   │   PostgreSQL / SQLite         │   │
│  └──────────────────────┘   └──────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Security Features

### 1. JWT Authentication
- **Access tokens**: 15-minute TTL — short-lived to limit breach window
- **Refresh tokens**: 7-day TTL — rotated on every use (prevents replay)
- **HS256 signing** with configurable secret key
- **Timing-safe** credential verification (constant-time hash comparison prevents user enumeration)

### 2. Role-Based Access Control (RBAC)

```
super_admin  ──┐
               ├─ all permissions
admin        ──┤
               ├─ user management, audit logs
analyst      ──┤
               ├─ run queries, read tenant data, export
viewer       ──┘
               └─ read own data, metrics summary
```

| Role | Rate Limit | Key Permissions |
|------|-----------|-----------------|
| `viewer` | 60/min | Read own data, view metrics |
| `analyst` | 200/min | + Run queries, export, ingest events |
| `admin` | 500/min | + Manage tenant users, view audit logs |
| `super_admin` | 10k/min | All permissions, cross-tenant access |

### 3. Multi-Tenant Isolation
Every database query is automatically scoped to `tenant_id`. Cross-tenant access raises HTTP 403 for all roles except `super_admin`. Enforced at the service layer — not just the API layer.

### 4. Rate Limiting
- Per-user limits keyed by `tenant_id:user_id`
- Dynamic limits based on role (analysts get 3× more capacity than viewers)
- Strict limits on auth endpoints (10/min login, 5/min register)
- Export endpoints throttled independently (10/min — expensive operations)
- **Production**: swap in-memory store for Redis backend

### 5. Structured Audit Logging

Every request emits a JSON log entry:
```json
{
  "event": "http.request",
  "severity": "INFO",
  "timestamp": "2024-03-15T10:23:41.123Z",
  "request_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "method": "POST",
  "path": "/api/v1/analytics/query",
  "status_code": 200,
  "duration_ms": 34.2,
  "tenant_id": "acme-corp-uuid",
  "user_id": "user-uuid",
  "user_role": "analyst"
}
```

Sensitive operations (data exports, role changes, deactivations) emit additional warning-level entries.

---

## Project Structure

```
secure-data-api/
├── app/
│   ├── main.py                 # FastAPI app, middleware registration
│   ├── core/
│   │   ├── config.py           # Pydantic settings (env-based config)
│   │   ├── database.py         # Async SQLAlchemy engine + session
│   │   ├── security.py         # JWT, RBAC, password hashing
│   │   ├── limiter.py          # Rate limiting (slowapi)
│   │   └── logging.py          # Structured JSON logging (structlog)
│   ├── middleware/
│   │   ├── audit.py            # Request/response audit logger
│   │   └── tenant.py           # JWT context extractor
│   ├── models/
│   │   ├── user.py             # User + Tenant ORM models
│   │   └── analytics.py        # AnalyticsEvent + AggregatedMetric models
│   ├── routers/
│   │   ├── auth.py             # /auth — register, login, refresh, me
│   │   ├── users.py            # /users — CRUD with RBAC
│   │   ├── analytics.py        # /analytics — events, queries, export
│   │   └── health.py           # /health — liveness + readiness probes
│   └── services/
│       └── user_service.py     # User/tenant business logic
├── tests/
│   └── test_api.py             # 25+ tests: auth, RBAC, tenant isolation
├── Dockerfile                  # Multi-stage production image
├── docker-compose.yml          # Local dev stack (API + Postgres + Redis)
├── requirements.txt
├── pyproject.toml              # pytest config
└── .env.example
```

---

## Quick Start

### Option A — Docker (recommended)
```bash
git clone https://github.com/muhammad-ali-dev0/secure-data-api
cd secure-data-api
cp .env.example .env
# Edit .env — set JWT_SECRET_KEY

docker-compose up
```

API available at `http://localhost:8000`  
Interactive docs at `http://localhost:8000/docs`

### Option B — Local
```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env  # set JWT_SECRET_KEY

uvicorn app.main:app --reload
```

---

## API Walkthrough

### Register & Login
```bash
# Register (creates tenant automatically if slug doesn't exist)
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@acme.com","password":"SecurePass1","full_name":"Alice","tenant_slug":"acme"}'

# Login
curl -X POST http://localhost:8000/api/v1/auth/login \
  -d '{"email":"alice@acme.com","password":"SecurePass1"}'
# → {"access_token":"eyJ...","refresh_token":"eyJ...","token_type":"bearer","expires_in":900}

export TOKEN=<access_token>
```

### RBAC in Action
```bash
# Viewer — can see metrics
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/analytics/metrics/summary

# Viewer — BLOCKED from listing users (403)
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/users/

# Viewer — BLOCKED from running queries (403)
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/v1/analytics/query \
  -d '{"group_by":"event_type"}'
```

### Refresh Token Rotation
```bash
curl -X POST http://localhost:8000/api/v1/auth/refresh \
  -d '{"refresh_token":"<your_refresh_token>"}'
# Returns a new token pair — old refresh token is logically invalidated
```

---

## Running Tests

```bash
pip install -r requirements.txt
pytest tests/ -v

# Expected output:
# tests/test_api.py::TestRegistration::test_register_creates_user PASSED
# tests/test_api.py::TestRegistration::test_register_weak_password_rejected PASSED
# tests/test_api.py::TestLogin::test_login_returns_token_pair PASSED
# tests/test_api.py::TestRBAC::test_viewer_cannot_list_users PASSED
# tests/test_api.py::TestRBAC::test_admin_can_list_users PASSED
# tests/test_api.py::TestTenantIsolation::test_admin_cannot_access_other_tenant_user PASSED
# ... (25+ tests)
```

---

## Production Hardening Checklist

- [ ] Set `JWT_SECRET_KEY` via secrets manager (AWS Secrets Manager / GCP Secret Manager)
- [ ] Switch `DATABASE_URL` to PostgreSQL with connection pooling (PgBouncer)
- [ ] Enable Redis backend in `app/core/limiter.py` for distributed rate limiting
- [ ] Add token blocklist in Redis for true server-side logout/revocation
- [ ] Configure Alembic for schema migrations (replace `init_db()`)
- [ ] Set up log shipping to SIEM (Datadog, Splunk, CloudWatch Logs)
- [ ] Enable HTTPS / TLS termination at load balancer
- [ ] Add `Referrer-Policy`, `X-Frame-Options`, `Content-Security-Policy` headers

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Framework | FastAPI 0.111 |
| Auth | python-jose (JWT), passlib (bcrypt) |
| ORM | SQLAlchemy 2.0 (async) |
| Database | SQLite (dev) / PostgreSQL (prod) |
| Rate Limiting | slowapi (Starlette-native) |
| Logging | structlog (JSON) |
| Testing | pytest-asyncio + httpx |
| Deployment | Docker / Docker Compose |

---

## License

MIT
