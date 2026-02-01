"""
RBAC + Cell-Level Security Demo - Main Application

Federated OIDC authentication via Keycloak with:
- Role-based access control (RBAC)
- Classification-based record access
- Cell-level security with need-to-know compartments
- Comprehensive audit logging
"""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.config import settings
from app.routes import records, admin, audit_routes


@asynccontextmanager
async def lifespan(app: FastAPI):
    print("=" * 50)
    print("  RBAC + Cell Security API Starting")
    print(f"  Keycloak: {settings.KEYCLOAK_URL}")
    print(f"  Realm: {settings.KEYCLOAK_REALM}")
    print("=" * 50)
    yield
    print("API Shutting down")


app = FastAPI(
    title="RBAC + Cell-Level Security Demo API",
    description="""
Demonstrates federated OIDC authentication with:
- **RBAC**: Role-based access control (viewer, analyst, manager, admin, auditor)
- **Classification**: UNCLASSIFIED → CONFIDENTIAL → SECRET → TOP_SECRET
- **Cell-Level Security**: Individual fields have their own classification + compartments
- **Need-to-Know**: Compartment-based access (PROJECT_ALPHA, PROJECT_OMEGA, OPERATION_DELTA)
- **Federation**: Two Keycloak instances representing partner organizations
- **Audit Trail**: Every access attempt is logged
    """,
    version="1.0.0",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(records.router)
app.include_router(admin.router)
app.include_router(audit_routes.router)


@app.get("/", tags=["Health"])
async def root():
    return {
        "service": "RBAC + Cell-Level Security Demo",
        "status": "running",
        "docs": "/docs",
        "endpoints": {
            "records": "/api/records",
            "admin": "/api/admin",
            "audit": "/api/audit",
        },
    }


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "healthy"}


@app.get("/api/auth/me", tags=["Auth"])
async def me(request: Request):
    """
    Get current user info from JWT.
    Useful for the frontend to display user details.
    """
    from app.auth import get_current_user
    from fastapi import Depends
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return {"authenticated": False}

    try:
        from app.auth import get_current_user, security_scheme
        from app.auth import CurrentUser
        token = auth_header.split(" ", 1)[1]

        # Manual token validation
        from jose import jwt, jwk
        from app.auth import get_jwks, find_key

        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        jwks = await get_jwks()
        key_data = find_key(jwks, kid)
        public_key = jwk.construct(key_data)

        payload = jwt.decode(
            token, public_key, algorithms=["RS256"],
            options={"verify_aud": False, "verify_iss": False},
        )

        clearance = payload.get("clearance_level", "UNCLASSIFIED")
        if isinstance(clearance, list):
            clearance = clearance[0] if clearance else "UNCLASSIFIED"

        compartments_raw = payload.get("compartments", "")
        if isinstance(compartments_raw, list):
            compartments_raw = compartments_raw[0] if compartments_raw else ""
        compartments = [c.strip() for c in compartments_raw.split(",") if c.strip()]

        org = payload.get("organization", "Unknown")
        if isinstance(org, list):
            org = org[0] if org else "Unknown"

        realm_roles = payload.get("realm_access", {}).get("roles", [])
        app_roles = [r for r in realm_roles
                     if r in ("viewer", "analyst", "manager", "admin", "auditor")]

        return {
            "authenticated": True,
            "keycloak_id": payload.get("sub"),
            "username": payload.get("preferred_username"),
            "email": payload.get("email"),
            "full_name": payload.get("name"),
            "organization": org,
            "clearance_level": clearance,
            "compartments": compartments,
            "roles": app_roles,
        }
    except Exception as e:
        return {"authenticated": False, "error": str(e)}
