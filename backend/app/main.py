"""
RBAC + Cell-Level Security Demo - Main Application

Federated OIDC authentication via Keycloak with:
- Role-based access control (RBAC)
- Classification-based record access
- Cell-level security with need-to-know compartments
- OpenSearch integration with security filtering (optional)
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
- **OpenSearch**: Full-text search with security-filtered results
- **Audit Trail**: Every access attempt is logged
    """,
    version="1.1.0",
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

# Include core routers
app.include_router(records.router)
app.include_router(admin.router)
app.include_router(audit_routes.router)

# Include search router (import is done at module level but won't fail)
try:
    from app.routes import search
    app.include_router(search.router)
    SEARCH_ENABLED = True
except Exception as e:
    print(f"Warning: Search routes not loaded: {e}")
    SEARCH_ENABLED = False


@app.get("/", tags=["Health"])
async def root():
    endpoints = {
        "records": "/api/records",
        "admin": "/api/admin",
        "audit": "/api/audit",
    }
    if SEARCH_ENABLED:
        endpoints["search"] = "/api/search"
    
    return {
        "service": "RBAC + Cell-Level Security Demo",
        "status": "running",
        "docs": "/docs",
        "endpoints": endpoints,
    }


@app.get("/health", tags=["Health"])
async def health():
    return {"status": "healthy"}


@app.get("/api/auth/me", tags=["Auth"])
async def me(request: Request):
    """
    Get current user info from JWT.

    Uses the SAME decode_token() and build_current_user() functions as
    the get_current_user FastAPI dependency, ensuring identical handling
    of both local (Alpha) and federated (Bravo) tokens.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return {"authenticated": False}

    try:
        from app.auth import decode_token, build_current_user

        token = auth_header.split(" ", 1)[1]
        payload = await decode_token(token)
        user = build_current_user(payload, token)

        return {
            "authenticated": True,
            "keycloak_id": user.keycloak_id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "organization": user.organization,
            "clearance_level": user.clearance_level,
            "compartments": user.compartments,
            "roles": user.roles,
        }
    except Exception as e:
        return {"authenticated": False, "error": str(e)}
