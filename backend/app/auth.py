"""JWT authentication with Keycloak - validates tokens and extracts security claims.

Supports both local (Agency Alpha) and federated (Agency Bravo) users.
All tokens are Alpha-issued — federation is transparent after IDP mapping.

Shared helpers (decode_token, build_current_user) are used by BOTH:
  - get_current_user()  → FastAPI dependency for protected endpoints
  - /api/auth/me        → Profile endpoint in main.py
"""
import time
from dataclasses import dataclass, field
from typing import Optional
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError, jwk
import httpx
from app.config import settings

security_scheme = HTTPBearer()

# ─── JWKS Cache ────────────────────────────────────────────────────────────
_jwks_cache: dict = {}
_jwks_cache_time: float = 0
JWKS_CACHE_TTL = 300  # 5 minutes


async def get_jwks() -> dict:
    """Fetch and cache JWKS from Keycloak."""
    global _jwks_cache, _jwks_cache_time
    now = time.time()
    if _jwks_cache and (now - _jwks_cache_time) < JWKS_CACHE_TTL:
        return _jwks_cache

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(settings.keycloak_jwks_url, timeout=10)
            resp.raise_for_status()
            _jwks_cache = resp.json()
            _jwks_cache_time = now
        except Exception as e:
            if _jwks_cache:
                return _jwks_cache  # Use stale cache on error
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Cannot reach Keycloak JWKS endpoint: {e}"
            )
    return _jwks_cache


def find_key(jwks: dict, kid: str) -> Optional[dict]:
    """Find a key in JWKS by kid."""
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            return key
    return None


# ─── Claim Extraction Helpers ─────────────────────────────────────────────
# Keycloak IDP attribute mappers can emit claims as either a plain string
# or a single-element list, depending on the mapper type and sync mode.
# These helpers normalize both formats so the rest of the code is clean.

def _extract_string_claim(payload: dict, claim: str, default: str = "") -> str:
    """
    Extract a string claim from the JWT payload.

    Handles Keycloak's inconsistent claim formats:
      - User-attribute mappers emit strings:       "clearance_level": "SECRET"
      - IDP attribute mappers may emit lists:       "clearance_level": ["SECRET"]
    """
    value = payload.get(claim, default)
    if isinstance(value, list):
        return value[0] if value else default
    return value or default


def _extract_roles(payload: dict) -> list[str]:
    """
    Extract application roles from realm_access.roles.

    Filters to only recognized app roles, ignoring Keycloak internal roles
    like 'default-roles-agency-alpha', 'uma_authorization', etc.
    """
    realm_roles = payload.get("realm_access", {}).get("roles", [])
    return [r for r in realm_roles if r in
            ("viewer", "analyst", "manager", "admin", "auditor")]


# ─── Shared Token Decoding ────────────────────────────────────────────────

async def decode_token(token: str) -> dict:
    """
    Validate a JWT against Keycloak Alpha's JWKS and return the decoded payload.

    This is the single source of truth for token validation. Used by both
    the FastAPI dependency (get_current_user) and the /api/auth/me endpoint.

    Raises JWTError or HTTPException on failure.
    """
    # Decode header to get key ID
    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header.get("kid")
    if not kid:
        raise HTTPException(status_code=401, detail="Token missing key ID")

    # Get signing key from JWKS
    jwks = await get_jwks()
    key_data = find_key(jwks, kid)
    if not key_data:
        # Force refresh JWKS cache (key rotation scenario)
        global _jwks_cache_time
        _jwks_cache_time = 0
        jwks = await get_jwks()
        key_data = find_key(jwks, kid)
        if not key_data:
            raise HTTPException(status_code=401, detail="Unknown signing key")

    # Build public key and decode
    public_key = jwk.construct(key_data)
    payload = jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        options={
            "verify_aud": False,   # Keycloak doesn't always set aud consistently
            "verify_iss": False,   # Federated tokens may have mismatched issuer
        },
    )
    return payload


# ─── Current User Data ────────────────────────────────────────────────────

@dataclass
class CurrentUser:
    """Represents the authenticated user extracted from JWT."""
    keycloak_id: str
    username: str
    email: str = ""
    full_name: str = ""
    organization: str = "Unknown"
    clearance_level: str = "UNCLASSIFIED"
    compartments: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    token: str = ""

    @property
    def is_admin(self) -> bool:
        return "admin" in self.roles

    @property
    def is_manager(self) -> bool:
        return "manager" in self.roles or self.is_admin

    @property
    def is_auditor(self) -> bool:
        return "auditor" in self.roles or self.is_admin

    @property
    def is_analyst(self) -> bool:
        return "analyst" in self.roles or self.is_manager


def build_current_user(payload: dict, token: str = "") -> CurrentUser:
    """
    Construct a CurrentUser from a decoded JWT payload.

    Shared builder used by both get_current_user() and /api/auth/me.
    Handles Keycloak's claim format quirks (string vs list) via the
    _extract_string_claim helper.
    """
    clearance = _extract_string_claim(payload, "clearance_level", "UNCLASSIFIED")
    compartments_raw = _extract_string_claim(payload, "compartments", "")
    compartments = [c.strip() for c in compartments_raw.split(",") if c.strip()]
    org = _extract_string_claim(payload, "organization", "Unknown")
    app_roles = _extract_roles(payload)

    return CurrentUser(
        keycloak_id=payload.get("sub", ""),
        username=payload.get("preferred_username", "unknown"),
        email=payload.get("email", ""),
        full_name=payload.get("name", ""),
        organization=org,
        clearance_level=clearance,
        compartments=compartments,
        roles=app_roles,
        token=token,
    )


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
) -> CurrentUser:
    """Validate JWT and extract user with security attributes (FastAPI dependency)."""
    token = credentials.credentials

    try:
        payload = await decode_token(token)
        return build_current_user(payload, token)
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ─── Role-based dependency helpers ────────────────────────────────────────

def require_role(*required_roles: str):
    """Dependency that requires the user to have at least one of the specified roles."""
    async def checker(user: CurrentUser = Depends(get_current_user)):
        if user.is_admin:
            return user  # Admin bypasses role checks
        if not any(r in user.roles for r in required_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {', '.join(required_roles)}"
            )
        return user
    return checker
