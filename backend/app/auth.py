"""JWT authentication with Keycloak - validates tokens and extracts security claims."""
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


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
) -> CurrentUser:
    """Validate JWT and extract user with security attributes."""
    token = credentials.credentials

    try:
        # Decode header to get key ID
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")
        if not kid:
            raise HTTPException(status_code=401, detail="Token missing key ID")

        # Get signing key
        jwks = await get_jwks()
        key_data = find_key(jwks, kid)
        if not key_data:
            # Force refresh JWKS cache
            global _jwks_cache_time
            _jwks_cache_time = 0
            jwks = await get_jwks()
            key_data = find_key(jwks, kid)
            if not key_data:
                raise HTTPException(status_code=401, detail="Unknown signing key")

        # Build public key
        public_key = jwk.construct(key_data)

        # Decode and validate token
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            options={
                "verify_aud": False,  # Keycloak doesn't always set aud
                "verify_iss": False,  # Allow federated issuers
            },
        )

        # Extract security attributes from token claims
        clearance = payload.get("clearance_level", "UNCLASSIFIED")
        if isinstance(clearance, list):
            clearance = clearance[0] if clearance else "UNCLASSIFIED"

        compartments_raw = payload.get("compartments", "")
        if isinstance(compartments_raw, list):
            compartments_raw = compartments_raw[0] if compartments_raw else ""
        compartments = [
            c.strip() for c in compartments_raw.split(",") if c.strip()
        ]

        org = payload.get("organization", "Unknown")
        if isinstance(org, list):
            org = org[0] if org else "Unknown"

        # Extract roles from realm_access
        realm_roles = payload.get("realm_access", {}).get("roles", [])
        app_roles = [r for r in realm_roles if r in
                     ("viewer", "analyst", "manager", "admin", "auditor")]

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
