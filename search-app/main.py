"""
OpenSearch Security Demo — RBAC, Cell-Level & NTK Search Application
=====================================================================
Demonstrates three security enforcement models on top of OpenSearch:

  • RBAC Mode   – filters documents by classification clearance + organisation
  • Cell-Level  – adds compartmented cell membership checks + field-level masking
  • NTK Mode    – adds Need-to-Know explicit user access control
  
Integrates with Keycloak for authentication and user attribute mapping.
"""

import os
import json
import logging
import time
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Query, Request, Depends, Header
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from opensearchpy import OpenSearch

# JWT validation
import httpx
from jose import jwt, jwk, JWTError
from jose.utils import base64url_decode

# ── Logging ─────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-8s  %(message)s")
logger = logging.getLogger("search-app")

# ── Configuration ───────────────────────────────────────────────────────
OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "localhost")
OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", "9200"))
INDEX_NAME = os.getenv("INDEX_NAME", "secure-documents")

# Keycloak configuration
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL", "http://localhost:8080")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "agency-alpha")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "frontend-app")

# ── FastAPI ─────────────────────────────────────────────────────────────
app = FastAPI(title="OpenSearch Security Demo", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── OpenSearch Client ───────────────────────────────────────────────────
os_client = OpenSearch(
    hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
    use_ssl=False,
    verify_certs=False,
    timeout=30,
)

# ═══════════════════════════════════════════════════════════════════════
# SECTION 1 — KEYCLOAK AUTHENTICATION
# ═══════════════════════════════════════════════════════════════════════

# JWKS cache for Keycloak public keys
_jwks_cache: Dict[str, Any] = {"keys": {}, "fetched_at": 0}
JWKS_CACHE_TTL = 300  # 5 minutes


async def fetch_jwks() -> Dict[str, Any]:
    """Fetch JWKS from Keycloak with caching."""
    now = time.time()
    if _jwks_cache["keys"] and (now - _jwks_cache["fetched_at"]) < JWKS_CACHE_TTL:
        return _jwks_cache["keys"]
    
    jwks_url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs"
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(jwks_url, timeout=10.0)
            response.raise_for_status()
            jwks_data = response.json()
            _jwks_cache["keys"] = {k["kid"]: k for k in jwks_data.get("keys", [])}
            _jwks_cache["fetched_at"] = now
            logger.info(f"Fetched JWKS from Keycloak: {len(_jwks_cache['keys'])} keys")
            return _jwks_cache["keys"]
    except Exception as e:
        logger.warning(f"Failed to fetch JWKS: {e}")
        return _jwks_cache["keys"]  # Return cached keys if available


class AuthenticatedUser(BaseModel):
    """User information extracted from JWT token."""
    username: str
    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    organization: str = "agency-alpha"
    clearance_level: str = "UNCLASSIFIED"
    compartments: List[str] = []
    roles: List[str] = []
    is_authenticated: bool = True


def parse_claim_value(value: Any) -> str:
    """Parse claim value handling both string and list formats."""
    if isinstance(value, list):
        return value[0] if value else ""
    return str(value) if value else ""


def parse_list_claim(value: Any) -> List[str]:
    """Parse claim value into list, handling comma-separated strings."""
    if isinstance(value, list):
        result = []
        for item in value:
            if isinstance(item, str) and "," in item:
                result.extend([x.strip() for x in item.split(",") if x.strip()])
            elif item:
                result.append(str(item).strip())
        return result
    if isinstance(value, str):
        return [x.strip() for x in value.split(",") if x.strip()]
    return []


async def validate_token(token: str) -> Optional[AuthenticatedUser]:
    """Validate JWT token and extract user information."""
    try:
        # Decode header to get key ID
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        
        # Fetch JWKS
        keys = await fetch_jwks()
        if not keys or kid not in keys:
            logger.warning(f"Key ID {kid} not found in JWKS")
            return None
        
        # Build public key
        key_data = keys[kid]
        public_key = jwk.construct(key_data)
        
        # Verify and decode
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=["account", KEYCLOAK_CLIENT_ID],
            options={"verify_aud": False}  # Keycloak can have multiple audiences
        )
        
        # Extract user info
        username = payload.get("preferred_username", payload.get("sub", "unknown"))
        
        # Extract roles from realm_access
        roles = []
        realm_access = payload.get("realm_access", {})
        if isinstance(realm_access, dict):
            roles = realm_access.get("roles", [])
        
        # Extract custom claims
        clearance = parse_claim_value(payload.get("clearance_level", "UNCLASSIFIED"))
        organization = parse_claim_value(payload.get("organization", "Agency Alpha"))
        compartments = parse_list_claim(payload.get("compartments", []))
        
        return AuthenticatedUser(
            username=username,
            email=payload.get("email"),
            first_name=payload.get("given_name"),
            last_name=payload.get("family_name"),
            organization=organization,
            clearance_level=clearance,
            compartments=compartments,
            roles=roles,
            is_authenticated=True
        )
    except JWTError as e:
        logger.warning(f"JWT validation failed: {e}")
        return None
    except Exception as e:
        logger.warning(f"Token validation error: {e}")
        return None


async def get_current_user(authorization: Optional[str] = Header(None)) -> Optional[AuthenticatedUser]:
    """Extract and validate user from Authorization header."""
    if not authorization or not authorization.startswith("Bearer "):
        return None
    
    token = authorization.split(" ", 1)[1]
    return await validate_token(token)


# ═══════════════════════════════════════════════════════════════════════
# SECTION 2 — PYDANTIC MODELS
# ═══════════════════════════════════════════════════════════════════════

class SearchRequest(BaseModel):
    query: str = ""
    user_id: str = ""  # Optional when using Keycloak auth
    mode: str = Field(pattern="^(rbac|cell|ntk)$", default="rbac")


class DocumentUpload(BaseModel):
    title: str
    content: str
    author: str = "Unknown"
    classification: str = Field(pattern="^(UNCLASSIFIED|CONFIDENTIAL|SECRET|TOP_SECRET)$")
    organization: str
    department: str = "general"
    cell_access: List[str] = ["all"]
    shared_with: List[str] = []
    source_name: str = ""
    handler_id: str = ""
    raw_intel: str = ""
    location: str = ""
    # NTK fields
    ntk_required: bool = False
    ntk_users: List[str] = []
    ntk_compartments: List[str] = []


class CompareRequest(BaseModel):
    query: str = ""
    user_id: str = ""  # Optional when using Keycloak auth


# ═══════════════════════════════════════════════════════════════════════
# SECTION 3 — CLASSIFICATION HIERARCHY
# ═══════════════════════════════════════════════════════════════════════

CLASSIFICATION_HIERARCHY: Dict[str, int] = {
    "UNCLASSIFIED": 0,
    "CONFIDENTIAL": 1,
    "SECRET": 2,
    "TOP_SECRET": 3,
}


def allowed_classifications(clearance: str) -> List[str]:
    """Return every classification at or below the given clearance."""
    ceiling = CLASSIFICATION_HIERARCHY.get(clearance, 0)
    return [c for c, v in CLASSIFICATION_HIERARCHY.items() if v <= ceiling]


# ═══════════════════════════════════════════════════════════════════════
# SECTION 4 — COMPARTMENT TO CELL MAPPING
# ═══════════════════════════════════════════════════════════════════════

COMPARTMENT_CELL_MAP: Dict[str, List[str]] = {
    "PROJECT_ALPHA": ["cell-hq", "cell-east"],
    "PROJECT_OMEGA": ["cell-hq", "cell-cyber"],
    "OPERATION_DELTA": ["cell-west", "cell-hq"],
    "PROJECT_BRAVO": ["cell-west"],
}

ALL_CELLS = ["cell-east", "cell-west", "cell-hq", "cell-cyber"]


def compartments_to_cells(compartments: List[str], is_admin: bool = False) -> List[str]:
    """Map compartment memberships to cell access."""
    if is_admin:
        return ALL_CELLS
    
    cells = set()
    for comp in compartments:
        if comp in COMPARTMENT_CELL_MAP:
            cells.update(COMPARTMENT_CELL_MAP[comp])
    return list(cells)


# ═══════════════════════════════════════════════════════════════════════
# SECTION 5 — DEMO USER PROFILES
# ═══════════════════════════════════════════════════════════════════════

DEMO_USERS: Dict[str, Dict[str, Any]] = {
    "alpha-admin": {
        "username": "alpha-admin",
        "name": "Director Reyes (Alpha)",
        "organization": "agency-alpha",
        "roles": ["admin"],
        "clearance": "TOP_SECRET",
        "cell_memberships": ["cell-east", "cell-west", "cell-hq", "cell-cyber"],
        "compartments": ["PROJECT_ALPHA", "PROJECT_OMEGA", "OPERATION_DELTA"],
        "department": "leadership",
        "description": "Full access — all classifications, all cells",
    },
    "alpha-senior": {
        "username": "alpha-senior",
        "name": "Senior Analyst Kowalski (Alpha)",
        "organization": "agency-alpha",
        "roles": ["senior-analyst"],
        "clearance": "SECRET",
        "cell_memberships": ["cell-east", "cell-hq"],
        "compartments": ["PROJECT_ALPHA", "PROJECT_OMEGA"],
        "department": "analysis",
        "description": "SECRET clearance — East & HQ cells only",
    },
    "alpha-analyst": {
        "username": "alpha-analyst",
        "name": "Analyst Park (Alpha)",
        "organization": "agency-alpha",
        "roles": ["analyst"],
        "clearance": "CONFIDENTIAL",
        "cell_memberships": ["cell-hq"],
        "compartments": ["PROJECT_ALPHA"],
        "department": "analysis",
        "description": "CONFIDENTIAL clearance — HQ cell only",
    },
    "alpha-viewer": {
        "username": "alpha-viewer",
        "name": "Intern Davis (Alpha)",
        "organization": "agency-alpha",
        "roles": ["viewer"],
        "clearance": "UNCLASSIFIED",
        "cell_memberships": [],
        "compartments": [],
        "department": "public-affairs",
        "description": "UNCLASSIFIED only — no cell memberships",
    },
    "bravo-analyst": {
        "username": "bravo-analyst",
        "name": "Analyst Tanaka (Bravo)",
        "organization": "agency-bravo",
        "roles": ["analyst"],
        "clearance": "SECRET",
        "cell_memberships": ["cell-west"],
        "compartments": ["PROJECT_ALPHA"],
        "department": "field-ops",
        "description": "SECRET clearance — West cell only (federated partner)",
    },
    "bravo-viewer": {
        "username": "bravo-viewer",
        "name": "Clerk Okonkwo (Bravo)",
        "organization": "agency-bravo",
        "roles": ["viewer"],
        "clearance": "UNCLASSIFIED",
        "cell_memberships": [],
        "compartments": [],
        "department": "admin",
        "description": "UNCLASSIFIED only — Bravo org (federated partner)",
    },
}


# Keycloak user mappings (username -> demo profile key or custom profile)
KEYCLOAK_USER_PROFILES: Dict[str, Dict[str, Any]] = {
    "alice_admin": {
        "username": "alice_admin",
        "name": "Alice Administrator",
        "organization": "agency-alpha",
        "roles": ["admin", "auditor"],
        "clearance": "TOP_SECRET",
        "cell_memberships": ["cell-east", "cell-west", "cell-hq", "cell-cyber"],
        "compartments": ["PROJECT_ALPHA", "PROJECT_OMEGA", "OPERATION_DELTA"],
        "department": "leadership",
        "description": "TOP SECRET / All Compartments / Admin+Auditor",
    },
    "bob_analyst": {
        "username": "bob_analyst",
        "name": "Bob Analyst",
        "organization": "agency-alpha",
        "roles": ["analyst"],
        "clearance": "SECRET",
        "cell_memberships": ["cell-hq", "cell-east", "cell-cyber"],
        "compartments": ["PROJECT_ALPHA", "PROJECT_OMEGA"],
        "department": "analysis",
        "description": "SECRET / PROJECT_ALPHA+OMEGA / Analyst",
    },
    "carol_viewer": {
        "username": "carol_viewer",
        "name": "Carol Viewer",
        "organization": "agency-alpha",
        "roles": ["viewer"],
        "clearance": "CONFIDENTIAL",
        "cell_memberships": ["cell-hq", "cell-east"],
        "compartments": ["PROJECT_ALPHA"],
        "department": "operations",
        "description": "CONFIDENTIAL / PROJECT_ALPHA / Viewer",
    },
    "dave_manager": {
        "username": "dave_manager",
        "name": "Dave Manager",
        "organization": "agency-alpha",
        "roles": ["manager", "analyst"],
        "clearance": "SECRET",
        "cell_memberships": ["cell-hq", "cell-west", "cell-east"],
        "compartments": ["PROJECT_ALPHA", "OPERATION_DELTA"],
        "department": "operations",
        "description": "SECRET / PROJECT_ALPHA+DELTA / Manager+Analyst",
    },
    "eve_auditor": {
        "username": "eve_auditor",
        "name": "Eve Auditor",
        "organization": "agency-alpha",
        "roles": ["auditor", "viewer"],
        "clearance": "TOP_SECRET",
        "cell_memberships": ["cell-east", "cell-west", "cell-hq", "cell-cyber"],
        "compartments": ["PROJECT_ALPHA", "PROJECT_OMEGA", "OPERATION_DELTA"],
        "department": "compliance",
        "description": "TOP SECRET / All Compartments / Auditor+Viewer",
    },
    "frank_bravo": {
        "username": "frank_bravo",
        "name": "Frank Bravo-Analyst",
        "organization": "agency-bravo",
        "roles": ["analyst"],
        "clearance": "SECRET",
        "cell_memberships": ["cell-west"],
        "compartments": ["PROJECT_ALPHA"],
        "department": "field-ops",
        "description": "SECRET / PROJECT_ALPHA / Analyst (Bravo)",
    },
    "grace_bravo": {
        "username": "grace_bravo",
        "name": "Grace Bravo-Viewer",
        "organization": "agency-bravo",
        "roles": ["viewer"],
        "clearance": "CONFIDENTIAL",
        "cell_memberships": [],
        "compartments": [],
        "department": "admin",
        "description": "CONFIDENTIAL / No Compartments / Viewer (Bravo)",
    },
}


def normalize_organization(org: str) -> str:
    """Normalize organization name to lowercase with hyphens."""
    if not org:
        return "agency-alpha"
    org_lower = org.lower().replace(" ", "-")
    if "alpha" in org_lower:
        return "agency-alpha"
    if "bravo" in org_lower:
        return "agency-bravo"
    return org_lower


def get_user_profile(auth_user: Optional[AuthenticatedUser], user_id: str = "") -> Dict[str, Any]:
    """Get user profile from authenticated user or demo user."""
    # If authenticated via Keycloak
    if auth_user and auth_user.is_authenticated:
        username = auth_user.username
        
        # Check for predefined Keycloak profile
        if username in KEYCLOAK_USER_PROFILES:
            profile = KEYCLOAK_USER_PROFILES[username].copy()
            # Update with actual token values where applicable
            profile["organization"] = normalize_organization(auth_user.organization)
            return profile
        
        # Build profile from token claims
        is_admin = "admin" in auth_user.roles
        cells = compartments_to_cells(auth_user.compartments, is_admin)
        
        return {
            "username": username,
            "name": f"{auth_user.first_name or ''} {auth_user.last_name or ''}".strip() or username,
            "organization": normalize_organization(auth_user.organization),
            "roles": auth_user.roles,
            "clearance": auth_user.clearance_level or "UNCLASSIFIED",
            "cell_memberships": cells,
            "compartments": auth_user.compartments,
            "department": "general",
            "description": f"Keycloak user: {auth_user.clearance_level}",
        }
    
    # Fall back to demo user
    if user_id and user_id in DEMO_USERS:
        return DEMO_USERS[user_id]
    
    # Default demo user
    return DEMO_USERS.get("alpha-analyst", DEMO_USERS["alpha-viewer"])


# ═══════════════════════════════════════════════════════════════════════
# SECTION 6 — SEED DOCUMENTS (Including NTK)
# ═══════════════════════════════════════════════════════════════════════

SEED_DOCUMENTS = [
    # ── UNCLASSIFIED ────────────────────────────────────────────────
    {
        "title": "Public Affairs Monthly Summary — January",
        "content": "Community engagement events across all districts continued at expected levels. The public outreach programme received positive media coverage. No operational details included.",
        "author": "Public Affairs Office",
        "classification": "UNCLASSIFIED",
        "organization": "agency-alpha",
        "department": "public-affairs",
        "cell_access": ["all"],
        "shared_with": ["all"],
        "source_name": "",
        "handler_id": "",
        "raw_intel": "",
        "location": "All Districts",
        "date_created": "2025-01-28",
        "ntk_required": False,
        "ntk_users": [],
        "ntk_compartments": [],
    },
    {
        "title": "Agency Bravo Quarterly Newsletter — Q4",
        "content": "Bravo operations maintained steady performance in Q4. Staff training programmes expanded to include cross-agency collaboration modules with Alpha.",
        "author": "Bravo Communications",
        "classification": "UNCLASSIFIED",
        "organization": "agency-bravo",
        "department": "communications",
        "cell_access": ["all"],
        "shared_with": ["all"],
        "source_name": "",
        "handler_id": "",
        "raw_intel": "",
        "location": "Bravo HQ",
        "date_created": "2025-01-05",
        "ntk_required": False,
        "ntk_users": [],
        "ntk_compartments": [],
    },
    {
        "title": "Open Data Initiative — Environmental Monitoring Results",
        "content": "Sensor network data from 47 monitoring stations published under open data mandate. Air quality indices remain within acceptable ranges for all tracked regions.",
        "author": "Data Governance Team",
        "classification": "UNCLASSIFIED",
        "organization": "agency-alpha",
        "department": "data-governance",
        "cell_access": ["all"],
        "shared_with": ["all"],
        "source_name": "",
        "handler_id": "",
        "raw_intel": "",
        "location": "National",
        "date_created": "2025-01-18",
        "ntk_required": False,
        "ntk_users": [],
        "ntk_compartments": [],
    },
    {
        "title": "Training Calendar — February 2025",
        "content": "Upcoming training sessions include: Basic Security Awareness (all staff), Advanced Threat Detection (analysts), Leadership Development (managers). Registration open.",
        "author": "Training Department",
        "classification": "UNCLASSIFIED",
        "organization": "agency-alpha",
        "department": "training",
        "cell_access": ["all"],
        "shared_with": ["all"],
        "source_name": "",
        "handler_id": "",
        "raw_intel": "",
        "location": "HQ Training Center",
        "date_created": "2025-01-30",
        "ntk_required": False,
        "ntk_users": [],
        "ntk_compartments": [],
    },

    # ── CONFIDENTIAL ────────────────────────────────────────────────
    {
        "title": "Internal Resource Allocation Plan — FY26",
        "content": "Budget forecasts project a 12% increase in technical surveillance funding. Human resources will redistribute three analyst positions from Western to Eastern district to address emerging workload.",
        "author": "Resource Planning",
        "classification": "CONFIDENTIAL",
        "organization": "agency-alpha",
        "department": "finance",
        "cell_access": ["cell-hq"],
        "shared_with": [],
        "source_name": "Budget Office",
        "handler_id": "FIN-2025-001",
        "raw_intel": "",
        "location": "HQ",
        "date_created": "2025-01-22",
        "ntk_required": False,
        "ntk_users": [],
        "ntk_compartments": [],
    },
    {
        "title": "Personnel Security Evaluation Report — Q4",
        "content": "Quarterly review of personnel security posture. Three staff members flagged for additional vetting due to foreign travel. Two clearance upgrades approved.",
        "author": "Security Division",
        "classification": "CONFIDENTIAL",
        "organization": "agency-alpha",
        "department": "security",
        "cell_access": ["cell-hq", "cell-east"],
        "shared_with": [],
        "source_name": "HR Security",
        "handler_id": "SEC-2025-Q4",
        "raw_intel": "Vetting flags: Travel to Region X (2), Financial anomaly (1)",
        "location": "HQ",
        "date_created": "2025-01-15",
        "ntk_required": False,
        "ntk_users": [],
        "ntk_compartments": [],
    },
    {
        "title": "Technical Infrastructure Assessment — Eastern Region",
        "content": "Network vulnerability assessment for Eastern region infrastructure. 14 medium-severity vulnerabilities identified. Remediation plan attached.",
        "author": "IT Security Team",
        "classification": "CONFIDENTIAL",
        "organization": "agency-alpha",
        "department": "it-security",
        "cell_access": ["cell-east", "cell-cyber"],
        "shared_with": [],
        "source_name": "Vulnerability Scanner",
        "handler_id": "VULN-2025-014",
        "raw_intel": "CVE details: 8 web app vulns, 4 infrastructure, 2 endpoint",
        "location": "Eastern Region",
        "date_created": "2025-01-20",
        "ntk_required": False,
        "ntk_users": [],
        "ntk_compartments": [],
    },
    {
        "title": "Cross-Agency Liaison Protocol Update",
        "content": "Updated protocols for information sharing between Agency Alpha and Agency Bravo. New encryption requirements for classified material transfer.",
        "author": "Interagency Affairs",
        "classification": "CONFIDENTIAL",
        "organization": "agency-alpha",
        "department": "liaison",
        "cell_access": ["cell-hq", "cell-west"],
        "shared_with": ["agency-bravo"],
        "source_name": "Policy Office",
        "handler_id": "POL-2025-007",
        "raw_intel": "",
        "location": "HQ",
        "date_created": "2025-01-25",
        "ntk_required": False,
        "ntk_users": [],
        "ntk_compartments": [],
    },
    {
        "title": "Bravo Field Equipment Inventory",
        "content": "Current inventory of field equipment assigned to Bravo operations. Includes communication devices, surveillance gear, and protective equipment.",
        "author": "Logistics Division",
        "classification": "CONFIDENTIAL",
        "organization": "agency-bravo",
        "department": "logistics",
        "cell_access": ["cell-west"],
        "shared_with": [],
        "source_name": "Asset Management",
        "handler_id": "BRV-INV-2025",
        "raw_intel": "",
        "location": "Bravo West Office",
        "date_created": "2025-01-12",
        "ntk_required": False,
        "ntk_users": [],
        "ntk_compartments": [],
    },

    # ── SECRET ─────────────────────────────────────────────────────
    {
        "title": "Operation MORNING STAR — Phase 2 Planning",
        "content": "Operational planning for Phase 2 of MORNING STAR. Target acquisition timeline adjusted based on new intelligence. Resources allocated from Eastern cell.",
        "author": "Operations Division",
        "classification": "SECRET",
        "organization": "agency-alpha",
        "department": "operations",
        "cell_access": ["cell-east", "cell-hq"],
        "shared_with": [],
        "source_name": "HUMINT-A7",
        "handler_id": "OPS-A7-2025",
        "raw_intel": "Source reports target movement pattern change. New surveillance window identified.",
        "location": "Eastern Region",
        "date_created": "2025-01-24",
        "ntk_required": False,
        "ntk_users": [],
        "ntk_compartments": [],
    },
    {
        "title": "Threat Assessment — Cyber Infrastructure",
        "content": "Assessment of cyber threats to critical infrastructure in Western region. Three APT groups identified as active threats. Recommended defensive measures included.",
        "author": "Cyber Threat Intelligence",
        "classification": "SECRET",
        "organization": "agency-alpha",
        "department": "cyber",
        "cell_access": ["cell-cyber", "cell-west"],
        "shared_with": [],
        "source_name": "SIGINT-C3",
        "handler_id": "CTI-2025-003",
        "raw_intel": "APT indicators: C2 servers at 192.168.x.x, malware hashes SHA256:abc123...",
        "location": "Western Region",
        "date_created": "2025-01-19",
        "ntk_required": False,
        "ntk_users": [],
        "ntk_compartments": [],
    },
    {
        "title": "Joint Operation Brief — WESTERN SHIELD",
        "content": "Briefing document for joint Alpha-Bravo operation WESTERN SHIELD. Coordination protocols and communication channels established.",
        "author": "Joint Operations Center",
        "classification": "SECRET",
        "organization": "agency-alpha",
        "department": "operations",
        "cell_access": ["cell-west", "cell-hq"],
        "shared_with": ["agency-bravo"],
        "source_name": "JOC-Alpha",
        "handler_id": "JOP-2025-WS",
        "raw_intel": "Coordination timeline: D-7 prep, D-3 final brief, D-day execute",
        "location": "Western Region",
        "date_created": "2025-01-26",
        "ntk_required": False,
        "ntk_users": [],
        "ntk_compartments": [],
    },
    {
        "title": "Intelligence Source Assessment — CARDINAL Network",
        "content": "Assessment of reliability and access levels for CARDINAL network sources. Three sources upgraded to Tier-1 reliability.",
        "author": "Source Evaluation Unit",
        "classification": "SECRET",
        "organization": "agency-alpha",
        "department": "intelligence",
        "cell_access": ["cell-hq"],
        "shared_with": [],
        "source_name": "Multiple HUMINT",
        "handler_id": "SEU-CARD-2025",
        "raw_intel": "Source CARDINAL-3: Promoted to Tier-1. Access expanded to include ministerial level.",
        "location": "HQ",
        "date_created": "2025-01-21",
        "ntk_required": True,
        "ntk_users": ["alice_admin", "bob_analyst"],
        "ntk_compartments": ["PROJECT_OMEGA"],
    },
    {
        "title": "Bravo Regional Threat Summary",
        "content": "Monthly threat summary for Bravo operational region. Increased activity from organized crime elements. Three incidents requiring Alpha coordination.",
        "author": "Bravo Intelligence",
        "classification": "SECRET",
        "organization": "agency-bravo",
        "department": "intelligence",
        "cell_access": ["cell-west"],
        "shared_with": ["agency-alpha"],
        "source_name": "BRAVO-INT",
        "handler_id": "BRV-THREAT-01",
        "raw_intel": "Incident details: Border crossing (2), Financial transfer (1)",
        "location": "Bravo Region",
        "date_created": "2025-01-23",
        "ntk_required": False,
        "ntk_users": [],
        "ntk_compartments": [],
    },

    # ── TOP SECRET ──────────────────────────────────────────────────
    {
        "title": "Strategic Intelligence Estimate — Q1 2025",
        "content": "Comprehensive strategic assessment of global threat landscape. Analysis of state actor intentions and capabilities across all regions.",
        "author": "Strategic Analysis Division",
        "classification": "TOP_SECRET",
        "organization": "agency-alpha",
        "department": "strategic",
        "cell_access": ["cell-hq"],
        "shared_with": [],
        "source_name": "All-Source",
        "handler_id": "SIE-2025-Q1",
        "raw_intel": "Key judgments: High confidence threat from Actor-X, Moderate from Actor-Y",
        "location": "HQ",
        "date_created": "2025-01-27",
        "ntk_required": True,
        "ntk_users": ["alice_admin", "eve_auditor"],
        "ntk_compartments": ["PROJECT_OMEGA"],
    },
    {
        "title": "Covert Action Authorization — NIGHTFALL",
        "content": "Presidential authorization for covert action program NIGHTFALL. Full operational parameters and legal findings classified.",
        "author": "Director's Office",
        "classification": "TOP_SECRET",
        "organization": "agency-alpha",
        "department": "leadership",
        "cell_access": ["cell-hq"],
        "shared_with": [],
        "source_name": "Executive",
        "handler_id": "CAA-NIGHTFALL",
        "raw_intel": "Authorization valid through FY26. Quarterly oversight reporting required.",
        "location": "HQ",
        "date_created": "2025-01-10",
        "ntk_required": True,
        "ntk_users": ["alice_admin"],
        "ntk_compartments": [],
    },
    {
        "title": "Technical Collection Capabilities Assessment",
        "content": "Assessment of current technical collection capabilities against priority targets. Gap analysis and capability development recommendations.",
        "author": "Technical Division",
        "classification": "TOP_SECRET",
        "organization": "agency-alpha",
        "department": "technical",
        "cell_access": ["cell-cyber", "cell-hq"],
        "shared_with": [],
        "source_name": "TECHINT",
        "handler_id": "TCA-2025",
        "raw_intel": "Capability gaps: Encrypted comms (partial), Satellite imagery (full), Cyber intrusion (developing)",
        "location": "HQ",
        "date_created": "2025-01-16",
        "ntk_required": True,
        "ntk_users": ["alice_admin", "bob_analyst", "eve_auditor"],
        "ntk_compartments": ["PROJECT_OMEGA", "PROJECT_ALPHA"],
    },

    # ── NTK-RESTRICTED DOCUMENTS ────────────────────────────────────
    {
        "title": "Operation DELTA FORCE — Execution Orders",
        "content": "Final execution orders for Operation DELTA FORCE. Tactical deployment schedule, asset assignments, and contingency protocols.",
        "author": "Operations Command",
        "classification": "SECRET",
        "organization": "agency-alpha",
        "department": "operations",
        "cell_access": ["cell-hq", "cell-west"],
        "shared_with": [],
        "source_name": "OPS-CMD",
        "handler_id": "DELTA-EXEC-01",
        "raw_intel": "H-hour: 0300Z. Primary insertion via Route Alpha. Backup: Route Bravo.",
        "location": "Western Region",
        "date_created": "2025-01-29",
        "ntk_required": True,
        "ntk_users": ["alice_admin", "dave_manager"],
        "ntk_compartments": ["OPERATION_DELTA"],
    },
    {
        "title": "Source Protection Report — CARDINAL Network",
        "content": "Detailed source protection assessment for CARDINAL network assets. Includes counterintelligence measures and emergency extraction procedures.",
        "author": "Counterintelligence Division",
        "classification": "TOP_SECRET",
        "organization": "agency-alpha",
        "department": "counterintel",
        "cell_access": ["cell-hq"],
        "shared_with": [],
        "source_name": "CI-DIVISION",
        "handler_id": "SPR-CARDINAL",
        "raw_intel": "Emergency protocols: EXFIL-7 (primary), EXFIL-9 (backup). Comms plan attached.",
        "location": "HQ",
        "date_created": "2025-01-28",
        "ntk_required": True,
        "ntk_users": ["alice_admin", "bob_analyst"],
        "ntk_compartments": [],
    },
    {
        "title": "Budget Allocation — Black Programs FY26",
        "content": "Detailed budget allocation for classified programs in FY26. Includes funding for NIGHTFALL, MORNING STAR, and three unnamed programs.",
        "author": "Finance Division",
        "classification": "TOP_SECRET",
        "organization": "agency-alpha",
        "department": "finance",
        "cell_access": ["cell-hq"],
        "shared_with": [],
        "source_name": "CFO Office",
        "handler_id": "BUD-BLACK-FY26",
        "raw_intel": "Total allocation: $XXX million. Breakdown by program attached.",
        "location": "HQ",
        "date_created": "2025-01-30",
        "ntk_required": True,
        "ntk_users": ["alice_admin", "dave_manager", "eve_auditor"],
        "ntk_compartments": [],
    },
    {
        "title": "Bravo Special Operations Brief — CROSSWIND",
        "content": "Special operations briefing for joint Alpha-Bravo operation CROSSWIND. Highly compartmented tactical details.",
        "author": "Special Operations",
        "classification": "SECRET",
        "organization": "agency-bravo",
        "department": "special-ops",
        "cell_access": ["cell-west"],
        "shared_with": ["agency-alpha"],
        "source_name": "BRAVO-SO",
        "handler_id": "CROSSWIND-01",
        "raw_intel": "Asset deployment: 3 teams, 12 personnel. Timeline: 72-hour window.",
        "location": "Bravo Region",
        "date_created": "2025-01-31",
        "ntk_required": True,
        "ntk_users": ["alice_admin", "dave_manager", "frank_bravo"],
        "ntk_compartments": ["OPERATION_DELTA"],
    },
]


# ═══════════════════════════════════════════════════════════════════════
# SECTION 7 — INDEX SETTINGS
# ═══════════════════════════════════════════════════════════════════════

INDEX_SETTINGS = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
    },
    "mappings": {
        "properties": {
            "title": {"type": "text", "analyzer": "standard"},
            "content": {"type": "text", "analyzer": "standard"},
            "author": {"type": "keyword"},
            "classification": {"type": "keyword"},
            "organization": {"type": "keyword"},
            "department": {"type": "keyword"},
            "cell_access": {"type": "keyword"},
            "shared_with": {"type": "keyword"},
            "source_name": {"type": "text"},
            "handler_id": {"type": "keyword"},
            "raw_intel": {"type": "text"},
            "location": {"type": "keyword"},
            "date_created": {"type": "date", "format": "yyyy-MM-dd"},
            "ntk_required": {"type": "boolean"},
            "ntk_users": {"type": "keyword"},
            "ntk_compartments": {"type": "keyword"},
        }
    },
}


# ═══════════════════════════════════════════════════════════════════════
# SECTION 8 — QUERY BUILDERS
# ═══════════════════════════════════════════════════════════════════════

def _text_query(search_text: str) -> dict:
    """Build text match query or match_all if empty."""
    if search_text.strip():
        return {
            "multi_match": {
                "query": search_text,
                "fields": ["title^3", "content", "author", "location", "department"],
                "type": "best_fields",
                "fuzziness": "AUTO",
            }
        }
    return {"match_all": {}}


def _org_filter(org: str) -> dict:
    """Organization filter: own org OR shared_with includes 'all' or own org."""
    return {
        "bool": {
            "should": [
                {"term": {"organization": org}},
                {"term": {"shared_with": "all"}},
                {"term": {"shared_with": org}},
            ],
            "minimum_should_match": 1,
        }
    }


def build_rbac_query(search_text: str, user: dict) -> dict:
    """
    RBAC Mode: Classification + Organisation.
    Document visible iff:
      • classification ≤ user's clearance
      • organisation matches OR shared_with includes user's org / 'all'
    """
    return {
        "bool": {
            "must": [_text_query(search_text)],
            "filter": [
                {"terms": {"classification": allowed_classifications(user["clearance"])}},
                _org_filter(user["organization"]),
            ],
        }
    }


def build_cell_query(search_text: str, user: dict) -> dict:
    """
    Cell-Level Mode: RBAC + Cell membership.
    Adds requirement that cell_access contains 'all' or at least one of user's cells.
    """
    cells = user.get("cell_memberships", [])
    cell_should = [{"term": {"cell_access": "all"}}]
    for cell in cells:
        cell_should.append({"term": {"cell_access": cell}})

    return {
        "bool": {
            "must": [_text_query(search_text)],
            "filter": [
                {"terms": {"classification": allowed_classifications(user["clearance"])}},
                _org_filter(user["organization"]),
                {"bool": {"should": cell_should, "minimum_should_match": 1}},
            ],
        }
    }


def build_ntk_query(search_text: str, user: dict) -> dict:
    """
    NTK Mode: Cell-Level + Need-to-Know check.
    Document visible iff:
      • Passes cell-level checks AND
      • (ntk_required = false OR user in ntk_users OR user has matching ntk_compartment)
    """
    username = user.get("username", "")
    user_compartments = user.get("compartments", [])
    cells = user.get("cell_memberships", [])
    
    cell_should = [{"term": {"cell_access": "all"}}]
    for cell in cells:
        cell_should.append({"term": {"cell_access": cell}})

    # NTK filter: document passes if any of these are true:
    # 1. ntk_required is false or doesn't exist
    # 2. user's username is in ntk_users
    # 3. user has at least one compartment in ntk_compartments
    ntk_should = [
        {"bool": {"must_not": [{"term": {"ntk_required": True}}]}},
        {"term": {"ntk_users": username}},
    ]
    for comp in user_compartments:
        ntk_should.append({"term": {"ntk_compartments": comp}})

    return {
        "bool": {
            "must": [_text_query(search_text)],
            "filter": [
                {"terms": {"classification": allowed_classifications(user["clearance"])}},
                _org_filter(user["organization"]),
                {"bool": {"should": cell_should, "minimum_should_match": 1}},
                {"bool": {"should": ntk_should, "minimum_should_match": 1}},
            ],
        }
    }


SENSITIVE_FIELDS = ["source_name", "handler_id", "raw_intel"]


def apply_field_masking(hits: list, user: dict, mode: str = "cell") -> list:
    """
    Field-level masking for Cell-Level and NTK modes.
    Masks sensitive fields based on cell access and NTK status.
    """
    username = user.get("username", "")
    user_cells = set(user.get("cell_memberships", []))
    user_compartments = set(user.get("compartments", []))

    for hit in hits:
        src = hit["_source"]
        doc_cells = set(src.get("cell_access", []))
        ntk_required = src.get("ntk_required", False)
        ntk_users = set(src.get("ntk_users", []))
        ntk_compartments = set(src.get("ntk_compartments", []))

        # Check cell access (ignoring 'all' wildcard)
        specific_cells = doc_cells - {"all"}
        has_cell_access = bool(user_cells & specific_cells)
        
        # Check NTK access
        has_ntk_access = (
            not ntk_required or
            username in ntk_users or
            bool(user_compartments & ntk_compartments)
        )

        src["_field_access"] = {}
        src["_ntk_status"] = {
            "required": ntk_required,
            "has_access": has_ntk_access,
            "reason": "explicit_user" if username in ntk_users else (
                "compartment_match" if bool(user_compartments & ntk_compartments) else (
                    "not_required" if not ntk_required else "denied"
                )
            )
        }

        for field in SENSITIVE_FIELDS:
            val = src.get(field, "")
            if not val:
                src["_field_access"][field] = "empty"
                continue
            
            # In NTK mode, check both cell and NTK access
            if mode == "ntk":
                if has_cell_access and has_ntk_access:
                    src["_field_access"][field] = "visible"
                elif not has_cell_access:
                    src[field] = "██ CELL RESTRICTED ██"
                    src["_field_access"][field] = "cell_denied"
                else:
                    src[field] = "██ NTK RESTRICTED ██"
                    src["_field_access"][field] = "ntk_denied"
            else:
                # Cell mode - only check cell access
                if has_cell_access:
                    src["_field_access"][field] = "visible"
                else:
                    src[field] = "██ REDACTED ██"
                    src["_field_access"][field] = "redacted"

    return hits


# ═══════════════════════════════════════════════════════════════════════
# SECTION 9 — STARTUP (INDEX CREATION + SEED)
# ═══════════════════════════════════════════════════════════════════════

@app.on_event("startup")
def startup_event():
    # Retry until OpenSearch is reachable
    for attempt in range(40):
        try:
            info = os_client.info()
            logger.info("Connected to OpenSearch %s", info["version"]["number"])
            break
        except Exception as exc:
            logger.warning("OpenSearch not ready (attempt %d): %s", attempt + 1, exc)
            time.sleep(3)
    else:
        raise RuntimeError("Could not connect to OpenSearch after 40 attempts")

    # Create index
    if not os_client.indices.exists(INDEX_NAME):
        os_client.indices.create(INDEX_NAME, body=INDEX_SETTINGS)
        logger.info("Created index '%s'", INDEX_NAME)

        # Seed documents
        for i, doc in enumerate(SEED_DOCUMENTS):
            os_client.index(index=INDEX_NAME, id=f"seed-{i}", body=doc, refresh=False)
        os_client.indices.refresh(INDEX_NAME)
        logger.info("Seeded %d documents", len(SEED_DOCUMENTS))
    else:
        logger.info("Index '%s' already exists — skipping seed", INDEX_NAME)


# ═══════════════════════════════════════════════════════════════════════
# SECTION 10 — API ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════

@app.get("/api/users")
def list_users():
    """Return all demo user profiles."""
    return DEMO_USERS


@app.get("/api/keycloak-users")
def list_keycloak_users():
    """Return Keycloak user profile mappings."""
    return KEYCLOAK_USER_PROFILES


@app.get("/api/me")
async def get_current_user_profile(
    user_id: str = Query(default=""),
    auth_user: Optional[AuthenticatedUser] = Depends(get_current_user)
):
    """Get current user profile (from Keycloak or demo user)."""
    profile = get_user_profile(auth_user, user_id)
    return {
        "authenticated": auth_user is not None and auth_user.is_authenticated,
        "source": "keycloak" if (auth_user and auth_user.is_authenticated) else "demo",
        "profile": profile
    }


@app.get("/api/stats")
def index_stats():
    """Total document count (unfiltered)."""
    try:
        count = os_client.count(index=INDEX_NAME)["count"]
        return {"total_documents": count}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ── SEARCH ──────────────────────────────────────────────────────────────

def _execute_search(query: dict, size: int = 50) -> dict:
    return os_client.search(index=INDEX_NAME, body={"query": query, "size": size, "sort": [{"date_created": "desc"}]})


def _format_hit(hit: dict) -> dict:
    doc = hit["_source"]
    doc["_id"] = hit["_id"]
    doc["_score"] = hit.get("_score")
    return doc


@app.post("/api/search")
async def search_documents(
    req: SearchRequest,
    auth_user: Optional[AuthenticatedUser] = Depends(get_current_user)
):
    """Search with RBAC, Cell-Level, or NTK security mode."""
    user = get_user_profile(auth_user, req.user_id)

    if req.mode == "rbac":
        query = build_rbac_query(req.query, user)
        results = _execute_search(query)
        hits = [_format_hit(h) for h in results["hits"]["hits"]]
        filter_explanation = (
            f"Classification ≤ {user['clearance']}  •  "
            f"Organisation = {user['organization']} (+ shared)"
        )
    elif req.mode == "cell":
        query = build_cell_query(req.query, user)
        results = _execute_search(query)
        raw_hits = results["hits"]["hits"]
        apply_field_masking(raw_hits, user, "cell")
        hits = [_format_hit(h) for h in raw_hits]
        cells_str = ", ".join(user.get("cell_memberships", [])) if user.get("cell_memberships") else "(none)"
        filter_explanation = (
            f"Classification ≤ {user['clearance']}  •  "
            f"Organisation = {user['organization']} (+ shared)  •  "
            f"Cells = {cells_str}  •  Sensitive fields masked where cell access is insufficient"
        )
    else:  # ntk
        query = build_ntk_query(req.query, user)
        results = _execute_search(query)
        raw_hits = results["hits"]["hits"]
        apply_field_masking(raw_hits, user, "ntk")
        hits = [_format_hit(h) for h in raw_hits]
        cells_str = ", ".join(user.get("cell_memberships", [])) if user.get("cell_memberships") else "(none)"
        comps_str = ", ".join(user.get("compartments", [])) if user.get("compartments") else "(none)"
        filter_explanation = (
            f"Classification ≤ {user['clearance']}  •  "
            f"Organisation = {user['organization']} (+ shared)  •  "
            f"Cells = {cells_str}  •  "
            f"Compartments = {comps_str}  •  "
            f"NTK check: user in ntk_users OR matching compartment"
        )

    total_docs = os_client.count(index=INDEX_NAME)["count"]
    return {
        "mode": req.mode,
        "user": user,
        "query_text": req.query or "(all documents)",
        "filter_explanation": filter_explanation,
        "total_in_index": total_docs,
        "visible_count": len(hits),
        "hidden_count": total_docs - len(hits),
        "documents": hits,
    }


# ── COMPARE (side-by-side) ──────────────────────────────────────────────

@app.post("/api/compare")
async def compare_modes(
    req: CompareRequest,
    auth_user: Optional[AuthenticatedUser] = Depends(get_current_user)
):
    """Run the same query in all three modes and return side-by-side results."""
    user = get_user_profile(auth_user, req.user_id)

    # RBAC
    rbac_query = build_rbac_query(req.query, user)
    rbac_results = _execute_search(rbac_query)
    rbac_hits = [_format_hit(h) for h in rbac_results["hits"]["hits"]]

    # Cell-Level
    cell_query = build_cell_query(req.query, user)
    cell_results = _execute_search(cell_query)
    cell_raw = [dict(h) for h in cell_results["hits"]["hits"]]
    for h in cell_raw:
        h["_source"] = dict(h["_source"])
    apply_field_masking(cell_raw, user, "cell")
    cell_hits = [_format_hit(h) for h in cell_raw]

    # NTK
    ntk_query = build_ntk_query(req.query, user)
    ntk_results = _execute_search(ntk_query)
    ntk_raw = [dict(h) for h in ntk_results["hits"]["hits"]]
    for h in ntk_raw:
        h["_source"] = dict(h["_source"])
    apply_field_masking(ntk_raw, user, "ntk")
    ntk_hits = [_format_hit(h) for h in ntk_raw]

    total = os_client.count(index=INDEX_NAME)["count"]
    return {
        "user": user,
        "query_text": req.query or "(all documents)",
        "total_in_index": total,
        "rbac": {"visible": len(rbac_hits), "documents": rbac_hits},
        "cell": {"visible": len(cell_hits), "documents": cell_hits},
        "ntk": {"visible": len(ntk_hits), "documents": ntk_hits},
    }


# ── UPLOAD ──────────────────────────────────────────────────────────────

@app.post("/api/documents")
async def upload_document(
    doc: DocumentUpload,
    auth_user: Optional[AuthenticatedUser] = Depends(get_current_user)
):
    """Index a new document into OpenSearch."""
    body = doc.dict()
    body["date_created"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    
    # Add created_by if authenticated
    if auth_user and auth_user.is_authenticated:
        body["created_by"] = auth_user.username
    
    result = os_client.index(index=INDEX_NAME, body=body, refresh="wait_for")
    return {"status": "indexed", "id": result["_id"]}


# ── DELETE (for demo resets) ────────────────────────────────────────────

@app.post("/api/reset")
async def reset_index(auth_user: Optional[AuthenticatedUser] = Depends(get_current_user)):
    """Delete and re-create the index with fresh seed data."""
    # Allow reset for admins or unauthenticated (demo mode)
    if auth_user and auth_user.is_authenticated and "admin" not in auth_user.roles:
        raise HTTPException(status_code=403, detail="Admin role required for reset")
    
    if os_client.indices.exists(INDEX_NAME):
        os_client.indices.delete(INDEX_NAME)
    os_client.indices.create(INDEX_NAME, body=INDEX_SETTINGS)
    for i, doc in enumerate(SEED_DOCUMENTS):
        os_client.index(index=INDEX_NAME, id=f"seed-{i}", body=doc, refresh=False)
    os_client.indices.refresh(INDEX_NAME)
    return {"status": "reset", "documents_seeded": len(SEED_DOCUMENTS)}


# ═══════════════════════════════════════════════════════════════════════
# SECTION 11 — STATIC FILES (UI)
# ═══════════════════════════════════════════════════════════════════════

app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def serve_ui():
    return FileResponse("static/index.html")
