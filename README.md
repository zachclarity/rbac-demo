# RBAC + Cell-Level Security Demo

![Login Screen](https://github.com/zactonicsai/rbac-demo/blob/main/rbacdemo.png)

# OpenSearch Security Implementation with JWT Authentication

## Executive Summary

This document describes how the OpenSearch-based document search application implements three layers of security filtering using JWT (JSON Web Token) authentication from Keycloak. The system enforces access control at the **application layer** by dynamically constructing OpenSearch queries based on authenticated user attributes.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SECURITY ARCHITECTURE OVERVIEW                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   ┌──────────┐      ┌──────────┐      ┌──────────┐      ┌──────────────┐   │
│   │  User    │─────▶│ Keycloak │─────▶│  Search  │─────▶│  OpenSearch  │   │
│   │ Browser  │      │   IdP    │      │   App    │      │    Index     │   │
│   └──────────┘      └──────────┘      └──────────┘      └──────────────┘   │
│        │                 │                  │                   │          │
│        │   1. Login      │                  │                   │          │
│        │────────────────▶│                  │                   │          │
│        │                 │                  │                   │          │
│        │   2. JWT Token  │                  │                   │          │
│        │◀────────────────│                  │                   │          │
│        │                 │                  │                   │          │
│        │   3. Search Request + JWT          │                   │          │
│        │───────────────────────────────────▶│                   │          │
│        │                 │                  │                   │          │
│        │                 │   4. Validate JWT│                   │          │
│        │                 │◀─────────────────│                   │          │
│        │                 │                  │                   │          │
│        │                 │   5. User Claims │                   │          │
│        │                 │─────────────────▶│                   │          │
│        │                 │                  │                   │          │
│        │                 │                  │ 6. Build Filtered │          │
│        │                 │                  │    Query          │          │
│        │                 │                  │──────────────────▶│          │
│        │                 │                  │                   │          │
│        │                 │                  │ 7. Filtered       │          │
│        │                 │                  │    Results        │          │
│        │                 │                  │◀──────────────────│          │
│        │                 │                  │                   │          │
│        │   8. Response (only authorized documents)              │          │
│        │◀───────────────────────────────────│                   │          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Table of Contents

1. [Data Model](#1-data-model)
2. [JWT Authentication Flow](#2-jwt-authentication-flow)
3. [Security Modes](#3-security-modes)
4. [OpenSearch Query Construction](#4-opensearch-query-construction)
5. [Field-Level Masking](#5-field-level-masking)
6. [Configuration Reference](#6-configuration-reference)
7. [User Access Matrix](#7-user-access-matrix)

---

## 1. Data Model

### 1.1 Document Schema

Every document in OpenSearch contains security metadata that determines who can access it:

```json
{
  "title": "Operation DELTA FORCE — Execution Orders",
  "content": "Final execution orders for Operation DELTA FORCE...",
  "author": "Operations Command",
  
  // ═══════════════════════════════════════════════════════════════
  // SECURITY METADATA - Used for access control filtering
  // ═══════════════════════════════════════════════════════════════
  
  // LAYER 1: RBAC (Role-Based Access Control)
  "classification": "SECRET",           // UNCLASSIFIED | CONFIDENTIAL | SECRET | TOP_SECRET
  "organization": "agency-alpha",       // Owning organization
  "shared_with": ["agency-bravo"],      // Cross-org sharing list (or ["all"])
  
  // LAYER 2: Cell-Level Access
  "cell_access": ["cell-hq", "cell-west"],  // Required cell memberships (or ["all"])
  
  // LAYER 3: Need-to-Know (NTK)
  "ntk_required": true,                 // Is explicit NTK authorization required?
  "ntk_users": ["alice_admin", "dave_manager"],  // Explicit user whitelist
  "ntk_compartments": ["OPERATION_DELTA"],       // Required compartment access
  
  // SENSITIVE FIELDS (subject to masking)
  "source_name": "OPS-CMD",
  "handler_id": "DELTA-EXEC-01",
  "raw_intel": "H-hour: 0300Z. Primary: Route Alpha.",
  
  // METADATA
  "department": "operations",
  "location": "Western Region",
  "date_created": "2025-01-29"
}
```

### 1.2 OpenSearch Index Mapping

```json
{
  "settings": {
    "number_of_shards": 1,
    "number_of_replicas": 0
  },
  "mappings": {
    "properties": {
      "title":            { "type": "text", "analyzer": "standard" },
      "content":          { "type": "text", "analyzer": "standard" },
      "author":           { "type": "keyword" },
      "classification":   { "type": "keyword" },
      "organization":     { "type": "keyword" },
      "department":       { "type": "keyword" },
      "cell_access":      { "type": "keyword" },
      "shared_with":      { "type": "keyword" },
      "source_name":      { "type": "text" },
      "handler_id":       { "type": "keyword" },
      "raw_intel":        { "type": "text" },
      "location":         { "type": "keyword" },
      "date_created":     { "type": "date", "format": "yyyy-MM-dd" },
      "ntk_required":     { "type": "boolean" },
      "ntk_users":        { "type": "keyword" },
      "ntk_compartments": { "type": "keyword" }
    }
  }
}
```

### 1.3 User Profile Schema

User attributes are extracted from JWT claims and mapped to a profile:

```json
{
  "username": "dave_manager",
  "name": "Dave Manager",
  "organization": "agency-alpha",
  "roles": ["manager", "analyst"],
  "clearance": "SECRET",
  "cell_memberships": ["cell-hq", "cell-west", "cell-east"],
  "compartments": ["PROJECT_ALPHA", "OPERATION_DELTA"],
  "department": "operations"
}
```

### 1.4 Classification Hierarchy

Classifications are hierarchical — higher clearance grants access to all lower levels:

```
┌─────────────────────────────────────────────────────────────┐
│                  CLASSIFICATION HIERARCHY                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   TOP_SECRET ────────────────────────────────────▶ Level 4  │
│       │                                                     │
│       ▼                                                     │
│   SECRET ────────────────────────────────────────▶ Level 3  │
│       │                                                     │
│       ▼                                                     │
│   CONFIDENTIAL ──────────────────────────────────▶ Level 2  │
│       │                                                     │
│       ▼                                                     │
│   UNCLASSIFIED ──────────────────────────────────▶ Level 1  │
│                                                             │
│   User with SECRET clearance can access:                    │
│   ✓ SECRET, CONFIDENTIAL, UNCLASSIFIED                      │
│   ✗ TOP_SECRET                                              │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. JWT Authentication Flow

### 2.1 Keycloak Token Structure

When a user authenticates via Keycloak, they receive a JWT with custom claims:

```json
{
  "exp": 1738700000,
  "iat": 1738696400,
  "sub": "user-uuid-here",
  "preferred_username": "dave_manager",
  "email": "dave@agency-alpha.gov",
  "given_name": "Dave",
  "family_name": "Manager",
  
  // ═══════════════════════════════════════════════════════════════
  // CUSTOM SECURITY CLAIMS (configured in Keycloak)
  // ═══════════════════════════════════════════════════════════════
  "clearance_level": "SECRET",
  "organization": "Agency Alpha",
  "compartments": ["PROJECT_ALPHA", "OPERATION_DELTA"],
  "realm_access": {
    "roles": ["manager", "analyst", "default-roles-agency-alpha"]
  }
}
```

### 2.2 JWT Validation Process

```python
# Step 1: Extract token from Authorization header
# Header: "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..."

async def get_current_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        return None  # No token = anonymous/demo user
    
    token = authorization.split(" ")[1]
    
    # Step 2: Fetch Keycloak's public keys (JWKS)
    jwks = await fetch_jwks()  # Cached for 5 minutes
    # URL: http://keycloak:8080/realms/agency-alpha/protocol/openid-connect/certs
    
    # Step 3: Extract key ID from token header
    header = jwt.get_unverified_header(token)
    kid = header.get("kid")
    
    # Step 4: Find matching public key
    key_data = jwks.get(kid)
    public_key = jwk.construct(key_data)
    
    # Step 5: Verify signature and decode claims
    payload = jwt.decode(
        token,
        public_key.to_pem().decode("utf-8"),
        algorithms=["RS256"],
        audience="account"  # Or your client ID
    )
    
    # Step 6: Extract user attributes
    return AuthenticatedUser(
        username=payload.get("preferred_username"),
        clearance_level=payload.get("clearance_level", "UNCLASSIFIED"),
        organization=payload.get("organization", "agency-alpha"),
        compartments=payload.get("compartments", []),
        roles=extract_roles(payload)
    )
```

### 2.3 JWKS Caching

To avoid fetching public keys on every request:

```python
_jwks_cache = {"keys": {}, "fetched_at": 0}
JWKS_CACHE_TTL = 300  # 5 minutes

async def fetch_jwks():
    now = time.time()
    if _jwks_cache["keys"] and (now - _jwks_cache["fetched_at"]) < JWKS_CACHE_TTL:
        return _jwks_cache["keys"]  # Return cached keys
    
    # Fetch fresh keys from Keycloak
    jwks_url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/certs"
    response = await httpx.get(jwks_url)
    jwks_data = response.json()
    
    # Cache by key ID for fast lookup
    _jwks_cache["keys"] = {k["kid"]: k for k in jwks_data["keys"]}
    _jwks_cache["fetched_at"] = now
    
    return _jwks_cache["keys"]
```

---

## 3. Security Modes

The application implements three progressively restrictive security modes:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SECURITY MODE COMPARISON                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   MODE 1: RBAC                                                              │
│   ═══════════════════════════════════════════════════════════════════════   │
│   Filters:  Classification + Organization                                   │
│   Logic:    user.clearance >= doc.classification                            │
│             AND (doc.org == user.org OR doc.shared_with contains user.org)  │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  User: SECRET clearance, agency-alpha                               │   │
│   │  Sees: All UNCLASSIFIED, CONFIDENTIAL, SECRET docs from alpha       │   │
│   │        + docs shared with alpha or "all"                            │   │
│   │  Hidden: TOP_SECRET docs, agency-bravo exclusive docs               │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│   MODE 2: CELL-LEVEL                                                        │
│   ═══════════════════════════════════════════════════════════════════════   │
│   Filters:  RBAC + Cell Membership + Field Masking                          │
│   Logic:    (RBAC filters)                                                  │
│             AND (doc.cell_access contains "all" OR                          │
│                  doc.cell_access intersects user.cells)                     │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  User: SECRET, agency-alpha, cells=[cell-hq, cell-west]             │   │
│   │  Sees: RBAC-allowed docs WHERE cell_access includes hq/west/all     │   │
│   │  Masked: source_name, handler_id, raw_intel (if cell mismatch)      │   │
│   │  Hidden: Docs requiring cell-east or cell-cyber only                │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
│   MODE 3: NEED-TO-KNOW (NTK)                                                │
│   ═══════════════════════════════════════════════════════════════════════   │
│   Filters:  Cell-Level + Explicit User/Compartment Authorization            │
│   Logic:    (Cell filters)                                                  │
│             AND (doc.ntk_required == false                                  │
│                  OR user.username IN doc.ntk_users                          │
│                  OR user.compartments intersects doc.ntk_compartments)      │
│                                                                             │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │  User: SECRET, agency-alpha, cells=[hq,west], comps=[ALPHA,DELTA]   │   │
│   │  Sees: Cell-allowed docs WHERE:                                     │   │
│   │        - ntk_required=false, OR                                     │   │
│   │        - username is in ntk_users list, OR                          │   │
│   │        - user has matching compartment                              │   │
│   │  Hidden: NTK docs where user not whitelisted & no compartment match │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. OpenSearch Query Construction

### 4.1 RBAC Query

```python
def build_rbac_query(search_text: str, user: dict) -> dict:
    """
    RBAC = Classification clearance + Organization membership
    """
    # Get classifications user can access
    allowed_classifications = get_allowed_classifications(user["clearance"])
    # e.g., SECRET user gets ["UNCLASSIFIED", "CONFIDENTIAL", "SECRET"]
    
    return {
        "query": {
            "bool": {
                "must": [
                    # Text search (or match_all if empty)
                    text_query(search_text)
                ],
                "filter": [
                    # FILTER 1: Classification must be at or below user's level
                    {
                        "terms": {
                            "classification": allowed_classifications
                        }
                    },
                    # FILTER 2: Organization check
                    {
                        "bool": {
                            "should": [
                                # Document belongs to user's org
                                {"term": {"organization": user["organization"]}},
                                # Document is shared with user's org
                                {"term": {"shared_with": user["organization"]}},
                                # Document is shared with everyone
                                {"term": {"shared_with": "all"}}
                            ],
                            "minimum_should_match": 1
                        }
                    }
                ]
            }
        },
        "size": 100
    }
```

**Example Generated Query for `bob_analyst` (SECRET, agency-alpha):**

```json
{
  "query": {
    "bool": {
      "must": [{ "match_all": {} }],
      "filter": [
        {
          "terms": {
            "classification": ["UNCLASSIFIED", "CONFIDENTIAL", "SECRET"]
          }
        },
        {
          "bool": {
            "should": [
              { "term": { "organization": "agency-alpha" } },
              { "term": { "shared_with": "agency-alpha" } },
              { "term": { "shared_with": "all" } }
            ],
            "minimum_should_match": 1
          }
        }
      ]
    }
  }
}
```

### 4.2 Cell-Level Query

```python
def build_cell_query(search_text: str, user: dict) -> dict:
    """
    Cell-Level = RBAC + Cell membership check
    """
    allowed_classifications = get_allowed_classifications(user["clearance"])
    user_cells = user.get("cell_memberships", [])
    
    return {
        "query": {
            "bool": {
                "must": [text_query(search_text)],
                "filter": [
                    # FILTER 1: Classification (same as RBAC)
                    {"terms": {"classification": allowed_classifications}},
                    
                    # FILTER 2: Organization (same as RBAC)
                    {
                        "bool": {
                            "should": [
                                {"term": {"organization": user["organization"]}},
                                {"term": {"shared_with": user["organization"]}},
                                {"term": {"shared_with": "all"}}
                            ],
                            "minimum_should_match": 1
                        }
                    },
                    
                    # FILTER 3: Cell access
                    {
                        "bool": {
                            "should": [
                                # Document allows all cells
                                {"term": {"cell_access": "all"}},
                                # User has at least one matching cell
                                {"terms": {"cell_access": user_cells}}
                            ],
                            "minimum_should_match": 1
                        }
                    }
                ]
            }
        }
    }
```

**Example Generated Query for `dave_manager` (cells: hq, west, east):**

```json
{
  "query": {
    "bool": {
      "filter": [
        { "terms": { "classification": ["UNCLASSIFIED", "CONFIDENTIAL", "SECRET"] } },
        {
          "bool": {
            "should": [
              { "term": { "organization": "agency-alpha" } },
              { "term": { "shared_with": "agency-alpha" } },
              { "term": { "shared_with": "all" } }
            ]
          }
        },
        {
          "bool": {
            "should": [
              { "term": { "cell_access": "all" } },
              { "terms": { "cell_access": ["cell-hq", "cell-west", "cell-east"] } }
            ]
          }
        }
      ]
    }
  }
}
```

### 4.3 Need-to-Know (NTK) Query

```python
def build_ntk_query(search_text: str, user: dict) -> dict:
    """
    NTK = Cell-Level + Explicit user authorization OR compartment match
    """
    allowed_classifications = get_allowed_classifications(user["clearance"])
    user_cells = user.get("cell_memberships", [])
    user_compartments = user.get("compartments", [])
    username = user["username"]
    
    return {
        "query": {
            "bool": {
                "must": [text_query(search_text)],
                "filter": [
                    # FILTER 1: Classification
                    {"terms": {"classification": allowed_classifications}},
                    
                    # FILTER 2: Organization
                    {"bool": {"should": [
                        {"term": {"organization": user["organization"]}},
                        {"term": {"shared_with": user["organization"]}},
                        {"term": {"shared_with": "all"}}
                    ], "minimum_should_match": 1}},
                    
                    # FILTER 3: Cell access
                    {"bool": {"should": [
                        {"term": {"cell_access": "all"}},
                        {"terms": {"cell_access": user_cells}}
                    ], "minimum_should_match": 1}},
                    
                    # FILTER 4: NTK check
                    {
                        "bool": {
                            "should": [
                                # Option A: NTK not required
                                {"term": {"ntk_required": False}},
                                
                                # Option B: User explicitly whitelisted
                                {"term": {"ntk_users": username}},
                                
                                # Option C: User has required compartment
                                {"terms": {"ntk_compartments": user_compartments}}
                            ],
                            "minimum_should_match": 1
                        }
                    }
                ]
            }
        }
    }
```

**Example Generated Query for `bob_analyst` (compartments: ALPHA, OMEGA):**

```json
{
  "query": {
    "bool": {
      "filter": [
        { "terms": { "classification": ["UNCLASSIFIED", "CONFIDENTIAL", "SECRET"] } },
        { "bool": { "should": [/* org filters */] } },
        { "bool": { "should": [/* cell filters */] } },
        {
          "bool": {
            "should": [
              { "term": { "ntk_required": false } },
              { "term": { "ntk_users": "bob_analyst" } },
              { "terms": { "ntk_compartments": ["PROJECT_ALPHA", "PROJECT_OMEGA"] } }
            ],
            "minimum_should_match": 1
          }
        }
      ]
    }
  }
}
```

---

## 5. Field-Level Masking

After query execution, sensitive fields are masked for documents where the user lacks full access:

### 5.1 Masking Logic

```python
SENSITIVE_FIELDS = ["source_name", "handler_id", "raw_intel"]

def apply_field_masking(hits: list, user: dict, mode: str):
    """
    Mask sensitive fields based on cell membership and NTK status.
    """
    user_cells = set(user.get("cell_memberships", []))
    user_compartments = set(user.get("compartments", []))
    username = user["username"]
    
    for hit in hits:
        doc = hit["_source"]
        doc_cells = set(doc.get("cell_access", []))
        
        # Check cell access
        has_cell_access = "all" in doc_cells or bool(user_cells & doc_cells)
        
        # Check NTK access (only in NTK mode)
        has_ntk_access = True
        if mode == "ntk" and doc.get("ntk_required"):
            ntk_users = set(doc.get("ntk_users", []))
            ntk_compartments = set(doc.get("ntk_compartments", []))
            has_ntk_access = (
                username in ntk_users or
                bool(user_compartments & ntk_compartments)
            )
        
        # Apply masking
        if not has_cell_access:
            for field in SENSITIVE_FIELDS:
                if doc.get(field):
                    doc[field] = "██ CELL RESTRICTED ██"
        elif not has_ntk_access:
            for field in SENSITIVE_FIELDS:
                if doc.get(field):
                    doc[field] = "██ NTK RESTRICTED ██"
```

### 5.2 Masking Examples

**Document:** "Operation DELTA FORCE — Execution Orders"
- `cell_access`: ["cell-hq", "cell-west"]
- `ntk_required`: true
- `ntk_users`: ["alice_admin", "dave_manager"]
- `ntk_compartments`: ["OPERATION_DELTA"]

| User | Cells | Compartments | Cell Access? | NTK Access? | Field Display |
|------|-------|--------------|--------------|-------------|---------------|
| alice_admin | all | all | ✓ | ✓ (whitelisted) | Full visibility |
| dave_manager | hq, west, east | ALPHA, DELTA | ✓ | ✓ (whitelisted + compartment) | Full visibility |
| bob_analyst | hq, east, cyber | ALPHA, OMEGA | ✓ (hq) | ✗ (not listed, no DELTA) | `██ NTK RESTRICTED ██` |
| frank_bravo | west | ALPHA | ✓ (west) | ✗ (not listed, no DELTA) | `██ NTK RESTRICTED ██` |
| carol_viewer | hq, east | ALPHA | ✓ (hq) | ✗ | `██ NTK RESTRICTED ██` |

---

## 6. Configuration Reference

### 6.1 Environment Variables

```bash
# OpenSearch Connection
OPENSEARCH_HOST=opensearch
OPENSEARCH_PORT=9200
INDEX_NAME=secure-documents

# Keycloak Configuration
KEYCLOAK_URL=http://keycloak:8080
KEYCLOAK_REALM=agency-alpha
KEYCLOAK_CLIENT_ID=frontend-app
```

### 6.2 Keycloak Realm Configuration

Custom user attributes must be configured in Keycloak:

```json
{
  "realm": "agency-alpha",
  "users": [
    {
      "username": "dave_manager",
      "enabled": true,
      "attributes": {
        "clearance_level": ["SECRET"],
        "organization": ["Agency Alpha"],
        "compartments": ["PROJECT_ALPHA", "OPERATION_DELTA"]
      },
      "realmRoles": ["manager", "analyst"]
    }
  ],
  "clients": [
    {
      "clientId": "frontend-app",
      "publicClient": true,
      "redirectUris": ["http://localhost:8002/*"],
      "webOrigins": ["*"],
      "protocolMappers": [
        {
          "name": "clearance_level",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-usermodel-attribute-mapper",
          "config": {
            "user.attribute": "clearance_level",
            "claim.name": "clearance_level",
            "id.token.claim": "true",
            "access.token.claim": "true"
          }
        },
        {
          "name": "compartments",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-usermodel-attribute-mapper",
          "config": {
            "user.attribute": "compartments",
            "claim.name": "compartments",
            "multivalued": "true",
            "id.token.claim": "true",
            "access.token.claim": "true"
          }
        }
      ]
    }
  ]
}
```

### 6.3 Classification Level Mapping

```python
CLASSIFICATION_LEVELS = {
    "UNCLASSIFIED": 1,
    "CONFIDENTIAL": 2,
    "SECRET": 3,
    "TOP_SECRET": 4
}

def get_allowed_classifications(user_clearance: str) -> list:
    """Return all classifications at or below user's level."""
    user_level = CLASSIFICATION_LEVELS.get(user_clearance, 1)
    return [
        classification 
        for classification, level in CLASSIFICATION_LEVELS.items()
        if level <= user_level
    ]
```

### 6.4 Compartment-to-Cell Mapping

```python
COMPARTMENT_CELL_MAP = {
    "PROJECT_ALPHA": ["cell-hq", "cell-east"],
    "PROJECT_OMEGA": ["cell-hq", "cell-cyber"],
    "OPERATION_DELTA": ["cell-west", "cell-hq"],
}

def compartments_to_cells(compartments: list, is_admin: bool) -> list:
    """Map compartments to cell memberships."""
    if is_admin:
        return ["cell-hq", "cell-east", "cell-west", "cell-cyber"]
    
    cells = set()
    for comp in compartments:
        cells.update(COMPARTMENT_CELL_MAP.get(comp, []))
    return list(cells)
```

---

## 7. User Access Matrix

### 7.1 Test Users

| Username | Clearance | Organization | Cells | Compartments |
|----------|-----------|--------------|-------|--------------|
| alice_admin | TOP_SECRET | agency-alpha | all | ALPHA, OMEGA, DELTA |
| bob_analyst | SECRET | agency-alpha | hq, east, cyber | ALPHA, OMEGA |
| carol_viewer | CONFIDENTIAL | agency-alpha | hq, east | ALPHA |
| dave_manager | SECRET | agency-alpha | hq, west, east | ALPHA, DELTA |
| eve_auditor | TOP_SECRET | agency-alpha | all | ALPHA, OMEGA, DELTA |
| frank_bravo | SECRET | agency-bravo | west | ALPHA |
| grace_bravo | CONFIDENTIAL | agency-bravo | (none) | (none) |

### 7.2 Expected Document Access (66 Total Documents)

| User | RBAC Mode | Cell-Level Mode | NTK Mode |
|------|-----------|-----------------|----------|
| alice_admin | 66 | 66 | 66 |
| bob_analyst | 49 | 38 | 28 |
| carol_viewer | 27 | 18 | 10 |
| dave_manager | 49 | 42 | 34 |
| eve_auditor | 66 | 66 | 52 |
| frank_bravo | 15 | 8 | 6 |
| grace_bravo | 10 | 3 | 2 |

### 7.3 NTK Document Access Examples

| Document | alice | bob | carol | dave | eve | frank | grace |
|----------|-------|-----|-------|------|-----|-------|-------|
| Carol's Performance Review | ✓ | ✗ | ✓ | ✓ | ✗ | ✗ | ✗ |
| Bob's Training Assignment | ✓ | ✓ | ✗ | ✓ | ✗ | ✗ | ✗ |
| Dave's Management Plan | ✓ | ✗ | ✗ | ✓ | ✓ | ✗ | ✗ |
| Frank's Access Request | ✓ | ✗ | ✗ | ✓ | ✗ | ✓ | ✗ |
| Grace's Clearance Upgrade | ✓ | ✗ | ✗ | ✗ | ✓ | ✗ | ✓ |
| Director's Daily Brief | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| DELTA FORCE Execution Orders | ✓ | ✗ | ✗ | ✓ | ✗ | ✗ | ✗ |
| Operation ALPHA STRIKE | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |

**Access Logic:**
- ✓ = User in `ntk_users` list OR user has matching compartment in `ntk_compartments`
- ✗ = Neither condition met

---

## 8. API Endpoints

### 8.1 Search Endpoint

```
POST /api/search
Authorization: Bearer <JWT>
Content-Type: application/json

{
  "query": "operation delta",
  "mode": "ntk",           // "rbac" | "cell" | "ntk"
  "user_id": "bob_analyst" // Only for demo mode (no JWT)
}
```

**Response:**
```json
{
  "mode": "ntk",
  "user": { /* user profile */ },
  "query_text": "operation delta",
  "filter_explanation": "Classification ≤ SECRET • Organisation = agency-alpha • Cells = cell-hq, cell-east, cell-cyber • Compartments = PROJECT_ALPHA, PROJECT_OMEGA • NTK check: user in ntk_users OR matching compartment",
  "total_in_index": 66,
  "visible_count": 8,
  "hidden_count": 58,
  "documents": [ /* filtered results */ ]
}
```

### 8.2 Compare Endpoint

```
POST /api/compare
Authorization: Bearer <JWT>

{
  "query": "budget",
  "user_id": null
}
```

**Response:**
```json
{
  "total_in_index": 66,
  "rbac": { "visible": 12, "documents": [...] },
  "cell": { "visible": 8, "documents": [...] },
  "ntk": { "visible": 5, "documents": [...] }
}
```

---

## 9. Security Considerations

### 9.1 Defense in Depth

This implementation uses **application-layer filtering**, not OpenSearch's native security features. This means:

1. **All queries go through the application** — Direct OpenSearch access must be blocked
2. **JWT validation is critical** — Invalid tokens must be rejected
3. **Query construction must be bulletproof** — No SQL/query injection possible

### 9.2 What This Does NOT Protect Against

- Direct OpenSearch API access (use network isolation)
- Compromised application server
- JWT key compromise
- Malicious administrators with database access

### 9.3 Recommendations for Production

1. **Enable OpenSearch Security Plugin** — Add authentication at the database layer
2. **Use HTTPS everywhere** — Encrypt JWT tokens in transit
3. **Implement audit logging** — Track who accessed what
4. **Add rate limiting** — Prevent enumeration attacks
5. **Use short-lived tokens** — Reduce window of compromise

---

## Appendix A: Complete Query Flow Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           COMPLETE QUERY FLOW                                 │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. USER REQUEST                                                             │
│  ════════════════════════════════════════════════════════════════════════    │
│  POST /api/search                                                            │
│  Authorization: Bearer eyJhbGciOiJSUzI1NiIs...                               │
│  {"query": "budget", "mode": "ntk"}                                          │
│                                                                              │
│                              │                                               │
│                              ▼                                               │
│                                                                              │
│  2. JWT VALIDATION                                                           │
│  ════════════════════════════════════════════════════════════════════════    │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │ async def get_current_user(authorization):                             │  │
│  │     token = extract_bearer_token(authorization)                        │  │
│  │     jwks = await fetch_jwks()  # Cached                                │  │
│  │     public_key = jwks[token.header.kid]                                │  │
│  │     payload = jwt.decode(token, public_key, algorithms=["RS256"])      │  │
│  │     return AuthenticatedUser(                                          │  │
│  │         username=payload["preferred_username"],                        │  │
│  │         clearance_level=payload["clearance_level"],                    │  │
│  │         organization=payload["organization"],                          │  │
│  │         compartments=payload["compartments"],                          │  │
│  │         roles=payload["realm_access"]["roles"]                         │  │
│  │     )                                                                  │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│                              │                                               │
│                              ▼                                               │
│                                                                              │
│  3. USER PROFILE LOOKUP                                                      │
│  ════════════════════════════════════════════════════════════════════════    │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │ user = {                                                               │  │
│  │     "username": "dave_manager",                                        │  │
│  │     "clearance": "SECRET",                                             │  │
│  │     "organization": "agency-alpha",                                    │  │
│  │     "cell_memberships": ["cell-hq", "cell-west", "cell-east"],         │  │
│  │     "compartments": ["PROJECT_ALPHA", "OPERATION_DELTA"]               │  │
│  │ }                                                                      │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│                              │                                               │
│                              ▼                                               │
│                                                                              │
│  4. QUERY CONSTRUCTION (NTK MODE)                                            │
│  ════════════════════════════════════════════════════════════════════════    │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │ {                                                                      │  │
│  │   "query": {                                                           │  │
│  │     "bool": {                                                          │  │
│  │       "must": [{"multi_match": {"query": "budget", ...}}],             │  │
│  │       "filter": [                                                      │  │
│  │         {"terms": {"classification": ["UNCLASSIFIED","CONFIDENTIAL",   │  │
│  │                                        "SECRET"]}},                    │  │
│  │         {"bool": {"should": [                                          │  │
│  │           {"term": {"organization": "agency-alpha"}},                  │  │
│  │           {"term": {"shared_with": "agency-alpha"}},                   │  │
│  │           {"term": {"shared_with": "all"}}                             │  │
│  │         ]}},                                                           │  │
│  │         {"bool": {"should": [                                          │  │
│  │           {"term": {"cell_access": "all"}},                            │  │
│  │           {"terms": {"cell_access": ["cell-hq","cell-west","cell-east"]}}│ │
│  │         ]}},                                                           │  │
│  │         {"bool": {"should": [                                          │  │
│  │           {"term": {"ntk_required": false}},                           │  │
│  │           {"term": {"ntk_users": "dave_manager"}},                     │  │
│  │           {"terms": {"ntk_compartments": ["PROJECT_ALPHA",             │  │
│  │                                           "OPERATION_DELTA"]}}         │  │
│  │         ]}}                                                            │  │
│  │       ]                                                                │  │
│  │     }                                                                  │  │
│  │   }                                                                    │  │
│  │ }                                                                      │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│                              │                                               │
│                              ▼                                               │
│                                                                              │
│  5. OPENSEARCH EXECUTION                                                     │
│  ════════════════════════════════════════════════════════════════════════    │
│  os_client.search(index="secure-documents", body=query)                      │
│                                                                              │
│                              │                                               │
│                              ▼                                               │
│                                                                              │
│  6. FIELD MASKING                                                            │
│  ════════════════════════════════════════════════════════════════════════    │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │ for doc in results:                                                    │  │
│  │     if not has_cell_access(user, doc):                                 │  │
│  │         doc.source_name = "██ CELL RESTRICTED ██"                      │  │
│  │         doc.handler_id = "██ CELL RESTRICTED ██"                       │  │
│  │         doc.raw_intel = "██ CELL RESTRICTED ██"                        │  │
│  │     elif not has_ntk_access(user, doc):                                │  │
│  │         doc.source_name = "██ NTK RESTRICTED ██"                       │  │
│  │         doc.handler_id = "██ NTK RESTRICTED ██"                        │  │
│  │         doc.raw_intel = "██ NTK RESTRICTED ██"                         │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│                              │                                               │
│                              ▼                                               │
│                                                                              │
│  7. RESPONSE                                                                 │
│  ════════════════════════════════════════════════════════════════════════    │
│  {                                                                           │
│    "mode": "ntk",                                                            │
│    "total_in_index": 66,                                                     │
│    "visible_count": 5,                                                       │
│    "documents": [/* filtered & masked results */]                            │
│  }                                                                           │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Appendix B: Glossary

| Term | Definition |
|------|------------|
| **RBAC** | Role-Based Access Control — filtering by classification level and organization |
| **Cell** | A compartmentalized organizational unit (e.g., cell-hq, cell-west) |
| **Compartment** | A project or program with restricted access (e.g., PROJECT_ALPHA) |
| **NTK** | Need-to-Know — explicit authorization required beyond clearance level |
| **JWT** | JSON Web Token — signed token containing user claims |
| **JWKS** | JSON Web Key Set — public keys used to verify JWT signatures |
| **Field Masking** | Hiding sensitive fields from users who lack full access |
| **Clearance** | Security level (UNCLASSIFIED → CONFIDENTIAL → SECRET → TOP_SECRET) |

---
# OpenSearch + Keycloak + NTK Security Integration

## Overview
Updated the search app to integrate with Keycloak authentication and implement three security enforcement levels: RBAC, Cell-Level, and Need-to-Know (NTK).

## Security Modes

### 1. RBAC Mode
- Filters by classification level (UNCLASSIFIED → CONFIDENTIAL → SECRET → TOP_SECRET)
- Filters by organization membership

### 2. Cell-Level Mode
- RBAC + compartmented cell membership checks
- Field-level masking for sensitive fields (source_name, handler_id, raw_intel)
- Cells: cell-hq, cell-east, cell-west, cell-cyber

### 3. NTK Mode (Need-to-Know)
- Cell-Level + explicit user access control
- Documents can require NTK access via:
  - Explicit username whitelist (`ntk_users`)
  - Compartment membership (`ntk_compartments`)

## Keycloak Users

| User | Clearance | Compartments | Cells | NTK Access |
|------|-----------|--------------|-------|------------|
| alice_admin | TOP_SECRET | All | All | Full access (admin) |
| bob_analyst | SECRET | PROJECT_ALPHA, PROJECT_OMEGA | HQ, East, Cyber | Source Protection Report |
| carol_viewer | CONFIDENTIAL | PROJECT_ALPHA | HQ, East | Limited |
| dave_manager | SECRET | PROJECT_ALPHA, OPERATION_DELTA | HQ, West, East | DELTA FORCE, Budget |
| eve_auditor | TOP_SECRET | All | All | Strategic docs, Budget |
| frank_bravo | SECRET | PROJECT_ALPHA | West | CROSSWIND operation |
| grace_bravo | CONFIDENTIAL | None | None | Minimal |

## Demo Documents (18 total)

### By Classification
- 4 UNCLASSIFIED (public access)
- 5 CONFIDENTIAL (compartment-restricted)
- 4 SECRET (2 with NTK restrictions)
- 5 TOP_SECRET (all NTK-restricted)

### NTK-Restricted Documents
1. **Operation DELTA FORCE** - alice_admin, dave_manager + OPERATION_DELTA compartment
2. **Source Protection Report — CARDINAL** - alice_admin, bob_analyst only
3. **Budget Allocation — Black Programs FY26** - alice_admin, dave_manager, eve_auditor
4. **Bravo Special Operations Brief — CROSSWIND** - Cross-agency (alice_admin, dave_manager, frank_bravo)
5. **Strategic Intelligence Estimate** - alice_admin, eve_auditor + PROJECT_OMEGA
6. **Covert Action Authorization — NIGHTFALL** - alice_admin only
7. **Technical Collection Capabilities** - alice_admin, bob_analyst, eve_auditor + PROJECT_OMEGA/ALPHA

## Files Modified

### search-app/main.py
- Added Keycloak JWT validation with JWKS caching
- User profile mapping from Keycloak tokens
- NTK query builder and field masking
- 18 seed documents with NTK restrictions

### search-app/static/index.html
- Keycloak-js integration with SSO
- Login/logout functionality
- Four security mode tabs (RBAC, Cell, NTK, Compare)
- NTK status indicators and purple styling

### search-app/requirements.txt
- Added python-jose[cryptography] for JWT validation
- Added httpx for async HTTP requests

### docker-compose.yml
- Added Keycloak environment variables for search-app

### frontend/index.html
- Added "OpenSearch + NTK" tab linking to search-app (port 8002)

## Running the Application

```bash
docker-compose up --build
```

### Access Points
- Main Frontend: http://localhost:3000
- Search App: http://localhost:8002
- Keycloak Alpha: http://localhost:8080
- Keycloak Bravo: http://localhost:8081
- OpenSearch Dashboards: http://localhost:5601

### Test Credentials
All users have password: `password123`

## SSO Flow
1. User logs in via main frontend (Keycloak)
2. Click "OpenSearch + NTK" tab → opens search-app
3. Search app detects existing Keycloak session via silent SSO
4. User authenticated with same token/profile
## Federated OIDC/OAuth2 with Classification Access & Need-to-Know Controls

# 🔐 RBAC + Cell-Level Security — Complete Architecture & Tutorial Guide

**Federated OIDC Authentication | Classification Access | Need-to-Know Controls**
**Docker Compose | Keycloak 26 | FastAPI | React | PostgreSQL**

*Version 1.0 — February 2026*

---

## Table of Contents

1. [Executive Summary & Key Components](#1-executive-summary--key-components)
2. [What is RBAC?](#2-what-is-rbac)
3. [What is Cell-Level Security?](#3-what-is-cell-level-security)
4. [System Architecture Overview](#4-system-architecture-overview)
5. [Docker Compose Services](#5-docker-compose-services)
6. [Network & Communication Flow](#6-network--communication-flow)
7. [PostgreSQL Database Schema](#7-postgresql-database-schema)
8. [Keycloak Identity Provider](#8-keycloak-identity-provider)
9. [Backend API (FastAPI)](#9-backend-api-fastapi)
10. [Security Engine — Line by Line](#10-security-engine--line-by-line)
11. [Frontend (React SPA)](#11-frontend-react-spa)
12. [Audit Logging System](#12-audit-logging-system)
13. [Demo Users & Access Matrix](#13-demo-users--access-matrix)
14. [Complete Dependency Reference](#14-complete-dependency-reference)
15. [Troubleshooting Guide](#15-troubleshooting-guide)

---

## 1. Executive Summary & Key Components

This project demonstrates a production-grade, multi-layered data security system. It shows how organizations can protect sensitive information using classification levels, role-based access, need-to-know compartments, and full audit trails — all running in Docker containers you can start with a single command.

> **WHO IS THIS FOR?**
> Software engineers, security architects, DevOps professionals, students, and anyone who wants to understand how classified data access works in modern web applications. No prior security experience required.

### Key Components at a Glance

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Identity Provider (Primary)** | Keycloak 26 | Manages users, passwords, roles, and security attributes for Agency Alpha. Issues JWT tokens containing clearance levels and compartments. |
| **Identity Provider (Federated)** | Keycloak 26 | Separate Keycloak instance for Agency Bravo. Federated with Alpha via OIDC so Bravo users can access Alpha's system. |
| **Backend API** | FastAPI (Python) | Validates JWT tokens, enforces RBAC, applies cell-level security, logs all access attempts to the audit trail. |
| **Frontend SPA** | React 18 | Single-page application that authenticates with Keycloak, displays data with real-time redaction visualization. |
| **Application Database** | PostgreSQL 16 | Stores records, cells, users, need-to-know approvals, and the complete audit log. |
| **Keycloak Databases (x2)** | PostgreSQL 16 | Dedicated databases for each Keycloak instance to store their internal configuration. |
| **Setup Container** | Python | One-shot container that configures federation between Keycloak instances and seeds demo data. |
| **Reverse Proxy** | Nginx | Serves the frontend SPA and proxies `/api/` requests to the backend, providing a unified access point on port 3000. |

### The Four Security Layers

| # | Layer | What It Does |
|---|-------|-------------|
| 1 | **RBAC (Role-Based Access)** | Users have roles (viewer, analyst, manager, admin, auditor). Each API endpoint checks if the user's role permits the action. For example, only managers can delete records. |
| 2 | **Record-Level Classification** | Each record (document) has an overall classification: UNCLASSIFIED, CONFIDENTIAL, SECRET, or TOP SECRET. If a user's clearance is below the record's classification, the entire record is invisible. |
| 3 | **Cell-Level Classification** | Within a visible record, each individual field (cell) has its own classification. Fields above the user's clearance show `[REDACTED]`. |
| 4 | **Need-to-Know Compartments** | Even with sufficient clearance, a cell may require specific compartment access (e.g., `PROJECT_ALPHA`). Missing any required compartment results in `[REDACTED]` with a specific denial reason. |

---

## 2. What is RBAC?

RBAC stands for **Role-Based Access Control**. Instead of assigning permissions directly to each user, you assign users to **ROLES**, and roles have **PERMISSIONS**. This makes access management scalable — instead of configuring 1,000 users individually, you configure 5 roles and assign users to them.

> **REAL-WORLD ANALOGY**
> Think of a hospital. A doctor, nurse, and receptionist all work in the same building, but they have different access. The doctor can prescribe medications. The nurse can administer them. The receptionist can schedule appointments. Their ROLE determines what they can do, not their individual identity.

### Roles in This System

| Permission | viewer | analyst | manager | admin | auditor |
|-----------|--------|---------|---------|-------|---------|
| Read Records | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes |
| Create Records | ❌ No | ✅ Yes | ✅ Yes | ✅ Yes | ❌ No |
| Update Records | ❌ No | ✅ Yes | ✅ Yes | ✅ Yes | ❌ No |
| Delete Records | ❌ No | ❌ No | ✅ Yes | ✅ Yes | ❌ No |
| Admin Panel | ❌ No | ❌ No | ✅ Yes | ✅ Yes | ❌ No |
| Audit Logs | ❌ No | ❌ No | ❌ No | ✅ Yes | ✅ Yes |
| Grant NTK Access | ❌ No | ❌ No | ✅ Yes | ✅ Yes | ❌ No |

### How RBAC is Implemented

Roles are stored in Keycloak as realm-level roles. When a user logs in, their JWT token contains a `realm_access.roles` claim listing all their assigned roles. The backend reads this claim and uses a `require_role()` dependency to enforce access.

**Backend enforcement (`auth.py`, lines 165-176):** The `require_role()` function is a FastAPI dependency factory. You call it with the roles you want to allow, and it returns a dependency function that checks the current user's roles. Admin users always bypass role checks.

```python
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
```

---

## 3. What is Cell-Level Security?

Traditional access control is binary: you either see a document or you don't. Cell-level security is more granular. Even within a document you're allowed to see, individual **FIELDS** can be restricted. This mirrors how classified documents work in government — a report might be overall SECRET, but certain paragraphs within it are TOP SECRET.

> **REAL-WORLD EXAMPLE**
> An intelligence brief about a weather operation is classified CONFIDENTIAL overall. The **mission name** field is UNCLASSIFIED (anyone can see it). The **personnel involved** field is SECRET with a PROJECT_ALPHA compartment (only people with SECRET clearance AND PROJECT_ALPHA access can see the names). The **technical methods** field is TOP SECRET with OPERATION_DELTA (only the highest cleared, need-to-know personnel can see how it was done).

### How It Works Step by Step

- **Step 1 — Record-level check:** The system first compares the user's clearance level against the record's overall classification. If the user's clearance is lower, the entire record is invisible. They don't even know it exists.
- **Step 2 — Cell-level classification check:** For each field in a visible record, the system compares the user's clearance against the field's classification. If insufficient, the field shows `[REDACTED]`.
- **Step 3 — Compartment check:** Even if the user has sufficient clearance, the field may require specific compartments. The user must have ALL required compartments. Missing any one results in `[REDACTED]` with a message like `NEED_TO_KNOW_REQUIRED: missing [OPERATION_DELTA]`.

### Classification Hierarchy

| Level | Rank | Description |
|-------|------|-------------|
| UNCLASSIFIED | 0 (lowest) | Public information. Anyone can see it regardless of clearance. |
| CONFIDENTIAL | 1 | Could cause damage if disclosed. Requires at least CONFIDENTIAL clearance. |
| SECRET | 2 | Could cause serious damage if disclosed. Requires at least SECRET clearance. |
| TOP_SECRET | 3 (highest) | Could cause exceptionally grave damage. Requires TOP SECRET clearance. |

**The rule is simple:** A user with clearance rank X can see any data at rank X or lower. TOP_SECRET (rank 3) can see everything. UNCLASSIFIED (rank 0) can only see UNCLASSIFIED data.

### Need-to-Know Compartments

Compartments add a second dimension beyond clearance levels. Having TOP SECRET clearance doesn't automatically give you access to everything at TOP SECRET — you also need to be "read in" to specific compartmented programs. This system uses three compartments:

| Compartment | Description |
|------------|-------------|
| `PROJECT_ALPHA` | Access to Alpha program data. Most common compartment, widely distributed. |
| `PROJECT_OMEGA` | Access to Omega program data. More restricted, given to analysts working on specific intelligence. |
| `OPERATION_DELTA` | Access to Delta operation data. Most restricted, given only to personnel directly involved in the operation. |

---

## 4. System Architecture Overview

The system consists of 8 Docker containers (7 long-running services + 1 setup container) communicating over a Docker bridge network.

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                      USER'S BROWSER                             │
│                                                                 │
│    ┌────────────────┐    ┌───────────────────────────────┐      │
│    │ React SPA      │    │  Keycloak JS Adapter (PKCE)   │      │
│    │  (:3000)       │    │  Redirects for login/logout   │      │
│    └───────┬────────┘    └─────────────┬─────────────────┘      │
└────────────┼───────────────────────────┼────────────────────────┘
             │ Bearer JWT                │ OIDC/PKCE
             │ (API calls)              │ (login redirect)
             ▼                           ▼
    ┌────────────────┐           ┌──────────────────┐
    │ Nginx + FastAPI │           │ Keycloak Alpha   │
    │  Backend API    │           │ (:8080)          │
    │  (:8000)        │───JWKS──▶│ Issues JWT tokens│
    └──────┬─────────┘           └───────┬──────────┘
           │                             │ OIDC Federation
           ▼                             ▼
    ┌────────────────┐           ┌──────────────────┐
    │ PostgreSQL App  │           │ Keycloak Bravo   │
    │  (:5433)        │           │ (:8081)          │
    └────────────────┘           └──────────────────┘
```

### Data Flow: What Happens When a User Clicks "Sign In"

- **Step 1 — Browser loads frontend:** User opens `http://localhost:3000`. Nginx serves the React SPA (`index.html`).
- **Step 2 — Keycloak JS adapter initializes:** The `keycloak-js` library (v24, UMD build) creates a Keycloak instance configured with URL `http://localhost:8080`, realm `agency-alpha`, and client `frontend-app`.
- **Step 3 — OIDC Authorization Code Flow with PKCE:** User clicks Sign In. The browser redirects to Keycloak's login page. After entering credentials, Keycloak validates them and redirects back to the SPA with an authorization code.
- **Step 4 — Token exchange:** The keycloak-js adapter exchanges the authorization code for an access token (JWT), a refresh token, and an ID token. The JWT contains the user's identity, roles, `clearance_level`, `compartments`, and `organization`.
- **Step 5 — API calls with Bearer token:** The SPA makes API calls to `/api/records`, `/api/auth/me`, etc. Each request includes an `Authorization: Bearer <JWT>` header.
- **Step 6 — Backend validates JWT:** FastAPI extracts the JWT, fetches Keycloak's JWKS (JSON Web Key Set) to get the public signing key, and verifies the token's signature, expiration, and claims.
- **Step 7 — Security engine applies access rules:** The backend checks RBAC (role), classification (clearance), and compartments (need-to-know). Records the user can't see are filtered out. Cells they can't see are replaced with `[REDACTED]`.
- **Step 8 — Audit log records everything:** Every access attempt — allowed or denied — is written to the `audit_log` table with full context (who, what, when, why denied).

---

## 5. Docker Compose Services

The entire system is defined in one `docker-compose.yml` file. Docker Compose reads this file and creates all containers, networks, and volumes. Here is every service explained:

### Service 1: `postgres-alpha`

- **Image:** `postgres:16-alpine` — Lightweight PostgreSQL 16 on Alpine Linux
- **Purpose:** Database for Keycloak Alpha. Stores Keycloak's internal data: users, realms, clients, roles, sessions.
- **Healthcheck:** `pg_isready -U keycloak` — Polls every 5 seconds to confirm PostgreSQL is accepting connections. Other services use `service_healthy` condition to wait for this.
- **Volume:** `pg_alpha_data` — Named Docker volume that persists data across container restarts.

### Service 2: `postgres-bravo`

- Identical to `postgres-alpha` but for Keycloak Bravo. Separate database ensures complete isolation between organizations.

### Service 3: `postgres-app`

- **Purpose:** The application database. Stores records, record cells, users (synced from Keycloak), need-to-know approvals, and the audit log.
- **Init script:** `database/init.sql` is mounted at `/docker-entrypoint-initdb.d/init.sql`. PostgreSQL automatically executes any `.sql` files in this directory on first startup, creating all tables, indexes, and helper functions.
- **External port:** `5433:5432` — Mapped to 5433 on the host so you can connect with tools like pgAdmin or psql.
- **Credentials:** User: `appuser`, Password: `apppass`, Database: `securedata`

### Service 4: `keycloak-alpha`

- **Image:** `quay.io/keycloak/keycloak:26.0`
- **Command:** `start-dev --import-realm` — Starts in development mode (HTTP, no TLS) and imports any realm JSON files found in `/opt/keycloak/data/import/`.
- **Realm file:** `agency-alpha-realm.json` defines the realm, clients (`frontend-app`, `backend-api`), custom roles (viewer, analyst, manager, admin, auditor), demo users with passwords, and custom client scopes for security attributes.
- **Health endpoint:** Keycloak 26 serves health on port 9000 (separate management port). The healthcheck uses bash's `/dev/tcp` to verify port 9000 is listening.

**Key environment variables:**

| Variable | Purpose |
|----------|---------|
| `KC_DB: postgres` | Tells Keycloak to use PostgreSQL instead of the built-in H2 database |
| `KC_DB_URL` | JDBC connection string pointing to the `postgres-alpha` container |
| `KEYCLOAK_ADMIN` / `PASSWORD` | Creates the master realm admin account (`admin`/`admin`) |
| `KC_HEALTH_ENABLED: "true"` | Enables the `/health` endpoints on port 9000 |
| `KC_HOSTNAME_STRICT: "false"` | Allows Keycloak to accept requests on any hostname (required for Docker) |

### Service 5: `keycloak-bravo`

- Identical structure to `keycloak-alpha` but represents a separate organization (Agency Bravo). Maps to external port 8081 (and 9001 for health). Uses its own database (`postgres-bravo`) and its own realm file (`agency-bravo-realm.json`) with different users.

### Service 6: `setup`

- **Purpose:** One-shot container that runs after both Keycloak instances are healthy. It:
  1. Configures OIDC federation between Alpha and Bravo by creating an Identity Provider in Alpha pointing to Bravo's endpoints.
  2. Creates IDP mappers to transfer `clearance_level`, `compartments`, and `organization` claims from Bravo tokens to Alpha.
  3. Seeds the application database with demo users (linked to Keycloak IDs), need-to-know approvals, and three demo records with varied cell classifications.
  4. Exits after completion (it's not a long-running service).

### Service 7: `backend`

- **Build:** Builds from `backend/Dockerfile`. Installs Python 3.12, pip dependencies, and runs uvicorn.
- **Healthcheck:** Hits `http://localhost:8000/health` using Python's `urllib`. Start period of 20 seconds allows time for the app to boot.

**Key environment variables:**

| Variable | Purpose |
|----------|---------|
| `DATABASE_URL` | Async connection string (`postgresql+asyncpg://`) for SQLAlchemy async engine |
| `KEYCLOAK_URL` | Internal Docker URL to Keycloak Alpha (`http://keycloak-alpha:8080`) |
| `KEYCLOAK_REALM` | Which realm to validate tokens against (`agency-alpha`) |
| `KEYCLOAK_CLIENT_ID` | The backend's client ID in Keycloak (`backend-api`) |
| `CORS_ORIGINS` | Allowed origins for CORS (`http://localhost:3000`) |

### Service 8: `frontend`

- **Build:** Builds from `frontend/Dockerfile`. Copies `index.html` into an Nginx container.
- **Nginx config:** Serves `/` requests as static files (the SPA). Proxies `/api/` requests to `http://backend:8000` (Docker internal DNS). Returns JSON error messages instead of HTML when backend is unreachable.
- **Port mapping:** `3000:80` — External port 3000 maps to Nginx's port 80 inside the container.

---

## 6. Network & Communication Flow

Docker Compose creates a default bridge network. All containers can reach each other by service name (Docker's built-in DNS). Here is every network connection:

### Internal Network (Docker-to-Docker)

| From | To | Protocol & Purpose |
|------|----|--------------------|
| `keycloak-alpha` | `postgres-alpha:5432` | PostgreSQL protocol. Keycloak stores its realm config, users, sessions. |
| `keycloak-bravo` | `postgres-bravo:5432` | PostgreSQL protocol. Same as above for the Bravo organization. |
| `backend` | `postgres-app:5432` | PostgreSQL (asyncpg). All CRUD operations and audit log writes. |
| `backend` | `keycloak-alpha:8080` | HTTP. Fetches JWKS (signing keys) to validate JWT tokens. |
| `frontend` (nginx) | `backend:8000` | HTTP. Proxies all `/api/*` requests from the browser to FastAPI. |
| `setup` | `keycloak-alpha:8080` | HTTP (Admin REST API). Creates Identity Provider, fetches user IDs. |
| `setup` | `keycloak-bravo:8080` | HTTP (Admin REST API). Fetches Bravo user IDs for federation config. |
| `setup` | `postgres-app:5432` | PostgreSQL. Seeds demo data directly into the application database. |
| `keycloak-alpha` | `keycloak-bravo:8080` | OIDC. During federated login, Alpha calls Bravo's token endpoint. |

### External Access (Host Machine)

| Host Port | Maps To | What You Access |
|-----------|---------|-----------------|
| `3000` | `frontend` (nginx:80) | The React SPA. Main entry point for users. |
| `8000` | `backend:8000` | FastAPI Swagger docs at `/docs`. Direct API access for testing. |
| `8080` | `keycloak-alpha:8080` | Keycloak Alpha admin console. Login: `admin`/`admin`. |
| `8081` | `keycloak-bravo:8080` | Keycloak Bravo admin console. Login: `admin`/`admin`. |
| `9000` | `keycloak-alpha:9000` | Keycloak Alpha health endpoint (`/health/ready`). |
| `9001` | `keycloak-bravo:9000` | Keycloak Bravo health endpoint. |
| `5433` | `postgres-app:5432` | Application database. Connect with psql or pgAdmin. |

### JWT Token Flow (Detailed)

**What is a JWT?** A JSON Web Token is a base64-encoded string with three parts separated by dots: `HEADER.PAYLOAD.SIGNATURE`. The header says what algorithm was used. The payload contains claims (user data). The signature proves the token wasn't tampered with.

**What claims does our JWT contain?**

| Claim | Description |
|-------|-------------|
| `sub` | Subject — the user's unique Keycloak ID (UUID) |
| `preferred_username` | The username (e.g., `alice_admin`) |
| `email` | User's email address |
| `realm_access.roles` | Array of assigned roles: `["admin", "auditor", "default-roles-agency-alpha"]` |
| `clearance_level` | Custom claim: the user's classification clearance (e.g., `TOP_SECRET`) |
| `compartments` | Custom claim: comma-separated compartments (e.g., `PROJECT_ALPHA,PROJECT_OMEGA`) |
| `organization` | Custom claim: which organization the user belongs to (e.g., `Agency Alpha`) |
| `exp` | Expiration timestamp — token is invalid after this time |
| `iss` | Issuer — the Keycloak realm URL that issued this token |

---

## 7. PostgreSQL Database Schema

**File:** `database/init.sql`

The application database has 5 tables, 2 helper functions, 1 view, and 11 indexes. Here is every table explained field by field:

### Table: `users`

Stores user records synced from Keycloak on first login. The setup container pre-populates this table.

| Column | Type | Purpose |
|--------|------|---------|
| `id` | UUID (PK) | Unique identifier, auto-generated |
| `keycloak_id` | VARCHAR(255) UNIQUE | Links to the user's Keycloak `sub` claim. Ensures 1:1 mapping. |
| `username` | VARCHAR(255) | Display name (e.g., `alice_admin`) |
| `email` | VARCHAR(255) | User's email from Keycloak |
| `organization` | VARCHAR(255) | Which agency: Agency Alpha or Agency Bravo |
| `clearance_level` | ENUM | `UNCLASSIFIED`, `CONFIDENTIAL`, `SECRET`, or `TOP_SECRET` |
| `approved_compartments` | TEXT[] | PostgreSQL array of approved compartments |
| `roles` | TEXT[] | Array of RBAC roles |
| `is_active` | BOOLEAN | Soft-disable without deleting the user |
| `last_login` | TIMESTAMP | Updated each time the user authenticates |
| `created_at` / `updated_at` | TIMESTAMP | Tracking timestamps |

```sql
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    keycloak_id     VARCHAR(255) UNIQUE NOT NULL,
    username        VARCHAR(255) NOT NULL,
    email           VARCHAR(255),
    full_name       VARCHAR(500),
    organization    VARCHAR(255) DEFAULT 'Unknown',
    clearance_level classification_level DEFAULT 'UNCLASSIFIED',
    approved_compartments TEXT[] DEFAULT '{}',
    roles           TEXT[] DEFAULT '{}',
    is_active       BOOLEAN DEFAULT TRUE,
    last_login      TIMESTAMP,
    created_at      TIMESTAMP DEFAULT NOW(),
    updated_at      TIMESTAMP DEFAULT NOW()
);
```

### Table: `records`

Top-level documents. Each record has an overall classification that determines who can even see it exists.

| Column | Type | Purpose |
|--------|------|---------|
| `id` | UUID (PK) | Unique identifier |
| `title` | VARCHAR(500) | Human-readable name of the record |
| `description` | TEXT | Optional description |
| `record_classification` | ENUM | Overall classification level (gates visibility) |
| `created_by` / `updated_by` | UUID (FK) | References `users` table — who created/modified |
| `is_deleted` | BOOLEAN | Soft-delete flag. Records are never physically deleted to preserve audit history. |
| `created_at` / `updated_at` | TIMESTAMP | Tracking timestamps |

```sql
CREATE TABLE records (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title                   VARCHAR(500) NOT NULL,
    description             TEXT,
    record_classification   classification_level NOT NULL DEFAULT 'UNCLASSIFIED',
    created_by              UUID REFERENCES users(id),
    updated_by              UUID REFERENCES users(id),
    is_deleted              BOOLEAN DEFAULT FALSE,
    created_at              TIMESTAMP DEFAULT NOW(),
    updated_at              TIMESTAMP DEFAULT NOW()
);
```

### Table: `record_cells`

Individual fields within a record. **THIS is where cell-level security happens.** Each cell has its own classification and compartments.

| Column | Type | Purpose |
|--------|------|---------|
| `id` | UUID (PK) | Unique identifier |
| `record_id` | UUID (FK) | Which record this cell belongs to (CASCADE delete) |
| `field_name` | VARCHAR(255) | Name of the field (e.g., `mission_name`, `personnel`) |
| `field_value` | TEXT | The actual data content |
| `cell_classification` | ENUM | Classification of THIS specific field |
| `compartments` | TEXT[] | Array of required compartments (e.g., `{PROJECT_ALPHA, OPERATION_DELTA}`) |
| `UNIQUE(record_id, field_name)` | — | Prevents duplicate field names within a record |

```sql
CREATE TABLE record_cells (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    record_id           UUID REFERENCES records(id) ON DELETE CASCADE,
    field_name          VARCHAR(255) NOT NULL,
    field_value         TEXT,
    cell_classification classification_level NOT NULL DEFAULT 'UNCLASSIFIED',
    compartments        TEXT[] DEFAULT '{}',
    created_at          TIMESTAMP DEFAULT NOW(),
    updated_at          TIMESTAMP DEFAULT NOW(),
    UNIQUE(record_id, field_name)
);
```

### Table: `need_to_know_approvals`

Tracks who approved a user's access to each compartment, when, why, and whether it has expired.

| Column | Type | Purpose |
|--------|------|---------|
| `id` | UUID (PK) | Unique identifier |
| `user_id` | UUID (FK) | Which user was granted access |
| `compartment` | VARCHAR(255) | Which compartment was granted |
| `approved_by` | UUID (FK) | Which manager/admin approved it |
| `approved_at` | TIMESTAMP | When the approval was given |
| `expires_at` | TIMESTAMP | Optional expiration — access revoked after this time |
| `reason` | TEXT | Why access was granted (for audit compliance) |
| `status` | VARCHAR(50) | `ACTIVE`, `REVOKED`, or `EXPIRED` |

```sql
CREATE TABLE need_to_know_approvals (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID REFERENCES users(id) ON DELETE CASCADE,
    compartment     VARCHAR(255) NOT NULL,
    approved_by     UUID REFERENCES users(id),
    approved_at     TIMESTAMP DEFAULT NOW(),
    expires_at      TIMESTAMP,
    reason          TEXT,
    status          VARCHAR(50) DEFAULT 'ACTIVE',
    UNIQUE(user_id, compartment)
);
```

### Table: `audit_log`

The audit log is **append-only**. Every action — reads, writes, denials — is recorded here. This table is the compliance backbone of the system.

| Column | Type | Purpose |
|--------|------|---------|
| `id` | UUID (PK) | Unique identifier |
| `event_timestamp` | TIMESTAMP | When the event occurred |
| `user_id` | UUID | Who performed the action |
| `username` | VARCHAR(255) | Username at time of action |
| `organization` | VARCHAR(255) | User's organization at time of action |
| `user_clearance` | ENUM | User's clearance at time of action |
| `action` | VARCHAR(50) | Event type: `READ_RECORD`, `ACCESS_DENIED`, `CREATE`, etc. |
| `resource_type` | VARCHAR(100) | What was accessed: `record`, `cell`, `user` |
| `resource_id` | UUID | ID of the accessed resource |
| `record_title` | VARCHAR(500) | Human-readable name for context |
| `field_name` | VARCHAR(255) | For cell events: which field |
| `classification_required` | ENUM | What clearance was needed |
| `compartments_required` | TEXT[] | What compartments were needed |
| `was_allowed` | BOOLEAN | Did the user get access? |
| `denial_reason` | TEXT | If denied: why |
| `old_value` / `new_value` | TEXT | For updates: what changed |
| `ip_address` | VARCHAR(45) | Client IP address |
| `user_agent` | TEXT | Browser/client identifier |
| `request_path` | TEXT | API endpoint called |
| `request_method` | VARCHAR(10) | HTTP method (GET, POST, etc.) |
| `session_id` | VARCHAR(255) | Session identifier |
| `details` | JSONB | Additional structured data |

### Database Indexes

```sql
-- Audit log performance indexes
CREATE INDEX idx_audit_timestamp ON audit_log(event_timestamp DESC);
CREATE INDEX idx_audit_user ON audit_log(user_id);
CREATE INDEX idx_audit_action ON audit_log(action);
CREATE INDEX idx_audit_resource ON audit_log(resource_type, resource_id);
CREATE INDEX idx_audit_allowed ON audit_log(was_allowed);
CREATE INDEX idx_audit_classification ON audit_log(classification_required);

-- Data query indexes
CREATE INDEX idx_records_classification ON records(record_classification);
CREATE INDEX idx_cells_record ON record_cells(record_id);
CREATE INDEX idx_cells_classification ON record_cells(cell_classification);
CREATE INDEX idx_users_keycloak ON users(keycloak_id);
CREATE INDEX idx_ntk_user ON need_to_know_approvals(user_id);
```

### Helper Functions

**`can_access_classification(user_clearance, required)`** — SQL function that implements the clearance hierarchy. Returns TRUE if `user_clearance` is sufficient for the required level.

```sql
CREATE OR REPLACE FUNCTION can_access_classification(
    user_clearance classification_level,
    required_classification classification_level
) RETURNS BOOLEAN AS $$
BEGIN
    RETURN CASE user_clearance
        WHEN 'TOP_SECRET' THEN TRUE
        WHEN 'SECRET' THEN required_classification IN ('UNCLASSIFIED', 'CONFIDENTIAL', 'SECRET')
        WHEN 'CONFIDENTIAL' THEN required_classification IN ('UNCLASSIFIED', 'CONFIDENTIAL')
        WHEN 'UNCLASSIFIED' THEN required_classification = 'UNCLASSIFIED'
        ELSE FALSE
    END;
END;
$$ LANGUAGE plpgsql IMMUTABLE;
```

**`has_compartments(user_compartments, required_compartments)`** — SQL function that checks if all required compartments are contained in the user's list. Uses PostgreSQL's `<@` (contained-by) operator.

```sql
CREATE OR REPLACE FUNCTION has_compartments(
    user_compartments TEXT[],
    required_compartments TEXT[]
) RETURNS BOOLEAN AS $$
BEGIN
    IF required_compartments IS NULL OR array_length(required_compartments, 1) IS NULL THEN
        RETURN TRUE;
    END IF;
    RETURN required_compartments <@ user_compartments;
END;
$$ LANGUAGE plpgsql IMMUTABLE;
```

**`audit_summary` view** — Pre-built view that selects the most useful columns from `audit_log`, ordered by newest first. Useful for quick auditing queries.

---

## 8. Keycloak Identity Provider

Keycloak is an open-source Identity and Access Management (IAM) system. It handles everything related to user identity: login, logout, password management, role assignment, and token issuance. In this system, we use two Keycloak instances to demonstrate federation between organizations.

### What is a Realm?

A realm is an isolated namespace in Keycloak. Each realm has its own users, roles, clients, and configuration.

| Realm | Instance | Purpose |
|-------|----------|---------|
| `agency-alpha` | `keycloak-alpha` (:8080) | Primary organization. Contains 5 demo users and the frontend/backend clients. |
| `agency-bravo` | `keycloak-bravo` (:8081) | Federated partner. Contains 2 demo users. Users login through Bravo and access Alpha's system. |

### What is a Client?

A client in Keycloak represents an application that uses Keycloak for authentication:

| Client ID | Type | Purpose |
|-----------|------|---------|
| `frontend-app` | Public | The React SPA. Public means no client secret is needed (browser apps can't keep secrets). Uses PKCE for security. |
| `backend-api` | Confidential | The FastAPI backend. Confidential means it has a client secret. Used for service-to-service token validation. |
| `alpha-federation` | Confidential | Exists in Bravo's realm. Used by Alpha to authenticate with Bravo during federated login. |

### Custom Client Scope: `security-attributes`

By default, Keycloak JWT tokens only contain standard claims (`sub`, `email`, `roles`). To include our custom security attributes, we created a client scope called `security-attributes` with three protocol mappers:

| Mapper Name | User Attribute | Token Claim | What It Does |
|------------|---------------|-------------|--------------|
| `clearance_level` | `clearance_level` | `clearance_level` | Reads the user's clearance attribute and adds it to the JWT |
| `compartments` | `compartments` | `compartments` | Reads compartments and adds them as a comma-separated string |
| `organization` | `organization` | `organization` | Reads the organization name and adds it to the JWT |

This scope is set as a **default client scope**, so it's automatically included in every token issued by the realm.

### Federation: How Agency Bravo Users Access Alpha's System

Federation allows users from one Keycloak to login to another without creating duplicate accounts. Here is the flow:

1. User navigates to Alpha's login page and clicks "Agency Bravo"
2. Alpha redirects the user to Bravo's login page (OIDC authorization endpoint)
3. User enters their Bravo credentials
4. Bravo validates credentials and issues a token to Alpha
5. Alpha reads Bravo's token, extracts security attributes via IDP mappers
6. Alpha creates/updates a linked user and issues its own JWT to the browser
7. The browser now has an Alpha JWT containing Bravo's security attributes
8. All API calls work exactly the same — the backend only trusts Alpha's JWT

---

## 9. Backend API (FastAPI)

The backend is built with FastAPI, a modern Python web framework. It validates JWT tokens, enforces all security layers, and logs every action.

### File Structure

| File | Purpose |
|------|---------|
| `backend/Dockerfile` | Builds the container: Python 3.12-slim, installs gcc + libpq-dev (for asyncpg), pip installs requirements, copies app code, runs uvicorn |
| `backend/requirements.txt` | All Python dependencies (10 packages) |
| `backend/app/__init__.py` | Empty file that makes `app/` a Python package |
| `backend/app/main.py` | FastAPI application entry point. Creates the app, adds CORS middleware, includes routers, defines `/health` and `/api/auth/me` endpoints. |
| `backend/app/config.py` | Pydantic settings class that reads environment variables (`DATABASE_URL`, `KEYCLOAK_URL`, etc.) |
| `backend/app/database.py` | Creates the async SQLAlchemy engine and session factory |
| `backend/app/models.py` | SQLAlchemy ORM models for all 5 tables |
| `backend/app/auth.py` | JWT validation, JWKS caching, user extraction, role-based dependency |
| `backend/app/security.py` | Cell-level security engine (classification + compartment checks) |
| `backend/app/audit.py` | Audit logging functions (write events to `audit_log` table via ORM) |
| `backend/app/routes/records.py` | CRUD endpoints for records with security filtering |
| `backend/app/routes/admin.py` | Admin endpoints: user management, NTK approvals |
| `backend/app/routes/audit_routes.py` | Audit log query endpoints with filtering and statistics |

### Backend Dockerfile — Line by Line

```dockerfile
FROM python:3.12-slim                    # Base: Python 3.12 on Debian slim (minimal)

WORKDIR /app                              # Set working directory inside container

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev && rm -rf /var/lib/apt/lists/*
    # gcc: C compiler needed to build asyncpg's C extensions
    # libpq-dev: PostgreSQL client library headers (asyncpg needs these)
    # rm -rf: Clean up apt cache to reduce image size

COPY requirements.txt .                   # Copy requirements first (Docker layer caching)
RUN pip install --no-cache-dir -r requirements.txt  # Install Python dependencies

COPY app/ ./app/                          # Copy application source code

EXPOSE 8000                               # Document that this container listens on 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
    # uvicorn: ASGI server
    # app.main:app: Import path to the FastAPI app object
    # --host 0.0.0.0: Listen on all interfaces (required for Docker)
    # --port 8000: Listen on port 8000
    # --reload: Auto-restart on code changes (development only)
```

### API Endpoints

| Method | Path | Roles | Description |
|--------|------|-------|-------------|
| GET | `/api/records` | Any authenticated | List records (filtered by user's clearance) |
| GET | `/api/records/{id}` | Any authenticated | Get record with cell-level redaction |
| POST | `/api/records` | analyst+ | Create a new record |
| PUT | `/api/records/{id}` | analyst+ | Update a record |
| DELETE | `/api/records/{id}` | manager+ | Soft-delete a record |
| GET | `/api/admin/users` | manager+ | List all users with security attributes |
| PUT | `/api/admin/users/{id}` | admin | Update user clearance/roles |
| GET | `/api/admin/approvals` | manager+ | List NTK approvals |
| POST | `/api/admin/approvals` | manager+ | Grant compartment access |
| DELETE | `/api/admin/approvals/{id}` | manager+ | Revoke compartment access |
| GET | `/api/admin/overview` | manager+ | System statistics |
| GET | `/api/audit/logs` | auditor+ | Query audit trail with filters |
| GET | `/api/audit/stats` | auditor+ | Audit statistics summary |
| GET | `/api/audit/denials` | auditor+ | Recent access denials |
| GET | `/api/auth/me` | Any authenticated | Current user info from JWT |
| GET | `/health` | Public (no auth) | Health check endpoint |

### Configuration (`config.py`) — Line by Line

```python
from pydantic_settings import BaseSettings    # Reads env vars into typed fields

class Settings(BaseSettings):
    # Each field reads from an environment variable of the same name
    DATABASE_URL: str = "postgresql+asyncpg://appuser:apppass@localhost:5433/securedata"
    DATABASE_URL_SYNC: str = "postgresql://appuser:apppass@localhost:5433/securedata"
    KEYCLOAK_URL: str = "http://localhost:8080"
    KEYCLOAK_REALM: str = "agency-alpha"
    KEYCLOAK_CLIENT_ID: str = "backend-api"
    CORS_ORIGINS: str = "http://localhost:3000"

    @property
    def keycloak_issuer(self) -> str:
        # Constructs: http://keycloak-alpha:8080/realms/agency-alpha
        return f"{self.KEYCLOAK_URL}/realms/{self.KEYCLOAK_REALM}"

    @property
    def keycloak_jwks_url(self) -> str:
        # JWKS endpoint for fetching public signing keys
        return f"{self.keycloak_issuer}/protocol/openid-connect/certs"

    @property
    def cors_origin_list(self) -> list[str]:
        # Splits comma-separated origins into a list
        return [o.strip() for o in self.CORS_ORIGINS.split(",")]

settings = Settings()  # Singleton instance used throughout the app
```

### Database Connection (`database.py`) — Line by Line

```python
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from app.config import settings

# Create the async engine — this manages a pool of database connections
engine = create_async_engine(
    settings.DATABASE_URL,    # postgresql+asyncpg://appuser:apppass@postgres-app:5432/securedata
    echo=False,               # Set True to log all SQL queries (very verbose)
    pool_size=10              # Keep 10 connections ready in the pool
)

# Session factory — creates new database sessions on demand
async_session = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False    # Don't expire objects after commit (avoids lazy-load issues)
)

class Base(DeclarativeBase):
    pass    # All ORM models inherit from this base class

async def get_db() -> AsyncSession:
    """FastAPI dependency: provides a database session for each request."""
    async with async_session() as session:
        try:
            yield session     # Give the session to the route handler
        finally:
            await session.close()  # Always close when done
```

### JWT Authentication (`auth.py`) — Key Sections

**JWKS Caching (lines 13-39):**

```python
_jwks_cache: dict = {}       # Cache for Keycloak's public keys
_jwks_cache_time: float = 0  # When the cache was last refreshed
JWKS_CACHE_TTL = 300         # Refresh every 5 minutes

async def get_jwks() -> dict:
    """Fetch and cache JWKS from Keycloak."""
    global _jwks_cache, _jwks_cache_time
    now = time.time()
    # Return cached keys if still fresh
    if _jwks_cache and (now - _jwks_cache_time) < JWKS_CACHE_TTL:
        return _jwks_cache

    # Otherwise fetch fresh keys from Keycloak
    async with httpx.AsyncClient() as client:
        resp = await client.get(settings.keycloak_jwks_url, timeout=10)
        resp.raise_for_status()
        _jwks_cache = resp.json()
        _jwks_cache_time = now

    return _jwks_cache
```

**Token Validation (lines 82-153):**

```python
async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
) -> CurrentUser:
    """Validate JWT and extract user with security attributes."""
    token = credentials.credentials

    # 1. Decode header to find which key signed this token
    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header.get("kid")

    # 2. Find the matching public key in Keycloak's JWKS
    jwks = await get_jwks()
    key_data = find_key(jwks, kid)
    public_key = jwk.construct(key_data)

    # 3. Verify and decode the token
    payload = jwt.decode(token, public_key, algorithms=["RS256"],
        options={"verify_aud": False, "verify_iss": False})

    # 4. Extract security attributes from custom claims
    clearance = payload.get("clearance_level", "UNCLASSIFIED")
    compartments_raw = payload.get("compartments", "")
    compartments = [c.strip() for c in compartments_raw.split(",") if c.strip()]
    organization = payload.get("organization", "Unknown")

    # 5. Extract roles from realm_access
    realm_roles = payload.get("realm_access", {}).get("roles", [])
    app_roles = [r for r in realm_roles
                 if r in ("viewer", "analyst", "manager", "admin", "auditor")]

    return CurrentUser(
        keycloak_id=payload.get("sub", ""),
        username=payload.get("preferred_username", "unknown"),
        clearance_level=clearance,
        compartments=compartments,
        organization=organization,
        roles=app_roles,
        token=token,
    )
```

---

## 10. Security Engine — Line by Line

**File:** `backend/app/security.py`

This is the heart of the system. The security engine makes all access decisions. Let's walk through every function:

### `clearance_rank(level)` — Lines 19-27

Converts a classification string to a numeric rank. This allows simple integer comparison instead of complex string logic.

```python
def clearance_rank(level: str) -> int:
    """Get numeric rank for a classification level."""
    mapping = {
        "UNCLASSIFIED": 0,
        "CONFIDENTIAL": 1,
        "SECRET": 2,
        "TOP_SECRET": 3,
    }
    return mapping.get(level, -1)  # -1 for unknown = no access
```

### `can_access_classification(user, required)` — Lines 30-32

The simplest function: does the user's rank meet or exceed the required rank?

```python
def can_access_classification(user_clearance: str, required: str) -> bool:
    """Check if user's clearance level meets or exceeds the required level."""
    return clearance_rank(user_clearance) >= clearance_rank(required)

# Examples:
# can_access_classification("SECRET", "CONFIDENTIAL") -> True  (2 >= 1)
# can_access_classification("CONFIDENTIAL", "SECRET") -> False (1 < 2)
# can_access_classification("TOP_SECRET", "TOP_SECRET") -> True (3 >= 3)
```

### `has_compartment_access(user_comps, required)` — Lines 35-39

Checks that the user has ALL required compartments. The `all()` function returns True only if every compartment in the required list is found in the user's list.

```python
def has_compartment_access(user_compartments: list[str], required: list[str]) -> bool:
    """Check if user has ALL required need-to-know compartments."""
    if not required:          # No compartments needed
        return True           # Everyone passes
    return all(comp in user_compartments for comp in required)

# Examples:
# has_compartment_access(["ALPHA", "OMEGA"], ["ALPHA"])          -> True
# has_compartment_access(["ALPHA"], ["ALPHA", "DELTA"])          -> False (missing DELTA)
# has_compartment_access(["ALPHA", "OMEGA", "DELTA"], ["DELTA"]) -> True
# has_compartment_access([], ["ALPHA"])                          -> False
```

### `check_record_access(user, record_classification)` — Lines 42-50

Record-level gate: can the user see this record at all?

```python
def check_record_access(user: CurrentUser, record_classification: str) -> tuple[bool, str]:
    """Check if user can access a record at all (record-level security)."""
    if can_access_classification(user.clearance_level, record_classification):
        return True, "ACCESS_GRANTED"
    return False, f"User clearance {user.clearance_level} insufficient for {record_classification} record"
```

### `check_cell_access(user, classification, compartments)` — Lines 53-73

**This is the core access decision function for individual cells.** It runs both checks in sequence:

```python
def check_cell_access(
    user: CurrentUser,
    cell_classification: str,
    cell_compartments: list[str],
) -> tuple[bool, str]:
    """
    Check if user can access a specific cell (cell-level security).
    Both classification AND compartment checks must pass.
    """
    # CHECK 1: Classification level
    if not can_access_classification(user.clearance_level, cell_classification):
        return False, "INSUFFICIENT_CLEARANCE"

    # CHECK 2: Need-to-know compartments
    if not has_compartment_access(user.compartments, cell_compartments):
        missing = [c for c in cell_compartments if c not in user.compartments]
        return False, f"NEED_TO_KNOW_REQUIRED: missing [{', '.join(missing)}]"

    return True, "ACCESS_GRANTED"
```

> **KEY INSIGHT:** Both checks must pass. A user with TOP_SECRET clearance but no compartments will still be denied access to a cell that requires PROJECT_ALPHA, even if the cell is only classified as UNCLASSIFIED.

### `filter_record_cells(user, cells)` — Lines 76-128

Takes all cells of a record and returns a filtered version. Allowed cells show their data. Denied cells show `[REDACTED]` with the denial reason. Also builds an access log for audit.

```python
def filter_record_cells(
    user: CurrentUser,
    cells: list[dict],
    record_title: str = "",
) -> tuple[list[dict], list[dict]]:
    """
    Filter cells based on user's clearance and compartments.
    Returns: (visible_cells, access_log_entries)
    """
    result = []
    access_log = []

    for cell in cells:
        cell_class = cell.get("cell_classification", "UNCLASSIFIED")
        cell_comps = cell.get("compartments", [])
        field_name = cell.get("field_name", "")

        allowed, reason = check_cell_access(user, cell_class, cell_comps)

        # ALWAYS log the attempt (both allowed and denied)
        log_entry = {
            "field_name": field_name,
            "classification_required": cell_class,
            "compartments_required": cell_comps,
            "was_allowed": allowed,
            "denial_reason": None if allowed else reason,
        }
        access_log.append(log_entry)

        if allowed:
            result.append({
                "id": str(cell.get("id", "")),
                "field_name": field_name,
                "field_value": cell.get("field_value"),     # ACTUAL DATA
                "cell_classification": cell_class,
                "compartments": cell_comps,
                "accessible": True,
            })
        else:
            result.append({
                "id": str(cell.get("id", "")),
                "field_name": field_name,
                "field_value": "[REDACTED]",                 # REDACTED
                "cell_classification": cell_class,
                "compartments": ["[REDACTED]"],
                "accessible": False,
                "denial_reason": reason,
            })

    return result, access_log  # Both returned for display + audit
```

### `get_access_summary(user)` — Lines 131-145

Generates a human-readable summary of what the user can access. Used by the frontend to display the user's permissions.

```python
def get_access_summary(user: CurrentUser) -> dict:
    max_class = user.clearance_level
    return {
        "username": user.username,
        "organization": user.organization,
        "clearance_level": max_class,
        "approved_compartments": user.compartments,
        "roles": user.roles,
        "can_view_unclassified": True,
        "can_view_confidential": clearance_rank(max_class) >= 1,
        "can_view_secret": clearance_rank(max_class) >= 2,
        "can_view_top_secret": clearance_rank(max_class) >= 3,
    }
```

---

## 11. Frontend (React SPA)

The frontend is a single `index.html` file containing all CSS, JavaScript, and React components. It uses Babel for JSX transformation in the browser.

### Key Technologies

| Library | Version | Purpose |
|---------|---------|---------|
| `keycloak-js` | 24.0.0 | JavaScript adapter for Keycloak. v24 is the last version with a UMD build (`window.Keycloak` global). Works with KC 26 server via standard OIDC. |
| React | 18 | UI framework for building the component tree |
| ReactDOM | 18 | Renders React components to the DOM |
| Babel Standalone | Latest | Compiles JSX syntax in the browser (for the demo — production apps would pre-compile) |

> **CRITICAL VERSION NOTE:** `keycloak-js` v25+ switched to ESM-only (no `window.Keycloak` global). If you use v25+ with a `<script>` tag, you get "Keycloak is not defined". Always use v24 for `<script>` tag usage. The v24 adapter speaks standard OIDC, so it works perfectly with a Keycloak 26 server.

### Keycloak Initialization Flow

1. Page loads and runs `initKeycloak()`
2. Creates a Keycloak instance with URL, realm, and clientId
3. Calls `kc.init()` with `onLoad: 'check-sso'` (checks if already logged in without forcing login)
4. `pkceMethod: 'S256'` enables Proof Key for Code Exchange (prevents authorization code interception)
5. `checkLoginIframe: false` disables the session iframe (avoids cross-origin issues)
6. If authenticated, fetches `/api/auth/me` with the Bearer token to get user details
7. Sets up a 30-second interval to refresh the token before it expires

```javascript
const kc = new Keycloak({
    url: 'http://localhost:8080',
    realm: 'agency-alpha',
    clientId: 'frontend-app',
});

kc.init({
    onLoad: 'check-sso',           // Don't force login, just check
    pkceMethod: 'S256',            // PKCE for public client security
    checkLoginIframe: false,       // Disable session iframe
    enableLogging: true,           // Console logging for debugging
}).then(authenticated => {
    if (authenticated) {
        // Token is available at kc.token
        // Use it in API calls: Authorization: Bearer ${kc.token}
    }
});
```

### UI Components

| Component | What It Shows |
|-----------|--------------|
| `LoginScreen` | Dark-themed login card with "Sign In via Keycloak" button. Shows error messages if Keycloak is unreachable. Lists demo accounts. |
| `App` | Main layout with header (user info, clearance badge, logout), navigation tabs, and content area. |
| `RecordsView` | Access statistics (total records, visible, hidden, redacted cells). Each record displayed as a card with a grid of cells showing field name, value, classification badge, and compartments. |
| `UserProfile` | Shows user's clearance level, roles, compartments, and organization. |
| `AdminView` | System overview with classification distribution. User management table. Need-to-know approvals with grant/revoke. |
| `AuditView` | Filterable event log with action type, username, allow/deny status, and time range. Statistics dashboard. |
| `ClassBadge` | Color-coded badge for classification levels (green=UNCLASSIFIED, blue=CONFIDENTIAL, red=SECRET, amber=TOP_SECRET) |
| `RoleBadge` | Color-coded badge for roles (purple=admin, blue=manager, teal=analyst, green=viewer, purple=auditor) |

### Nginx Configuration (`frontend/nginx.conf`) — Line by Line

```nginx
server {
    listen 80;                              # Listen on port 80 inside container
    server_name localhost;
    root /usr/share/nginx/html;             # Static files directory
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;   # SPA routing: serve index.html for all paths
    }

    location /api/ {
        proxy_pass http://backend:8000;     # Forward API calls to FastAPI
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_connect_timeout 10s;          # Max time to establish connection
        proxy_send_timeout 30s;             # Max time to send request
        proxy_read_timeout 30s;             # Max time to wait for response

        proxy_intercept_errors on;          # Intercept error responses
        error_page 502 503 504 = @backend_down;  # Custom handler for errors
    }

    location = /health {
        proxy_pass http://backend:8000;     # Proxy health check too
        proxy_set_header Host $host;
    }

    location @backend_down {
        default_type application/json;
        return 503 '{"error": "Backend API is starting up or unavailable.", "status": 503}';
    }
}
```

---

## 12. Audit Logging System

Every action in the system is logged. The audit log is the compliance backbone — it provides a complete, tamper-evident record of who accessed what, when, and whether they were allowed.

### Audit Event Types

| Action | When It's Logged |
|--------|-----------------|
| `LIST_RECORDS` | User requested the list of records. Stats about visible/hidden are logged. |
| `READ_RECORD` | User successfully accessed a specific record. |
| `READ_CELL` | User successfully read a specific cell within a record. |
| `ACCESS_DENIED` | User tried to access a record but their clearance was too low. |
| `CELL_ACCESS_DENIED` | User could see the record but a specific cell was redacted. |
| `CREATE` | A new record was created. |
| `UPDATE` | A record or cell was modified. Old and new values are stored. |
| `DELETE` | A record was soft-deleted. |
| `GRANT_NTK` | A manager granted need-to-know compartment access to a user. |
| `REVOKE_NTK` | A manager revoked compartment access from a user. |
| `UPDATE_USER` | An admin changed a user's clearance level or roles. |

### Implementation (`audit.py`)

The audit module uses **SQLAlchemy ORM** (not raw SQL) to avoid asyncpg type-casting issues:

```python
async def log_event(db, user, action, resource_type, **kwargs):
    """Write an audit log entry using ORM."""
    entry = AuditLog(
        event_timestamp=datetime.utcnow(),
        username=user.username if user else "anonymous",
        organization=user.organization if user else "Unknown",
        user_clearance=user.clearance_level if user else None,
        action=action,
        resource_type=resource_type,
        # ... all other fields from kwargs
    )
    db.add(entry)        # Add to session
    await db.commit()    # Write to database
```

> **WHY ORM INSTEAD OF RAW SQL?**
> An earlier version used `sqlalchemy.text()` with raw SQL. This caused two bugs: (1) `str(dict)` produces Python repr with single quotes, which PostgreSQL rejects as invalid JSON for JSONB columns. (2) The `::` cast syntax (e.g., `::text[]`) conflicts with SQLAlchemy's `:param` binding syntax. The ORM approach avoids both issues because SQLAlchemy handles type mapping automatically.

> **WHY IS AUDITING IMPORTANT?**
> In regulated environments (government, healthcare, finance), organizations must prove who accessed sensitive data and when. The audit log answers questions like: "Who tried to access the TOP SECRET records last week?", "How many access denials were there for user X?", and "Was this data accessed before the breach was discovered?"

---

## 13. Demo Users & Access Matrix

**All demo user passwords are:** `password`

### Agency Alpha Users

| Username | Clearance | Compartments | Roles |
|----------|-----------|-------------|-------|
| `alice_admin` | TOP_SECRET | ALPHA, OMEGA, DELTA | admin, auditor |
| `bob_analyst` | SECRET | ALPHA, OMEGA | analyst |
| `carol_viewer` | CONFIDENTIAL | ALPHA | viewer |
| `dave_manager` | SECRET | ALPHA, DELTA | manager, analyst |
| `eve_auditor` | TOP_SECRET | ALPHA, OMEGA, DELTA | auditor, viewer |

### Agency Bravo Users (Federated)

| Username | Clearance | Compartments | Roles |
|----------|-----------|-------------|-------|
| `frank_bravo` | SECRET | ALPHA | analyst |
| `grace_bravo` | CONFIDENTIAL | (none) | viewer |

### What Each User Sees

There are 3 demo records. Here is the visibility matrix:

| Record | Alice | Bob | Carol | Dave | Frank | Grace |
|--------|-------|-----|-------|------|-------|-------|
| Op Weather Report (CONF) | ✅ Full | ✅ Partial | ✅ Partial | ✅ Partial | ✅ Partial | ✅ Minimal |
| Asset Intel Brief (SECRET) | ✅ Full | ✅ Partial | ❌ Hidden | ✅ Partial | ✅ Partial | ❌ Hidden |
| Project Cipher (TOP SECRET) | ✅ Full | ❌ Hidden | ❌ Hidden | ❌ Hidden | ❌ Hidden | ❌ Hidden |

- ✅ **Full** = all cells visible
- ✅ **Partial** = some cells redacted due to classification or compartments
- ✅ **Minimal** = most cells redacted
- ❌ **Hidden** = record completely invisible (user doesn't know it exists)

### Detailed Cell Visibility Example: "Op Weather Report"

This record is CONFIDENTIAL overall. Here are its cells and who can see them:

| Field | Classification | Compartments | Alice (TS/All) | Bob (S/A,O) | Carol (C/A) | Grace (C/none) |
|-------|---------------|-------------|----------------|-------------|-------------|----------------|
| `mission_name` | UNCLASSIFIED | none | ✅ | ✅ | ✅ | ✅ |
| `location` | CONFIDENTIAL | none | ✅ | ✅ | ✅ | ✅ |
| `personnel` | SECRET | PROJECT_ALPHA | ✅ | ✅ | ❌ clearance | ❌ clearance |
| `methodology` | TOP_SECRET | OPERATION_DELTA | ✅ | ❌ clearance | ❌ clearance | ❌ clearance |
| `findings` | SECRET | PROJECT_OMEGA | ✅ | ✅ | ❌ clearance | ❌ clearance |

---

## 14. Complete Dependency Reference

### Backend Python Dependencies (`requirements.txt`)

| Package | Version | Why It's Needed |
|---------|---------|----------------|
| `fastapi` | 0.109.2 | The web framework. Handles HTTP routing, request/response parsing, dependency injection, and auto-generates OpenAPI docs at `/docs`. |
| `uvicorn[standard]` | 0.27.1 | ASGI server that runs FastAPI. The `[standard]` extra includes `uvloop` (fast event loop) and `httptools` (fast HTTP parsing). |
| `sqlalchemy[asyncio]` | 2.0.27 | ORM (Object-Relational Mapper). Maps Python classes to database tables. The `[asyncio]` extra enables async database operations. |
| `asyncpg` | 0.29.0 | Async PostgreSQL driver. SQLAlchemy uses this under the hood for non-blocking database queries. Written in C for performance. |
| `psycopg2-binary` | 2.9.9 | Synchronous PostgreSQL driver. Used for the `DATABASE_URL_SYNC` connection string (some operations need sync access). The `-binary` variant includes pre-compiled C extensions. |
| `python-jose[cryptography]` | 3.3.0 | JWT library. Decodes and validates JSON Web Tokens. The `[cryptography]` extra adds RSA key support for Keycloak's RS256 signatures. |
| `httpx` | 0.27.0 | Async HTTP client. Used to fetch JWKS (JSON Web Key Set) from Keycloak to get the public key for JWT verification. |
| `pydantic` | 2.6.1 | Data validation library. FastAPI uses it to validate request/response bodies and to define typed models. |
| `pydantic-settings` | 2.1.0 | Extension that reads environment variables into Pydantic models (`config.py`'s `Settings` class). |
| `python-multipart` | 0.0.9 | Required by FastAPI for form data parsing. Needed even if you only use JSON (FastAPI imports it at startup). |

### Frontend Dependencies (CDN)

| Library | Why It's Needed |
|---------|----------------|
| `keycloak-js@24.0.0` (UMD) | Handles OIDC authentication with Keycloak. Manages login redirects, token exchange, token refresh, and logout. v24 is the last version with a global constructor (v25+ is ESM-only). |
| `react@18` (UMD) | UI component framework. All views are React functional components with hooks (`useState`, `useEffect`, `useCallback`). |
| `react-dom@18` (UMD) | DOM renderer for React. Creates and updates DOM elements from the React virtual DOM. |
| `@babel/standalone` | In-browser JSX compiler. Transforms the `<Component />` syntax into `React.createElement()` calls. Not needed in production builds. |

### Docker Images

| Image | Why It's Used |
|-------|--------------|
| `postgres:16-alpine` | Lightweight PostgreSQL 16. Alpine variant is ~80MB vs ~400MB for the full image. Used for all 3 databases. |
| `quay.io/keycloak/keycloak:26.0` | Identity provider. Handles user management, OIDC/OAuth2, SAML, federation. Two instances (Alpha + Bravo). |
| `python:3.12-slim` | Base image for backend and setup containers. Slim variant omits development tools to reduce image size. |
| `nginx:alpine` | Web server for frontend. Serves static files and proxies API requests. Alpine variant is very small (~25MB). |

### System-Level Dependencies

| Tool | Purpose |
|------|---------|
| **Docker** | Container runtime. All services run in isolated containers. |
| **Docker Compose** | Orchestration. Defines all services, networks, volumes, and dependencies in one YAML file. |
| `gcc` + `libpq-dev` | Installed in the backend Dockerfile. Required to compile `asyncpg`'s C extension for PostgreSQL. |

---

## 15. Troubleshooting Guide

### Common Issues

| Problem | Solution |
|---------|----------|
| `"Keycloak is not defined"` | keycloak-js version is wrong. MUST use v24 (UMD build). v25+ is ESM-only and does not create `window.Keycloak`. Check the `<script>` tag in `index.html`. |
| `"Bad Gateway"` on login | Backend is not running. Check: `docker-compose logs backend`. Common causes: `audit.py` SQL syntax error, missing database tables, Keycloak not ready. |
| Realm import fails | Keycloak filename must match realm name: `agency-alpha-realm.json` for realm `agency-alpha`. Also: `docker-compose down -v` to clear stale volumes. |
| Health check fails (KC 26) | KC 26 serves health on port 9000 (not 8080). Healthcheck must use bash explicitly: `bash -c 'cat < /dev/null > /dev/tcp/localhost/9000'` |
| `"Invalid JSON"` in audit | The `audit.py` used `str(dict)` which produces Python repr with single quotes. Fixed by using SQLAlchemy ORM (`db.add`) instead of raw SQL. |
| `"Syntax error near :"` | SQLAlchemy `text()` + asyncpg: the `::` cast syntax conflicts with `:param` binding. Use `CAST()` or (better) use ORM inserts. |
| CORS errors in browser | Backend `CORS_ORIGINS` must include `http://localhost:3000`. Check `docker-compose.yml` environment. |
| Token validation fails | Backend's `KEYCLOAK_URL` must be the Docker-internal URL (`http://keycloak-alpha:8080`), not localhost. |
| Federated login loops | Federation setup may have failed. Check: `docker-compose logs setup`. Ensure both Keycloaks were healthy before setup ran. |
| Records not visible after login | User may not be in the application database. The setup container must run successfully to seed users. Check: `docker-compose logs setup`. |

### Quick Start Commands

```bash
# Start everything from scratch (recommended first time)
docker-compose down -v
docker-compose up --build

# Check service status
docker-compose ps

# View specific service logs
docker-compose logs backend --tail 50
docker-compose logs keycloak-alpha --tail 50
docker-compose logs setup --tail 100

# Verify Keycloak realm exists
curl http://localhost:8080/realms/agency-alpha/.well-known/openid-configuration

# Verify backend is healthy
curl http://localhost:8000/health

# Connect to application database
psql -h localhost -p 5433 -U appuser -d securedata

# Query the audit log
psql -h localhost -p 5433 -U appuser -d securedata \
  -c "SELECT username, action, was_allowed, record_title FROM audit_summary LIMIT 20;"
```

### Startup Order

Services start in dependency order (Docker Compose handles this automatically via `depends_on` + `service_healthy`):

```
1. postgres-alpha, postgres-bravo, postgres-app    (parallel, ~5s)
2. keycloak-alpha, keycloak-bravo                  (after their DBs, ~30-60s)
3. setup                                            (after both Keycloaks, ~10s, then exits)
4. backend                                          (after postgres-app + keycloak-alpha, ~5s)
5. frontend                                         (after backend healthy, ~2s)
```

Total time from `docker-compose up` to ready: **approximately 60-90 seconds** (mostly waiting for Keycloak to boot).

> **REMEMBER:** When in doubt: `docker-compose down -v && docker-compose up --build`. The `-v` flag removes all data volumes, giving you a completely clean start. This fixes 90% of "it worked yesterday" problems.

A complete, dockerized demonstration of enterprise-grade data security featuring:

- **Two Keycloak instances** (Agency Alpha + Agency Bravo) with OIDC federation
- **Role-Based Access Control (RBAC)**: viewer, analyst, manager, admin, auditor
- **Classification-based access**: UNCLASSIFIED → CONFIDENTIAL → SECRET → TOP SECRET
- **Cell-level security**: Individual fields within records have their own classification + compartment requirements
- **Need-to-know compartments**: PROJECT\_ALPHA, PROJECT\_OMEGA, OPERATION\_DELTA
- **Full audit trail**: Every CRUD operation and access attempt is logged
- **React frontend** with real-time redaction visualization
- **FastAPI backend** with comprehensive security enforcement

---

## Quick Start

```bash
# Clone and start all services
docker-compose up --build

# Wait ~90 seconds for Keycloak to initialize, then open:
# Frontend:       http://localhost:3000
# Backend API:    http://localhost:8000/docs
# Keycloak Alpha: http://localhost:8080 (admin/admin)
# Keycloak Bravo: http://localhost:8081 (admin/admin)
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           BROWSER                                   │
│   React SPA (:3000) ◄── Keycloak JS OIDC PKCE ──► Keycloak (:8080)│
│        │                                                │           │
│        │ Bearer JWT                          Federation │           │
│        ▼                                                ▼           │
│   FastAPI API (:8000)                         Keycloak Bravo (:8081)│
│   ├── JWT validation                          ├── Federated users   │
│   ├── Classification filter                   └── Security claims   │
│   ├── Cell-level redaction                                          │
│   ├── RBAC enforcement                                              │
│   └── Audit logging                                                 │
│        │                                                            │
│        ▼                                                            │
│   PostgreSQL (:5433)                                                │
│   ├── users, records, record_cells                                  │
│   ├── need_to_know_approvals                                        │
│   └── audit_log                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Demo Users

All passwords are `password`.

### Agency Alpha (Direct Login)

| Username       | Clearance    | Compartments                    | Roles            |
|---------------|-------------|--------------------------------|------------------|
| alice\_admin   | TOP\_SECRET  | ALPHA, OMEGA, DELTA            | admin, auditor   |
| bob\_analyst   | SECRET       | ALPHA, OMEGA                   | analyst          |
| carol\_viewer  | CONFIDENTIAL | ALPHA                          | viewer           |
| dave\_manager  | SECRET       | ALPHA, DELTA                   | manager, analyst |
| eve\_auditor   | TOP\_SECRET  | ALPHA, OMEGA, DELTA            | auditor, viewer  |

### Agency Bravo (Federated Login)

| Username      | Clearance    | Compartments | Roles   |
|--------------|-------------|-------------|---------|
| frank\_bravo  | SECRET       | ALPHA        | analyst |
| grace\_bravo  | CONFIDENTIAL | None         | viewer  |

---

## Security Model

### 1. Classification Hierarchy

```
TOP_SECRET  (rank 3) ─── Highest
SECRET      (rank 2)
CONFIDENTIAL (rank 1)
UNCLASSIFIED (rank 0) ─── Lowest
```

A user with clearance X can see data at level X or below.

### 2. Three Layers of Security

**Layer 1 — Record-Level**: Each record has an overall classification. If a user's clearance is below this level, the entire record is invisible (they don't even know it exists).

**Layer 2 — Cell-Level Classification**: Within a visible record, each field has its own classification. Fields above the user's clearance show `[REDACTED]`.

**Layer 3 — Need-to-Know Compartments**: Even with sufficient clearance, a field may require specific compartment approvals. Missing any required compartment results in `[REDACTED]` with a specific denial reason.

### 3. Access Decision Logic

```
can_access_cell(user, cell):
    IF user.clearance < cell.classification:
        RETURN DENIED("INSUFFICIENT_CLEARANCE")
    IF cell.compartments NOT SUBSET OF user.compartments:
        RETURN DENIED("NEED_TO_KNOW_REQUIRED: missing [X, Y]")
    RETURN ALLOWED
```

### 4. What Each User Sees

**Alice (TOP\_SECRET, all compartments)**: Sees everything — all 3 records, all cells.

**Bob (SECRET, ALPHA+OMEGA)**: Sees 2 records (not TOP\_SECRET). Within those records, cells requiring OPERATION\_DELTA are redacted.

**Carol (CONFIDENTIAL, ALPHA only)**: Sees 1 record. SECRET and TOP\_SECRET cells are redacted. Cells requiring OMEGA or DELTA are also redacted.

**Dave (SECRET, ALPHA+DELTA)**: Sees 2 records. Cells requiring OMEGA are redacted.

**Eve (TOP\_SECRET, all compartments)**: Sees everything, same as Alice.

**Frank (SECRET, ALPHA, federated)**: Sees 2 records via federation. Cells requiring OMEGA or DELTA are redacted.

**Grace (CONFIDENTIAL, none, federated)**: Sees 1 record. Most cells are redacted due to low clearance and no compartments.

---

## RBAC Roles

| Role     | Records | Admin Panel | Audit Logs | Create Records | Delete Records | NTK Approvals |
|---------|---------|-------------|-----------|---------------|---------------|---------------|
| viewer   | Read    | ❌          | ❌         | ❌             | ❌             | ❌             |
| analyst  | Read    | ❌          | ❌         | ✅             | ❌             | ❌             |
| manager  | Read    | ✅          | ❌         | ✅             | ✅             | ✅             |
| admin    | Read    | ✅          | ✅         | ✅             | ✅             | ✅             |
| auditor  | Read    | ❌          | ✅         | ❌             | ❌             | ❌             |

---

## Audit Trail

Every action is logged with:

| Field                  | Description                                    |
|-----------------------|-----------------------------------------------|
| event\_timestamp       | When the event occurred                        |
| username               | Who performed the action                       |
| organization           | User's organization                            |
| user\_clearance        | User's clearance level at time of access       |
| action                 | What happened (READ\_CELL, ACCESS\_DENIED, etc.) |
| resource\_type         | What was accessed (record, cell, user, etc.)   |
| resource\_id           | UUID of the resource                           |
| record\_title          | Human-readable record name                     |
| field\_name            | Specific cell field (for cell-level events)    |
| classification\_required | Classification level needed                  |
| compartments\_required | Compartments needed                            |
| was\_allowed           | Whether access was granted                     |
| denial\_reason         | Why access was denied (if applicable)          |
| ip\_address            | Client IP address                              |
| user\_agent            | Client browser/tool                            |
| request\_path          | API endpoint accessed                          |
| request\_method        | HTTP method                                    |

### Audit Event Types

| Action             | Description                            |
|-------------------|----------------------------------------|
| LIST\_RECORDS      | User listed records (with filter stats) |
| READ\_RECORD       | User accessed a specific record         |
| READ\_CELL         | User successfully read a cell           |
| ACCESS\_DENIED     | Record-level access denied              |
| CELL\_ACCESS\_DENIED | Cell-level access denied               |
| CREATE             | Record created                          |
| UPDATE             | Record modified                         |
| DELETE             | Record soft-deleted                     |
| GRANT\_NTK         | Need-to-know compartment granted        |
| REVOKE\_NTK        | Need-to-know compartment revoked        |
| UPDATE\_USER       | User security attributes changed        |

---

## Federation Setup

### How It Works

1. Keycloak Bravo has a client `alpha-federation` that Keycloak Alpha uses to verify Bravo users.
2. Keycloak Alpha has an Identity Provider configured pointing to Bravo's OIDC endpoints.
3. IDP Mappers transfer `clearance_level`, `compartments`, and `organization` from Bravo tokens to Alpha.
4. When a Bravo user logs in, they're redirected to Bravo, then back to Alpha with their security claims.
5. The backend API trusts Alpha's JWT, which now contains Bravo user's attributes.

### Manual Federation Setup (if auto-setup fails)

1. Go to http://localhost:8080 → admin/admin → Realm: agency-alpha
2. Identity Providers → Add → Keycloak OpenID Connect
3. Alias: `agency-bravo`
4. Authorization URL: `http://localhost:8081/realms/agency-bravo/protocol/openid-connect/auth`
5. Token URL: `http://keycloak-bravo:8080/realms/agency-bravo/protocol/openid-connect/token`
6. Client ID: `alpha-federation`
7. Client Secret: `federation-secret-key`

---

## API Endpoints

### Records
- `GET /api/records` — List records with security filtering
- `GET /api/records/{id}` — Get single record with cell-level security
- `POST /api/records` — Create record (analyst+)
- `PUT /api/records/{id}` — Update record (analyst+)
- `DELETE /api/records/{id}` — Soft-delete record (manager+)

### Admin
- `GET /api/admin/users` — List users (manager+)
- `PUT /api/admin/users/{id}` — Update user security (admin)
- `GET /api/admin/approvals` — List NTK approvals (manager+)
- `POST /api/admin/approvals` — Grant compartment (manager+)
- `DELETE /api/admin/approvals/{id}` — Revoke compartment (manager+)
- `GET /api/admin/overview` — System statistics (manager+)

### Audit
- `GET /api/audit/logs` — Query audit trail (auditor+)
- `GET /api/audit/stats` — Audit statistics (auditor+)
- `GET /api/audit/denials` — Recent denials (auditor+)

### Auth
- `GET /api/auth/me` — Current user info from JWT

---

## Running Tests

```bash
# Install test dependencies
pip install requests

# Run the comprehensive test suite
python tests/test_client.py
```

The test suite validates:
1. Authentication for all users
2. JWT security claim extraction
3. Record-level classification filtering
4. Cell-level redaction correctness
5. RBAC role enforcement
6. CRUD operation security
7. Audit trail completeness
8. Unauthenticated access prevention

---

## Database Schema

```sql
users              — Synced from Keycloak on first login
records            — Top-level documents with overall classification
record_cells       — Individual fields with cell-level security
need_to_know_approvals — Compartment access grants with expiration
audit_log          — Immutable event log for all activity
```

---

## Key Design Decisions

1. **Cell-level security in the database**: Each field is a separate row in `record_cells` with its own classification and compartments. This enables fine-grained access control without complex column-level permissions.

2. **Soft deletes**: Records are never physically deleted — `is_deleted` flag preserves audit history.

3. **Audit everything**: Every read, write, and denial is logged. The audit table is append-only with no update/delete operations.

4. **JWT-based claims**: Security attributes (clearance, compartments) are embedded in the JWT by Keycloak, reducing database lookups on every request.

5. **Federation via IDP mappers**: Keycloak's IDP mapper system transfers security claims from federated organizations without custom code.

6. **Frontend redaction UI**: The UI clearly shows which cells are accessible vs. redacted, including the specific reason for denial. This helps users understand the security model.

---

## Stopping the Demo

```bash
docker-compose down          # Stop containers
docker-compose down -v       # Stop and remove all data
```
