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
