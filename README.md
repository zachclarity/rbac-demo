# RBAC + Cell-Level Security Demo

![Login Screen](https://github.com/zactonicsai/rbac-demo/blob/main/rbacdemo.png)


## Federated OIDC/OAuth2 with Classification Access & Need-to-Know Controls

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
