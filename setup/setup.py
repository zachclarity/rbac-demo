"""
Setup script: Configures Keycloak federation and seeds demo data.
Runs once after both Keycloak instances are healthy.
"""
import os
import sys
import time
import json
import uuid
import requests
import psycopg2

# ─── Configuration ──────────────────────────────────────────────────────────
ALPHA_URL = os.environ["ALPHA_URL"]
BRAVO_URL = os.environ["BRAVO_URL"]
BRAVO_EXTERNAL_URL = os.environ["BRAVO_EXTERNAL_URL"]
ADMIN_USER = os.environ["ADMIN_USER"]
ADMIN_PASS = os.environ["ADMIN_PASS"]

DB_CONFIG = {
    "host": os.environ["APP_DB_HOST"],
    "port": int(os.environ["APP_DB_PORT"]),
    "dbname": os.environ["APP_DB_NAME"],
    "user": os.environ["APP_DB_USER"],
    "password": os.environ["APP_DB_PASS"],
}


def get_admin_token(base_url):
    """Get admin access token from Keycloak."""
    resp = requests.post(
        f"{base_url}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": ADMIN_USER,
            "password": ADMIN_PASS,
        },
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def setup_federation():
    """Configure Keycloak Alpha to trust Keycloak Bravo as an Identity Provider."""
    print("=" * 60)
    print("SETTING UP FEDERATION: Alpha <-> Bravo")
    print("=" * 60)

    alpha_token = get_admin_token(ALPHA_URL)
    headers = {
        "Authorization": f"Bearer {alpha_token}",
        "Content-Type": "application/json",
    }

    # Check if IDP already exists
    resp = requests.get(
        f"{ALPHA_URL}/admin/realms/agency-alpha/identity-provider/instances",
        headers=headers,
    )
    existing = [idp["alias"] for idp in resp.json()]
    if "agency-bravo" in existing:
        print("  Federation already configured. Skipping.")
        return

    # Create Identity Provider in Alpha pointing to Bravo
    idp_config = {
        "alias": "agency-bravo",
        "displayName": "Login via Agency Bravo",
        "providerId": "keycloak-oidc",
        "enabled": True,
        "trustEmail": True,
        "storeToken": True,
        "firstBrokerLoginFlowAlias": "first broker login",
        "config": {
            "authorizationUrl": f"{BRAVO_EXTERNAL_URL}/realms/agency-bravo/protocol/openid-connect/auth",
            "tokenUrl": f"{BRAVO_URL}/realms/agency-bravo/protocol/openid-connect/token",
            "userInfoUrl": f"{BRAVO_URL}/realms/agency-bravo/protocol/openid-connect/userinfo",
            "jwksUrl": f"{BRAVO_URL}/realms/agency-bravo/protocol/openid-connect/certs",
            "issuer": f"{BRAVO_URL}/realms/agency-bravo",
            "clientId": "alpha-federation",
            "clientSecret": "federation-secret-key",
            "clientAuthMethod": "client_secret_post",
            "defaultScope": "openid profile email security-attributes",
            "syncMode": "FORCE",
            "validateSignature": "false",
        },
    }

    resp = requests.post(
        f"{ALPHA_URL}/admin/realms/agency-alpha/identity-provider/instances",
        headers=headers,
        json=idp_config,
    )
    if resp.status_code in (201, 204):
        print("  ✓ Identity Provider 'agency-bravo' created in Alpha realm")
    else:
        print(f"  ✗ Failed to create IDP: {resp.status_code} {resp.text}")

    # Add IDP mappers to carry over security attributes
    mappers = [
        {
            "name": "clearance-mapper",
            "identityProviderAlias": "agency-bravo",
            "identityProviderMapper": "oidc-user-attribute-idp-mapper",
            "config": {
                "claim": "clearance_level",
                "user.attribute": "clearance_level",
                "syncMode": "FORCE",
            },
        },
        {
            "name": "compartments-mapper",
            "identityProviderAlias": "agency-bravo",
            "identityProviderMapper": "oidc-user-attribute-idp-mapper",
            "config": {
                "claim": "compartments",
                "user.attribute": "compartments",
                "syncMode": "FORCE",
            },
        },
        {
            "name": "organization-mapper",
            "identityProviderAlias": "agency-bravo",
            "identityProviderMapper": "hardcoded-attribute-idp-mapper",
            "config": {
                "attribute": "organization",
                "attribute.value": "Agency Bravo",
            },
        },
    ]

    for mapper in mappers:
        resp = requests.post(
            f"{ALPHA_URL}/admin/realms/agency-alpha/identity-provider/instances/agency-bravo/mappers",
            headers=headers,
            json=mapper,
        )
        status = "✓" if resp.status_code in (201, 204) else "✗"
        print(f"  {status} IDP Mapper '{mapper['name']}' -> {resp.status_code}")

    print("  ✓ Federation setup complete!\n")


def get_keycloak_users():
    """Fetch all users from Keycloak Alpha to link with app DB."""
    alpha_token = get_admin_token(ALPHA_URL)
    headers = {"Authorization": f"Bearer {alpha_token}"}
    resp = requests.get(
        f"{ALPHA_URL}/admin/realms/agency-alpha/users?max=100",
        headers=headers,
    )
    resp.raise_for_status()
    return resp.json()


def seed_database():
    """Seed the application database with users and demo records."""
    print("=" * 60)
    print("SEEDING APPLICATION DATABASE")
    print("=" * 60)

    conn = psycopg2.connect(**DB_CONFIG)
    conn.autocommit = True
    cur = conn.cursor()

    # Check if already seeded
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] > 0:
        print("  Database already seeded. Skipping.")
        cur.close()
        conn.close()
        return

    # Get Keycloak users
    kc_users = get_keycloak_users()
    print(f"  Found {len(kc_users)} users in Keycloak Alpha")

    # User definitions with their security attributes
    user_defs = {
        "alice_admin": {
            "clearance": "TOP_SECRET",
            "compartments": ["PROJECT_ALPHA", "PROJECT_OMEGA", "OPERATION_DELTA"],
            "roles": ["admin", "auditor"],
        },
        "bob_analyst": {
            "clearance": "SECRET",
            "compartments": ["PROJECT_ALPHA", "PROJECT_OMEGA"],
            "roles": ["analyst"],
        },
        "carol_viewer": {
            "clearance": "CONFIDENTIAL",
            "compartments": ["PROJECT_ALPHA"],
            "roles": ["viewer"],
        },
        "dave_manager": {
            "clearance": "SECRET",
            "compartments": ["PROJECT_ALPHA", "OPERATION_DELTA"],
            "roles": ["manager", "analyst"],
        },
        "eve_auditor": {
            "clearance": "TOP_SECRET",
            "compartments": ["PROJECT_ALPHA", "PROJECT_OMEGA", "OPERATION_DELTA"],
            "roles": ["auditor", "viewer"],
        },
    }

    user_ids = {}

    for kc_user in kc_users:
        username = kc_user.get("username", "")
        if username not in user_defs:
            continue

        udef = user_defs[username]
        user_id = str(uuid.uuid4())
        user_ids[username] = user_id

        cur.execute(
            """INSERT INTO users
               (id, keycloak_id, username, email, full_name, organization,
                clearance_level, approved_compartments, roles, last_login)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, NOW())""",
            (
                user_id,
                kc_user["id"],
                username,
                kc_user.get("email", ""),
                f"{kc_user.get('firstName', '')} {kc_user.get('lastName', '')}",
                "Agency Alpha",
                udef["clearance"],
                udef["compartments"],
                udef["roles"],
            ),
        )
        print(f"  ✓ User '{username}' (clearance={udef['clearance']})")

    # Insert need-to-know approvals
    admin_id = user_ids.get("alice_admin")
    for username, udef in user_defs.items():
        uid = user_ids.get(username)
        if not uid:
            continue
        for comp in udef["compartments"]:
            cur.execute(
                """INSERT INTO need_to_know_approvals
                   (user_id, compartment, approved_by, reason, status)
                   VALUES (%s, %s, %s, %s, 'ACTIVE')""",
                (uid, comp, admin_id, f"Initial clearance grant for {username}"),
            )

    print("\n  Seeding demo records...")

    # ─── Record 1: Operation Weather Report ─────────────────────────────
    rec1_id = str(uuid.uuid4())
    cur.execute(
        """INSERT INTO records (id, title, description, record_classification, created_by)
           VALUES (%s, %s, %s, 'CONFIDENTIAL', %s)""",
        (rec1_id, "Operation Weather Report",
         "Environmental monitoring and analysis report", admin_id),
    )
    cells_1 = [
        ("summary", "Quarterly environmental monitoring across all stations shows normal patterns with localized anomalies in the Pacific sector.",
         "UNCLASSIFIED", []),
        ("location", "Pacific Monitoring Station 7 - Sector G",
         "CONFIDENTIAL", []),
        ("coordinates", "37.7749° N, 122.4194° W - Subsurface Array Delta",
         "SECRET", ["PROJECT_ALPHA"]),
        ("findings", "Unusual electromagnetic readings detected at 2300hrs on multiple consecutive nights. Pattern suggests non-natural origin. Further analysis required.",
         "CONFIDENTIAL", ["PROJECT_ALPHA"]),
        ("recommendations", "Deploy three additional deep-water sensor arrays. Coordinate with OPERATION_DELTA assets for aerial surveillance coverage.",
         "SECRET", ["OPERATION_DELTA"]),
    ]
    for fname, fval, fclass, comps in cells_1:
        cur.execute(
            """INSERT INTO record_cells (record_id, field_name, field_value, cell_classification, compartments)
               VALUES (%s, %s, %s, %s, %s)""",
            (rec1_id, fname, fval, fclass, comps),
        )
    print("  ✓ Record 1: 'Operation Weather Report' (CONFIDENTIAL)")

    # ─── Record 2: Asset Intelligence Brief ─────────────────────────────
    rec2_id = str(uuid.uuid4())
    cur.execute(
        """INSERT INTO records (id, title, description, record_classification, created_by)
           VALUES (%s, %s, %s, 'SECRET', %s)""",
        (rec2_id, "Asset Intelligence Brief",
         "Quarterly intelligence summary and threat assessment", admin_id),
    )
    cells_2 = [
        ("title", "Q4 Regional Intelligence Summary - Southeast Asia Theater",
         "UNCLASSIFIED", []),
        ("region", "Southeast Asia - Maritime Corridor Zones 3 through 7",
         "CONFIDENTIAL", []),
        ("asset_status", "Asset BLUE-7 operational and reporting. Cover intact. Next scheduled contact: 15 days. Asset RED-3 extracted successfully last quarter.",
         "SECRET", ["PROJECT_OMEGA"]),
        ("threat_assessment", "Medium-high risk. Increased naval activity observed in contested waters. Signals intelligence indicates possible escalation in 60-90 day window.",
         "SECRET", ["PROJECT_ALPHA"]),
        ("action_items", "Priority 1: Activate backup communication channels. Priority 2: Position extraction assets within 48-hour response radius. Priority 3: Brief allied partners under FIVE EYES framework.",
         "TOP_SECRET", ["PROJECT_OMEGA", "OPERATION_DELTA"]),
    ]
    for fname, fval, fclass, comps in cells_2:
        cur.execute(
            """INSERT INTO record_cells (record_id, field_name, field_value, cell_classification, compartments)
               VALUES (%s, %s, %s, %s, %s)""",
            (rec2_id, fname, fval, fclass, comps),
        )
    print("  ✓ Record 2: 'Asset Intelligence Brief' (SECRET)")

    # ─── Record 3: Technical Specifications ─────────────────────────────
    rec3_id = str(uuid.uuid4())
    cur.execute(
        """INSERT INTO records (id, title, description, record_classification, created_by)
           VALUES (%s, %s, %s, 'TOP_SECRET', %s)""",
        (rec3_id, "Project Cipher - Technical Specifications",
         "Advanced cryptographic system specifications and test results", admin_id),
    )
    cells_3 = [
        ("project_name", "Project Cipher - Next Generation Cryptographic Framework",
         "CONFIDENTIAL", []),
        ("phase", "Phase 2 - Controlled Environment Testing. All lab results nominal. Ready for Phase 3 field trials pending committee approval.",
         "SECRET", ["PROJECT_ALPHA"]),
        ("specifications", "Operating Frequency: 2.4GHz spread-spectrum with adaptive hopping. Encryption: 512-bit post-quantum lattice-based. Throughput: 10Gbps sustained.",
         "TOP_SECRET", ["PROJECT_OMEGA"]),
        ("test_results", "Lab accuracy: 98.7%. Bit error rate: 1.2e-12. Jamming resistance: survived 340dB interference. Quantum readiness score: 94/100.",
         "TOP_SECRET", ["PROJECT_ALPHA", "OPERATION_DELTA"]),
    ]
    for fname, fval, fclass, comps in cells_3:
        cur.execute(
            """INSERT INTO record_cells (record_id, field_name, field_value, cell_classification, compartments)
               VALUES (%s, %s, %s, %s, %s)""",
            (rec3_id, fname, fval, fclass, comps),
        )
    print("  ✓ Record 3: 'Project Cipher - Technical Specifications' (TOP_SECRET)")

    # Log the initial seed as an audit event
    cur.execute(
        """INSERT INTO audit_log
           (username, organization, action, resource_type, details)
           VALUES ('SYSTEM', 'SYSTEM', 'SEED_DATA', 'system',
                   '{"message": "Demo data seeded by setup script"}'::jsonb)"""
    )

    cur.close()
    conn.close()
    print("\n  ✓ Database seeding complete!\n")


def main():
    print("\n" + "=" * 60)
    print("  RBAC + CELL-LEVEL SECURITY DEMO SETUP")
    print("=" * 60 + "\n")

    # Wait a moment for Keycloak to fully initialize imports
    print("Waiting for Keycloak realm imports to complete...")
    time.sleep(10)

    try:
        setup_federation()
    except Exception as e:
        print(f"  ⚠ Federation setup error (non-fatal): {e}")
        print("  Federation can be configured manually via Keycloak admin console.\n")

    try:
        seed_database()
    except Exception as e:
        print(f"  ✗ Database seeding error: {e}")
        sys.exit(1)

    print("=" * 60)
    print("  SETUP COMPLETE!")
    print("=" * 60)
    print()
    print("  Access Points:")
    print("  ─────────────────────────────────────────")
    print("  Frontend:         http://localhost:3000")
    print("  Backend API:      http://localhost:8000/docs")
    print("  Keycloak Alpha:   http://localhost:8080 (admin/admin)")
    print("  Keycloak Bravo:   http://localhost:8081 (admin/admin)")
    print()
    print("  Test Users (all passwords: 'password'):")
    print("  ─────────────────────────────────────────")
    print("  alice_admin   | TOP_SECRET | All compartments    | Admin")
    print("  bob_analyst   | SECRET     | ALPHA, OMEGA        | Analyst")
    print("  carol_viewer  | CONFIDENTIAL| ALPHA              | Viewer")
    print("  dave_manager  | SECRET     | ALPHA, DELTA        | Manager")
    print("  eve_auditor   | TOP_SECRET | All compartments    | Auditor")
    print("  frank_bravo   | SECRET     | ALPHA (federated)   | Analyst")
    print("  grace_bravo   | CONFIDENTIAL| None (federated)  | Viewer")
    print()


if __name__ == "__main__":
    main()
