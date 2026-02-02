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


def create_auto_link_flow(headers):
    """
    Create an authentication flow that auto-creates and auto-links federated
    users WITHOUT showing the 'Update Account Information' form.

    Default 'first broker login' flow shows a form → confusing for users.
    This custom flow silently creates/links the user.
    """
    flow_alias = "auto-link-first-login"

    # Check if flow already exists
    resp = requests.get(
        f"{ALPHA_URL}/admin/realms/agency-alpha/authentication/flows",
        headers=headers,
    )
    existing_flows = [f["alias"] for f in resp.json()]
    if flow_alias in existing_flows:
        print(f"    Auth flow '{flow_alias}' already exists. Skipping.")
        return flow_alias

    # Step 1: Create the top-level flow
    resp = requests.post(
        f"{ALPHA_URL}/admin/realms/agency-alpha/authentication/flows",
        headers=headers,
        json={
            "alias": flow_alias,
            "description": "Auto-create and link federated users without prompting",
            "providerId": "basic-flow",
            "topLevel": True,
            "builtIn": False,
        },
    )
    if resp.status_code not in (201, 204):
        print(f"    ✗ Failed to create flow: {resp.status_code} {resp.text}")
        return None
    print(f"    ✓ Created auth flow '{flow_alias}'")

    # Step 2: Add 'Create User If Unique' execution
    resp = requests.post(
        f"{ALPHA_URL}/admin/realms/agency-alpha/authentication/flows/{flow_alias}/executions/execution",
        headers=headers,
        json={"provider": "idp-create-user-if-unique"},
    )
    if resp.status_code in (201, 204):
        print("    ✓ Added 'Create User If Unique' execution")
    else:
        print(f"    ✗ Failed to add create-user execution: {resp.status_code} {resp.text}")

    # Step 3: Add 'Automatically Set Existing User' execution
    resp = requests.post(
        f"{ALPHA_URL}/admin/realms/agency-alpha/authentication/flows/{flow_alias}/executions/execution",
        headers=headers,
        json={"provider": "idp-auto-link"},
    )
    if resp.status_code in (201, 204):
        print("    ✓ Added 'Auto Link Existing User' execution")
    else:
        print(f"    ✗ Failed to add auto-link execution: {resp.status_code} {resp.text}")

    # Step 4: Set both executions to ALTERNATIVE
    resp = requests.get(
        f"{ALPHA_URL}/admin/realms/agency-alpha/authentication/flows/{flow_alias}/executions",
        headers=headers,
    )
    if resp.status_code == 200:
        for execution in resp.json():
            execution["requirement"] = "ALTERNATIVE"
            requests.put(
                f"{ALPHA_URL}/admin/realms/agency-alpha/authentication/flows/{flow_alias}/executions",
                headers=headers,
                json=execution,
            )
        print("    ✓ Set executions to ALTERNATIVE")

    return flow_alias


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

    # ─── Step 1: Create auto-link authentication flow ─────────────────────
    print("\n  [1/3] Creating auto-link authentication flow...")
    flow_alias = create_auto_link_flow(headers)
    first_broker_flow = flow_alias or "first broker login"  # fallback to default

    # ─── Step 2: Create Identity Provider ─────────────────────────────────
    print("\n  [2/3] Configuring Identity Provider...")

    resp = requests.get(
        f"{ALPHA_URL}/admin/realms/agency-alpha/identity-provider/instances",
        headers=headers,
    )
    existing = [idp["alias"] for idp in resp.json()]

    idp_config = {
        "alias": "agency-bravo",
        "displayName": "Agency Bravo",
        "providerId": "keycloak-oidc",
        "enabled": True,
        "trustEmail": True,
        "storeToken": True,
        "firstBrokerLoginFlowAlias": first_broker_flow,
        "config": {
            "authorizationUrl": f"{BRAVO_EXTERNAL_URL}/realms/agency-bravo/protocol/openid-connect/auth",
            "tokenUrl": f"{BRAVO_URL}/realms/agency-bravo/protocol/openid-connect/token",
            "userInfoUrl": f"{BRAVO_URL}/realms/agency-bravo/protocol/openid-connect/userinfo",
            "jwksUrl": f"{BRAVO_URL}/realms/agency-bravo/protocol/openid-connect/certs",
            "logoutUrl": f"{BRAVO_EXTERNAL_URL}/realms/agency-bravo/protocol/openid-connect/logout",
            # FIX: Empty issuer to skip issuer validation — avoids mismatch between
            # browser URL (localhost:8081) and Docker-internal URL (keycloak-bravo:8080)
            "issuer": "",
            "clientId": "alpha-federation",
            "clientSecret": "federation-secret-key",
            "clientAuthMethod": "client_secret_post",
            # FIX: Include "roles" scope so Bravo's token includes realm_access.roles
            "defaultScope": "openid profile email roles security-attributes",
            "syncMode": "FORCE",
            "validateSignature": "false",
            # Disable user info to avoid internal/external URL mismatch
            "disableUserInfo": "false",
        },
    }

    if "agency-bravo" in existing:
        # Update existing IDP with fixed config
        resp = requests.put(
            f"{ALPHA_URL}/admin/realms/agency-alpha/identity-provider/instances/agency-bravo",
            headers=headers,
            json=idp_config,
        )
        if resp.status_code in (200, 204):
            print("  ✓ Updated Identity Provider 'agency-bravo' with fixed config")
        else:
            print(f"  ✗ Failed to update IDP: {resp.status_code} {resp.text}")
    else:
        # Create new IDP
        resp = requests.post(
            f"{ALPHA_URL}/admin/realms/agency-alpha/identity-provider/instances",
            headers=headers,
            json=idp_config,
        )
        if resp.status_code in (201, 204):
            print("  ✓ Created Identity Provider 'agency-bravo'")
        else:
            print(f"  ✗ Failed to create IDP: {resp.status_code} {resp.text}")

    # ─── Step 3: Add IDP mappers ─────────────────────────────────────────
    print("\n  [3/3] Configuring IDP mappers...")

    # Get existing mappers to avoid duplicates
    resp = requests.get(
        f"{ALPHA_URL}/admin/realms/agency-alpha/identity-provider/instances/agency-bravo/mappers",
        headers=headers,
    )
    existing_mappers = [m["name"] for m in resp.json()] if resp.status_code == 200 else []

    # Attribute mappers (clearance, compartments, organization)
    attribute_mappers = [
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
                "syncMode": "FORCE",
            },
        },
    ]

    # FIX: Role mappers — map Bravo realm roles to Alpha realm roles
    role_mappers = [
        {
            "name": "role-mapper-viewer",
            "identityProviderAlias": "agency-bravo",
            "identityProviderMapper": "oidc-role-idp-mapper",
            "config": {
                "syncMode": "FORCE",
                "external.role": "viewer",
                "role": "viewer",
            },
        },
        {
            "name": "role-mapper-analyst",
            "identityProviderAlias": "agency-bravo",
            "identityProviderMapper": "oidc-role-idp-mapper",
            "config": {
                "syncMode": "FORCE",
                "external.role": "analyst",
                "role": "analyst",
            },
        },
        {
            "name": "role-mapper-manager",
            "identityProviderAlias": "agency-bravo",
            "identityProviderMapper": "oidc-role-idp-mapper",
            "config": {
                "syncMode": "FORCE",
                "external.role": "manager",
                "role": "manager",
            },
        },
        {
            "name": "role-mapper-admin",
            "identityProviderAlias": "agency-bravo",
            "identityProviderMapper": "oidc-role-idp-mapper",
            "config": {
                "syncMode": "FORCE",
                "external.role": "admin",
                "role": "admin",
            },
        },
        # Fallback: give ALL federated users at least "viewer" role
        {
            "name": "default-viewer-role",
            "identityProviderAlias": "agency-bravo",
            "identityProviderMapper": "hardcoded-role-idp-mapper",
            "config": {
                "syncMode": "FORCE",
                "role": "viewer",
            },
        },
    ]

    all_mappers = attribute_mappers + role_mappers

    for mapper in all_mappers:
        if mapper["name"] in existing_mappers:
            print(f"    ⏭ Mapper '{mapper['name']}' already exists. Skipping.")
            continue

        resp = requests.post(
            f"{ALPHA_URL}/admin/realms/agency-alpha/identity-provider/instances/agency-bravo/mappers",
            headers=headers,
            json=mapper,
        )
        status = "✓" if resp.status_code in (201, 204) else "✗"
        print(f"    {status} IDP Mapper '{mapper['name']}' -> {resp.status_code}")

    print("\n  ✓ Federation setup complete!\n")


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
        import traceback
        traceback.print_exc()
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
    print("  alice_admin   | TOP_SECRET   | All compartments    | Admin + Auditor")
    print("  bob_analyst   | SECRET       | ALPHA, OMEGA        | Analyst")
    print("  carol_viewer  | CONFIDENTIAL | ALPHA               | Viewer")
    print("  dave_manager  | SECRET       | ALPHA, DELTA        | Manager + Analyst")
    print("  eve_auditor   | TOP_SECRET   | All compartments    | Auditor + Viewer")
    print()
    print("  Federated (Agency Bravo — click 'Agency Bravo' button):")
    print("  ─────────────────────────────────────────")
    print("  frank_bravo   | SECRET       | ALPHA               | Analyst")
    print("  grace_bravo   | CONFIDENTIAL | None                | Viewer")
    print()


if __name__ == "__main__":
    main()
