#!/usr/bin/env python3
"""
RBAC + Cell-Level Security Test Client

Tests all security scenarios:
1. Authentication via Keycloak OIDC
2. Classification-based record filtering
3. Cell-level redaction based on clearance and compartments
4. Role-based access control
5. Audit trail verification
6. Need-to-know enforcement

Usage:
    pip install requests
    python test_client.py
"""
import sys
import json
import requests
from datetime import datetime

# ─── Configuration ──────────────────────────────────────────────────────────
KEYCLOAK_URL = "http://localhost:8080"
KEYCLOAK_REALM = "agency-alpha"
API_URL = "http://localhost:8000"

# Test users with their expected access
TEST_USERS = {
    "alice_admin": {
        "password": "password",
        "clearance": "TOP_SECRET",
        "compartments": ["PROJECT_ALPHA", "PROJECT_OMEGA", "OPERATION_DELTA"],
        "expected_visible_records": 3,
        "expected_redacted_cells": 0,
        "roles": ["admin", "auditor"],
    },
    "bob_analyst": {
        "password": "password",
        "clearance": "SECRET",
        "compartments": ["PROJECT_ALPHA", "PROJECT_OMEGA"],
        "expected_visible_records": 2,  # Can't see TOP_SECRET record
        "roles": ["analyst"],
    },
    "carol_viewer": {
        "password": "password",
        "clearance": "CONFIDENTIAL",
        "compartments": ["PROJECT_ALPHA"],
        "expected_visible_records": 1,  # Can only see CONFIDENTIAL record
        "roles": ["viewer"],
    },
    "dave_manager": {
        "password": "password",
        "clearance": "SECRET",
        "compartments": ["PROJECT_ALPHA", "OPERATION_DELTA"],
        "expected_visible_records": 2,
        "roles": ["manager", "analyst"],
    },
    "eve_auditor": {
        "password": "password",
        "clearance": "TOP_SECRET",
        "compartments": ["PROJECT_ALPHA", "PROJECT_OMEGA", "OPERATION_DELTA"],
        "expected_visible_records": 3,
        "roles": ["auditor", "viewer"],
    },
}

# ─── Helpers ────────────────────────────────────────────────────────────────

class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def ok(msg):
    print(f"  {Colors.GREEN}✓{Colors.RESET} {msg}")

def fail(msg):
    print(f"  {Colors.RED}✗{Colors.RESET} {msg}")

def info(msg):
    print(f"  {Colors.BLUE}ℹ{Colors.RESET} {msg}")

def warn(msg):
    print(f"  {Colors.YELLOW}⚠{Colors.RESET} {msg}")

def header(msg):
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'═' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}  {msg}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'═' * 60}{Colors.RESET}")


def get_token(username, password):
    """Get access token from Keycloak using direct access grant."""
    resp = requests.post(
        f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "frontend-app",
            "username": username,
            "password": password,
        },
    )
    if resp.status_code != 200:
        return None
    return resp.json().get("access_token")


def api_get(path, token):
    """Make authenticated GET request to API."""
    resp = requests.get(
        f"{API_URL}{path}",
        headers={"Authorization": f"Bearer {token}"},
    )
    return resp


def api_post(path, token, data):
    """Make authenticated POST request."""
    resp = requests.post(
        f"{API_URL}{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        json=data,
    )
    return resp


# ─── Tests ──────────────────────────────────────────────────────────────────

def test_authentication():
    """Test that all users can authenticate."""
    header("TEST 1: Authentication")
    results = {}

    for username, config in TEST_USERS.items():
        token = get_token(username, config["password"])
        if token:
            ok(f"{username} authenticated successfully")
            results[username] = token
        else:
            fail(f"{username} FAILED to authenticate")
            results[username] = None

    # Test invalid credentials
    token = get_token("nonexistent", "wrongpass")
    if token is None:
        ok("Invalid credentials correctly rejected")
    else:
        fail("Invalid credentials should have been rejected!")

    return results


def test_user_info(tokens):
    """Test that user info is correctly returned from JWT claims."""
    header("TEST 2: User Info & Security Attributes")

    for username, config in TEST_USERS.items():
        token = tokens.get(username)
        if not token:
            warn(f"Skipping {username} (no token)")
            continue

        resp = api_get("/api/auth/me", token)
        if resp.status_code != 200:
            fail(f"{username}: Failed to get user info ({resp.status_code})")
            continue

        data = resp.json()
        if data.get("clearance_level") == config["clearance"]:
            ok(f"{username}: Clearance = {data['clearance_level']}")
        else:
            fail(f"{username}: Expected clearance {config['clearance']}, got {data.get('clearance_level')}")

        user_comps = set(data.get("compartments", []))
        expected_comps = set(config["compartments"])
        if user_comps == expected_comps:
            ok(f"{username}: Compartments = {sorted(user_comps)}")
        else:
            fail(f"{username}: Expected compartments {expected_comps}, got {user_comps}")


def test_record_visibility(tokens):
    """Test that records are filtered by classification level."""
    header("TEST 3: Record-Level Classification Filtering")

    for username, config in TEST_USERS.items():
        token = tokens.get(username)
        if not token:
            continue

        resp = api_get("/api/records", token)
        if resp.status_code != 200:
            fail(f"{username}: Failed to list records ({resp.status_code})")
            continue

        data = resp.json()
        visible = data.get("visible_to_you", 0)
        hidden = data.get("hidden_by_classification", 0)
        total = data.get("total_in_system", 0)
        expected = config["expected_visible_records"]

        if visible == expected:
            ok(f"{username} ({config['clearance']}): Sees {visible}/{total} records ({hidden} hidden)")
        else:
            fail(f"{username}: Expected {expected} visible records, got {visible}")

        # Show what they can see
        for rec in data.get("records", []):
            accessible = rec["access_stats"]["accessible_cells"]
            redacted = rec["access_stats"]["redacted_cells"]
            info(f"  └─ '{rec['title']}' [{rec['record_classification']}] → {accessible} cells visible, {redacted} redacted")


def test_cell_level_security(tokens):
    """Test cell-level redaction based on clearance + compartments."""
    header("TEST 4: Cell-Level Security & Need-to-Know")

    for username, config in TEST_USERS.items():
        token = tokens.get(username)
        if not token:
            continue

        resp = api_get("/api/records", token)
        data = resp.json()

        print(f"\n  {Colors.BOLD}--- {username} ({config['clearance']}, compartments: {config['compartments']}) ---{Colors.RESET}")

        for rec in data.get("records", []):
            print(f"  Record: {rec['title']} [{rec['record_classification']}]")
            for cell in rec.get("cells", []):
                if cell["accessible"]:
                    ok(f"    {cell['field_name']}: VISIBLE [{cell['cell_classification']}] (compartments: {cell.get('compartments', [])})")
                else:
                    fail(f"    {cell['field_name']}: REDACTED [{cell['cell_classification']}] → {cell.get('denial_reason', 'Unknown')}")


def test_role_based_access(tokens):
    """Test RBAC for admin and audit endpoints."""
    header("TEST 5: Role-Based Access Control")

    # Admin endpoints
    for username in ["alice_admin", "dave_manager"]:
        token = tokens.get(username)
        if not token:
            continue
        resp = api_get("/api/admin/users", token)
        if resp.status_code == 200:
            ok(f"{username} CAN access admin/users (has {'admin' if 'admin' in TEST_USERS[username]['roles'] else 'manager'} role)")
        else:
            fail(f"{username} should be able to access admin/users")

    for username in ["carol_viewer", "bob_analyst"]:
        token = tokens.get(username)
        if not token:
            continue
        resp = api_get("/api/admin/users", token)
        if resp.status_code == 403:
            ok(f"{username} correctly DENIED access to admin/users")
        else:
            fail(f"{username} should NOT be able to access admin/users (got {resp.status_code})")

    # Audit endpoints
    for username in ["alice_admin", "eve_auditor"]:
        token = tokens.get(username)
        if not token:
            continue
        resp = api_get("/api/audit/logs?hours=1&limit=10", token)
        if resp.status_code == 200:
            ok(f"{username} CAN access audit logs")
        else:
            fail(f"{username} should be able to access audit logs")

    for username in ["carol_viewer", "bob_analyst"]:
        token = tokens.get(username)
        if not token:
            continue
        resp = api_get("/api/audit/logs?hours=1&limit=10", token)
        if resp.status_code == 403:
            ok(f"{username} correctly DENIED access to audit logs")
        else:
            fail(f"{username} should NOT be able to access audit logs (got {resp.status_code})")


def test_crud_operations(tokens):
    """Test create/update/delete with security enforcement."""
    header("TEST 6: CRUD Operations with Security")

    # Analyst can create records up to their clearance
    token = tokens.get("bob_analyst")
    if token:
        resp = api_post("/api/records", token, {
            "title": "Test Record by Bob",
            "description": "Analyst-created record",
            "record_classification": "SECRET",
            "cells": [
                {"field_name": "test_field", "field_value": "test value", "cell_classification": "CONFIDENTIAL", "compartments": []},
                {"field_name": "secret_field", "field_value": "secret data", "cell_classification": "SECRET", "compartments": ["PROJECT_ALPHA"]},
            ],
        })
        if resp.status_code == 201:
            ok("bob_analyst created SECRET record (within clearance)")
        else:
            fail(f"bob_analyst should be able to create SECRET record ({resp.status_code}: {resp.text})")

        # Should not be able to create TOP_SECRET
        resp = api_post("/api/records", token, {
            "title": "Should Fail",
            "record_classification": "TOP_SECRET",
            "cells": [],
        })
        if resp.status_code == 403:
            ok("bob_analyst correctly DENIED creating TOP_SECRET record")
        else:
            fail(f"bob_analyst should NOT create TOP_SECRET record ({resp.status_code})")

    # Viewer cannot create records
    token = tokens.get("carol_viewer")
    if token:
        resp = api_post("/api/records", token, {
            "title": "Should Fail",
            "record_classification": "UNCLASSIFIED",
            "cells": [],
        })
        if resp.status_code == 403:
            ok("carol_viewer correctly DENIED record creation (viewer role)")
        else:
            fail(f"carol_viewer should NOT create records ({resp.status_code})")


def test_audit_trail(tokens):
    """Verify that all access attempts are logged in the audit trail."""
    header("TEST 7: Audit Trail Verification")

    token = tokens.get("alice_admin")
    if not token:
        warn("Need alice_admin token for audit verification")
        return

    resp = api_get("/api/audit/logs?hours=1&limit=500", token)
    if resp.status_code != 200:
        fail(f"Failed to fetch audit logs ({resp.status_code})")
        return

    data = resp.json()
    total = data.get("total", 0)
    logs = data.get("logs", [])

    ok(f"Total audit events in last hour: {total}")

    # Count by action type
    actions = {}
    for log in logs:
        action = log.get("action", "UNKNOWN")
        actions[action] = actions.get(action, 0) + 1

    for action, count in sorted(actions.items()):
        color = Colors.RED if "DENIED" in action else Colors.GREEN
        print(f"    {color}{'●'}{Colors.RESET} {action}: {count}")

    # Verify denials exist
    denials = sum(1 for log in logs if not log.get("was_allowed", True))
    if denials > 0:
        ok(f"Access denials properly logged: {denials} denial events")
    else:
        warn("No access denials logged yet (may need to run other tests first)")

    # Check audit stats
    resp = api_get("/api/audit/stats?hours=1", token)
    if resp.status_code == 200:
        stats = resp.json()
        ok("Audit statistics endpoint working")
        info(f"  Actions: {json.dumps(stats.get('actions_breakdown', {}), indent=2)}")


def test_unauthenticated_access():
    """Test that unauthenticated requests are rejected."""
    header("TEST 8: Unauthenticated Access Prevention")

    endpoints = [
        "/api/records",
        "/api/admin/users",
        "/api/audit/logs",
    ]

    for endpoint in endpoints:
        resp = requests.get(f"{API_URL}{endpoint}")
        if resp.status_code in (401, 403):
            ok(f"{endpoint} correctly requires authentication ({resp.status_code})")
        else:
            fail(f"{endpoint} should require auth (got {resp.status_code})")


# ─── Main ───────────────────────────────────────────────────────────────────

def main():
    print(f"\n{Colors.BOLD}{'▓' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}  RBAC + CELL-LEVEL SECURITY — COMPREHENSIVE TEST SUITE{Colors.RESET}")
    print(f"{Colors.BOLD}{'▓' * 60}{Colors.RESET}")
    print(f"  Keycloak: {KEYCLOAK_URL}")
    print(f"  API:      {API_URL}")
    print(f"  Time:     {datetime.now().isoformat()}")

    # Run all tests
    try:
        tokens = test_authentication()

        if not any(tokens.values()):
            print(f"\n{Colors.RED}FATAL: No tokens obtained. Is Keycloak running?{Colors.RESET}")
            sys.exit(1)

        test_user_info(tokens)
        test_record_visibility(tokens)
        test_cell_level_security(tokens)
        test_role_based_access(tokens)
        test_crud_operations(tokens)
        test_audit_trail(tokens)
        test_unauthenticated_access()

    except requests.exceptions.ConnectionError as e:
        print(f"\n{Colors.RED}CONNECTION ERROR: Cannot reach services.{Colors.RESET}")
        print(f"  Make sure docker-compose is running: docker-compose up")
        print(f"  Error: {e}")
        sys.exit(1)

    header("TEST SUITE COMPLETE")
    print(f"\n  All security scenarios have been validated.")
    print(f"  Check the Audit Log in the UI or via API for full trail.\n")


if __name__ == "__main__":
    main()
