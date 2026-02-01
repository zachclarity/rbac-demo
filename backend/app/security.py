"""
Cell-Level Security Engine

Implements the core security model:
1. Record-level classification: Determines if user can SEE a record at all
2. Cell-level classification: Determines if user can see individual fields
3. Need-to-know compartments: Additional access restriction per cell
4. Combined: User must have BOTH sufficient clearance AND all required compartments
"""
from app.models import ClassificationLevel, CLASSIFICATION_ORDER
from app.auth import CurrentUser

# ─── Redaction marker ──────────────────────────────────────────────────────
REDACTED = "[REDACTED]"
CLASSIFICATION_DENIED = "INSUFFICIENT_CLEARANCE"
COMPARTMENT_DENIED = "NEED_TO_KNOW_REQUIRED"


def clearance_rank(level: str) -> int:
    """Get numeric rank for a classification level."""
    mapping = {
        "UNCLASSIFIED": 0,
        "CONFIDENTIAL": 1,
        "SECRET": 2,
        "TOP_SECRET": 3,
    }
    return mapping.get(level, -1)


def can_access_classification(user_clearance: str, required: str) -> bool:
    """Check if user's clearance level meets or exceeds the required level."""
    return clearance_rank(user_clearance) >= clearance_rank(required)


def has_compartment_access(user_compartments: list[str], required: list[str]) -> bool:
    """Check if user has ALL required need-to-know compartments."""
    if not required:
        return True
    return all(comp in user_compartments for comp in required)


def check_record_access(user: CurrentUser, record_classification: str) -> tuple[bool, str]:
    """
    Check if user can access a record at all (record-level security).

    Returns: (allowed, reason)
    """
    if can_access_classification(user.clearance_level, record_classification):
        return True, "ACCESS_GRANTED"
    return False, f"User clearance {user.clearance_level} insufficient for {record_classification} record"


def check_cell_access(
    user: CurrentUser,
    cell_classification: str,
    cell_compartments: list[str],
) -> tuple[bool, str]:
    """
    Check if user can access a specific cell (cell-level security).

    Both classification AND compartment checks must pass.
    Returns: (allowed, denial_reason)
    """
    # Check 1: Classification level
    if not can_access_classification(user.clearance_level, cell_classification):
        return False, CLASSIFICATION_DENIED

    # Check 2: Need-to-know compartments
    if not has_compartment_access(user.compartments, cell_compartments):
        missing = [c for c in cell_compartments if c not in user.compartments]
        return False, f"{COMPARTMENT_DENIED}: missing [{', '.join(missing)}]"

    return True, "ACCESS_GRANTED"


def filter_record_cells(
    user: CurrentUser,
    cells: list[dict],
    record_title: str = "",
) -> tuple[list[dict], list[dict]]:
    """
    Filter cells based on user's clearance and compartments.

    Returns: (visible_cells, access_log_entries)

    Each visible cell includes its classification info.
    Denied cells are replaced with redaction markers.
    """
    result = []
    access_log = []

    for cell in cells:
        cell_class = cell.get("cell_classification", "UNCLASSIFIED")
        cell_comps = cell.get("compartments", [])
        field_name = cell.get("field_name", "")

        allowed, reason = check_cell_access(user, cell_class, cell_comps)

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
                "field_value": cell.get("field_value"),
                "cell_classification": cell_class,
                "compartments": cell_comps,
                "accessible": True,
            })
        else:
            result.append({
                "id": str(cell.get("id", "")),
                "field_name": field_name,
                "field_value": REDACTED,
                "cell_classification": cell_class,
                "compartments": [REDACTED],
                "accessible": False,
                "denial_reason": reason,
            })

    return result, access_log


def get_access_summary(user: CurrentUser) -> dict:
    """Generate a summary of what the user can access."""
    max_class = user.clearance_level
    return {
        "username": user.username,
        "organization": user.organization,
        "clearance_level": max_class,
        "max_record_classification": max_class,
        "approved_compartments": user.compartments,
        "roles": user.roles,
        "can_view_unclassified": True,
        "can_view_confidential": clearance_rank(max_class) >= 1,
        "can_view_secret": clearance_rank(max_class) >= 2,
        "can_view_top_secret": clearance_rank(max_class) >= 3,
    }
