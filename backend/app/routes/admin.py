"""
Admin API - User management, need-to-know approvals, system overview.
"""
from uuid import UUID, uuid4
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

from app.database import get_db
from app.auth import CurrentUser, get_current_user, require_role
from app.models import User, NeedToKnowApproval, Record, RecordCell, AuditLog
from app.audit import log_crud_event

router = APIRouter(prefix="/api/admin", tags=["Admin"])


# ─── Schemas ───────────────────────────────────────────────────────────────

class NTKApprovalRequest(BaseModel):
    user_id: str
    compartment: str
    reason: str = ""
    expires_at: Optional[str] = None


class UserUpdateRequest(BaseModel):
    clearance_level: Optional[str] = None
    is_active: Optional[bool] = None


# ─── LIST USERS ────────────────────────────────────────────────────────────

@router.get("/users")
async def list_users(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_role("manager", "admin")),
):
    """List all users with their security attributes."""
    result = await db.execute(select(User).order_by(User.username))
    users = result.scalars().all()

    return {
        "users": [
            {
                "id": str(u.id),
                "username": u.username,
                "email": u.email,
                "full_name": u.full_name,
                "organization": u.organization,
                "clearance_level": u.clearance_level,
                "approved_compartments": u.approved_compartments or [],
                "roles": u.roles or [],
                "is_active": u.is_active,
                "last_login": u.last_login.isoformat() if u.last_login else None,
            }
            for u in users
        ]
    }


# ─── UPDATE USER ──────────────────────────────────────────────────────────

@router.put("/users/{user_id}")
async def update_user(
    user_id: UUID,
    data: UserUpdateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_role("admin")),
):
    """Update user security attributes. Admin only."""
    result = await db.execute(select(User).where(User.id == user_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    changes = {}
    if data.clearance_level is not None:
        changes["clearance_level"] = {
            "old": target.clearance_level, "new": data.clearance_level
        }
        target.clearance_level = data.clearance_level
    if data.is_active is not None:
        changes["is_active"] = {"old": target.is_active, "new": data.is_active}
        target.is_active = data.is_active

    target.updated_at = datetime.utcnow()
    await db.commit()

    await log_crud_event(
        db, user, "UPDATE_USER", "user",
        resource_id=str(user_id),
        details={"target_user": target.username, "changes": changes},
        request=request,
    )

    return {"message": f"User {target.username} updated", "changes": changes}


# ─── NEED-TO-KNOW APPROVALS ──────────────────────────────────────────────

@router.get("/approvals")
async def list_approvals(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_role("manager", "admin")),
):
    """List all need-to-know approvals."""
    result = await db.execute(
        select(NeedToKnowApproval).order_by(NeedToKnowApproval.approved_at.desc())
    )
    approvals = result.scalars().all()

    # Get user names
    user_ids = set()
    for a in approvals:
        if a.user_id:
            user_ids.add(a.user_id)
        if a.approved_by:
            user_ids.add(a.approved_by)

    users_result = await db.execute(select(User).where(User.id.in_(user_ids)))
    users_map = {u.id: u.username for u in users_result.scalars().all()}

    return {
        "approvals": [
            {
                "id": str(a.id),
                "user_id": str(a.user_id),
                "username": users_map.get(a.user_id, "unknown"),
                "compartment": a.compartment,
                "approved_by": users_map.get(a.approved_by, "unknown"),
                "approved_at": a.approved_at.isoformat() if a.approved_at else None,
                "expires_at": a.expires_at.isoformat() if a.expires_at else None,
                "reason": a.reason,
                "status": a.status,
            }
            for a in approvals
        ]
    }


@router.post("/approvals")
async def create_approval(
    data: NTKApprovalRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_role("manager", "admin")),
):
    """Grant a need-to-know compartment approval. Manager+ only."""
    # Verify target user exists
    result = await db.execute(
        select(User).where(User.id == UUID(data.user_id))
    )
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    # Get approver's DB user
    approver_result = await db.execute(
        select(User).where(User.keycloak_id == user.keycloak_id)
    )
    approver = approver_result.scalar_one_or_none()

    # Check if already approved
    existing = await db.execute(
        select(NeedToKnowApproval).where(
            NeedToKnowApproval.user_id == UUID(data.user_id),
            NeedToKnowApproval.compartment == data.compartment,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=409,
            detail=f"User already has approval for {data.compartment}"
        )

    expires = None
    if data.expires_at:
        expires = datetime.fromisoformat(data.expires_at)

    approval = NeedToKnowApproval(
        id=uuid4(),
        user_id=UUID(data.user_id),
        compartment=data.compartment,
        approved_by=approver.id if approver else None,
        reason=data.reason,
        expires_at=expires,
        status="ACTIVE",
    )
    db.add(approval)

    # Update user's compartments
    if target.approved_compartments is None:
        target.approved_compartments = []
    if data.compartment not in target.approved_compartments:
        target.approved_compartments = target.approved_compartments + [data.compartment]

    await db.commit()

    await log_crud_event(
        db, user, "GRANT_NTK", "approval",
        resource_id=str(approval.id),
        details={
            "target_user": target.username,
            "compartment": data.compartment,
            "reason": data.reason,
        },
        request=request,
    )

    return {
        "message": f"Compartment {data.compartment} approved for {target.username}",
        "approval_id": str(approval.id),
    }


@router.delete("/approvals/{approval_id}")
async def revoke_approval(
    approval_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_role("manager", "admin")),
):
    """Revoke a need-to-know approval. Manager+ only."""
    result = await db.execute(
        select(NeedToKnowApproval).where(NeedToKnowApproval.id == approval_id)
    )
    approval = result.scalar_one_or_none()
    if not approval:
        raise HTTPException(status_code=404, detail="Approval not found")

    approval.status = "REVOKED"

    # Remove from user's compartments
    target_result = await db.execute(
        select(User).where(User.id == approval.user_id)
    )
    target = target_result.scalar_one_or_none()
    if target and target.approved_compartments:
        target.approved_compartments = [
            c for c in target.approved_compartments if c != approval.compartment
        ]

    await db.commit()

    await log_crud_event(
        db, user, "REVOKE_NTK", "approval",
        resource_id=str(approval_id),
        details={
            "target_user": target.username if target else "unknown",
            "compartment": approval.compartment,
        },
        request=request,
    )

    return {"message": "Approval revoked"}


# ─── SYSTEM OVERVIEW ─────────────────────────────────────────────────────

@router.get("/overview")
async def system_overview(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_role("manager", "admin", "auditor")),
):
    """System-wide security overview with statistics."""
    # Count records by classification
    records_result = await db.execute(
        select(
            Record.record_classification,
            func.count(Record.id)
        )
        .where(Record.is_deleted == False)
        .group_by(Record.record_classification)
    )
    records_by_class = dict(records_result.all())

    # Count users by clearance
    users_result = await db.execute(
        select(User.clearance_level, func.count(User.id))
        .group_by(User.clearance_level)
    )
    users_by_clearance = dict(users_result.all())

    # Count cells by classification
    cells_result = await db.execute(
        select(RecordCell.cell_classification, func.count(RecordCell.id))
        .group_by(RecordCell.cell_classification)
    )
    cells_by_class = dict(cells_result.all())

    # Recent access denials
    denials_result = await db.execute(
        select(func.count(AuditLog.id))
        .where(AuditLog.was_allowed == False)
    )
    total_denials = denials_result.scalar() or 0

    # Active approvals count
    approvals_result = await db.execute(
        select(func.count(NeedToKnowApproval.id))
        .where(NeedToKnowApproval.status == "ACTIVE")
    )
    active_approvals = approvals_result.scalar() or 0

    return {
        "records_by_classification": records_by_class,
        "users_by_clearance": users_by_clearance,
        "cells_by_classification": cells_by_class,
        "total_access_denials": total_denials,
        "active_ntk_approvals": active_approvals,
    }
