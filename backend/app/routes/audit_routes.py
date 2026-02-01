"""
Audit Log API - Query and filter the comprehensive audit trail.
"""
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, text
from datetime import datetime, timedelta

from app.database import get_db
from app.auth import CurrentUser, require_role
from app.models import AuditLog

router = APIRouter(prefix="/api/audit", tags=["Audit"])


@router.get("/logs")
async def get_audit_logs(
    action: Optional[str] = Query(None, description="Filter by action type"),
    username: Optional[str] = Query(None, description="Filter by username"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    was_allowed: Optional[bool] = Query(None, description="Filter by access result"),
    hours: int = Query(24, description="How many hours back to look"),
    limit: int = Query(100, description="Max results", le=500),
    offset: int = Query(0, description="Offset for pagination"),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_role("auditor", "admin")),
):
    """
    Query audit logs with filters. Requires auditor or admin role.
    """
    since = datetime.utcnow() - timedelta(hours=hours)

    query = (
        select(AuditLog)
        .where(AuditLog.event_timestamp >= since)
        .order_by(desc(AuditLog.event_timestamp))
    )

    if action:
        query = query.where(AuditLog.action == action)
    if username:
        query = query.where(AuditLog.username == username)
    if resource_type:
        query = query.where(AuditLog.resource_type == resource_type)
    if was_allowed is not None:
        query = query.where(AuditLog.was_allowed == was_allowed)

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    # Apply pagination
    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    logs = result.scalars().all()

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "logs": [
            {
                "id": str(log.id),
                "timestamp": log.event_timestamp.isoformat() if log.event_timestamp else None,
                "username": log.username,
                "organization": log.organization,
                "user_clearance": log.user_clearance,
                "action": log.action,
                "resource_type": log.resource_type,
                "resource_id": str(log.resource_id) if log.resource_id else None,
                "record_title": log.record_title,
                "field_name": log.field_name,
                "classification_required": log.classification_required,
                "compartments_required": log.compartments_required,
                "was_allowed": log.was_allowed,
                "denial_reason": log.denial_reason,
                "ip_address": log.ip_address,
                "request_method": log.request_method,
                "request_path": log.request_path,
            }
            for log in logs
        ],
    }


@router.get("/stats")
async def audit_stats(
    hours: int = Query(24, description="How many hours back"),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_role("auditor", "admin")),
):
    """Audit statistics summary."""
    since = datetime.utcnow() - timedelta(hours=hours)

    # Actions breakdown
    actions_result = await db.execute(
        select(AuditLog.action, func.count(AuditLog.id))
        .where(AuditLog.event_timestamp >= since)
        .group_by(AuditLog.action)
    )
    actions = dict(actions_result.all())

    # Denials by user
    denials_result = await db.execute(
        select(AuditLog.username, func.count(AuditLog.id))
        .where(AuditLog.event_timestamp >= since, AuditLog.was_allowed == False)
        .group_by(AuditLog.username)
    )
    denials_by_user = dict(denials_result.all())

    # Activity by user
    activity_result = await db.execute(
        select(AuditLog.username, func.count(AuditLog.id))
        .where(AuditLog.event_timestamp >= since)
        .group_by(AuditLog.username)
    )
    activity_by_user = dict(activity_result.all())

    # Access by classification
    class_result = await db.execute(
        select(AuditLog.classification_required, func.count(AuditLog.id))
        .where(
            AuditLog.event_timestamp >= since,
            AuditLog.classification_required.isnot(None)
        )
        .group_by(AuditLog.classification_required)
    )
    by_classification = dict(class_result.all())

    return {
        "period_hours": hours,
        "actions_breakdown": actions,
        "denials_by_user": denials_by_user,
        "activity_by_user": activity_by_user,
        "access_by_classification": by_classification,
    }


@router.get("/denials")
async def recent_denials(
    limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_role("auditor", "admin")),
):
    """Get recent access denials for security review."""
    result = await db.execute(
        select(AuditLog)
        .where(AuditLog.was_allowed == False)
        .order_by(desc(AuditLog.event_timestamp))
        .limit(limit)
    )
    logs = result.scalars().all()

    return {
        "denials": [
            {
                "timestamp": log.event_timestamp.isoformat() if log.event_timestamp else None,
                "username": log.username,
                "organization": log.organization,
                "user_clearance": log.user_clearance,
                "action": log.action,
                "record_title": log.record_title,
                "field_name": log.field_name,
                "classification_required": log.classification_required,
                "compartments_required": log.compartments_required,
                "denial_reason": log.denial_reason,
                "ip_address": log.ip_address,
            }
            for log in logs
        ]
    }
