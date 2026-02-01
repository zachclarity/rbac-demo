"""
Comprehensive Audit Logging

Logs every data access, modification, and denied access attempt.
All CRUD operations and security events are recorded.
"""
from datetime import datetime
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.auth import CurrentUser
from app.models import AuditLog


async def log_event(
    db: AsyncSession,
    user: Optional[CurrentUser],
    action: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    record_title: Optional[str] = None,
    field_name: Optional[str] = None,
    classification_required: Optional[str] = None,
    compartments_required: Optional[list] = None,
    was_allowed: bool = True,
    denial_reason: Optional[str] = None,
    old_value: Optional[str] = None,
    new_value: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    request_path: Optional[str] = None,
    request_method: Optional[str] = None,
    session_id: Optional[str] = None,
    details: Optional[dict] = None,
):
    """Write an audit log entry using ORM."""
    username = "anonymous"
    organization = "Unknown"
    clearance = None

    if user:
        username = user.username
        organization = user.organization
        clearance = user.clearance_level

    entry = AuditLog(
        event_timestamp=datetime.utcnow(),
        user_id=None,
        username=username,
        organization=organization,
        user_clearance=clearance,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        record_title=record_title,
        field_name=field_name,
        classification_required=classification_required,
        compartments_required=compartments_required if compartments_required else None,
        was_allowed=was_allowed,
        denial_reason=denial_reason,
        old_value=old_value,
        new_value=new_value,
        ip_address=ip_address,
        user_agent=user_agent,
        request_path=request_path,
        request_method=request_method,
        session_id=session_id,
        details=details if details else None,
    )

    db.add(entry)
    await db.commit()


async def log_record_access(
    db: AsyncSession,
    user: CurrentUser,
    record_id: str,
    record_title: str,
    was_allowed: bool,
    denial_reason: Optional[str] = None,
    request: Optional[object] = None,
):
    """Log a record-level access attempt."""
    ip = None
    ua = None
    path = None
    method = None
    if request:
        ip = getattr(request.client, "host", None) if request.client else None
        ua = request.headers.get("user-agent", "")
        path = str(request.url.path)
        method = request.method

    await log_event(
        db=db,
        user=user,
        action="READ_RECORD" if was_allowed else "ACCESS_DENIED",
        resource_type="record",
        resource_id=record_id,
        record_title=record_title,
        was_allowed=was_allowed,
        denial_reason=denial_reason,
        ip_address=ip,
        user_agent=ua,
        request_path=path,
        request_method=method,
    )


async def log_cell_access_batch(
    db: AsyncSession,
    user: CurrentUser,
    record_id: str,
    record_title: str,
    cell_access_log: list[dict],
    request: Optional[object] = None,
):
    """Log multiple cell access attempts in a batch."""
    ip = None
    ua = None
    path = None
    method = None
    if request:
        ip = getattr(request.client, "host", None) if request.client else None
        ua = request.headers.get("user-agent", "")
        path = str(request.url.path)
        method = request.method

    for entry in cell_access_log:
        await log_event(
            db=db,
            user=user,
            action="READ_CELL" if entry["was_allowed"] else "CELL_ACCESS_DENIED",
            resource_type="cell",
            resource_id=record_id,
            record_title=record_title,
            field_name=entry["field_name"],
            classification_required=entry["classification_required"],
            compartments_required=entry["compartments_required"],
            was_allowed=entry["was_allowed"],
            denial_reason=entry.get("denial_reason"),
            ip_address=ip,
            user_agent=ua,
            request_path=path,
            request_method=method,
        )


async def log_crud_event(
    db: AsyncSession,
    user: CurrentUser,
    action: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    record_title: Optional[str] = None,
    field_name: Optional[str] = None,
    old_value: Optional[str] = None,
    new_value: Optional[str] = None,
    details: Optional[dict] = None,
    request: Optional[object] = None,
):
    """Log a CRUD operation."""
    ip = None
    ua = None
    path = None
    method = None
    if request:
        ip = getattr(request.client, "host", None) if request.client else None
        ua = request.headers.get("user-agent", "")
        path = str(request.url.path)
        method = request.method

    await log_event(
        db=db,
        user=user,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        record_title=record_title,
        field_name=field_name,
        was_allowed=True,
        old_value=old_value,
        new_value=new_value,
        details=details,
        ip_address=ip,
        user_agent=ua,
        request_path=path,
        request_method=method,
    )