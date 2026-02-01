"""
Records API - CRUD with cell-level security enforcement.

Every access is filtered through the security engine and logged in the audit trail.
"""
from uuid import UUID, uuid4
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from sqlalchemy.orm import selectinload
from pydantic import BaseModel
from datetime import datetime

from app.database import get_db
from app.auth import CurrentUser, get_current_user, require_role
from app.models import Record, RecordCell, User
from app.security import (
    check_record_access, filter_record_cells, get_access_summary, REDACTED
)
from app.audit import log_record_access, log_cell_access_batch, log_crud_event

router = APIRouter(prefix="/api/records", tags=["Records"])


# ─── Schemas ───────────────────────────────────────────────────────────────

class CellCreate(BaseModel):
    field_name: str
    field_value: str
    cell_classification: str = "UNCLASSIFIED"
    compartments: list[str] = []


class RecordCreate(BaseModel):
    title: str
    description: str = ""
    record_classification: str = "UNCLASSIFIED"
    cells: list[CellCreate] = []


class CellUpdate(BaseModel):
    field_name: str
    field_value: Optional[str] = None
    cell_classification: Optional[str] = None
    compartments: Optional[list[str]] = None


class RecordUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    record_classification: Optional[str] = None
    cells: Optional[list[CellUpdate]] = None


# ─── Helper: sync user from Keycloak to app DB ────────────────────────────

async def ensure_user_synced(db: AsyncSession, user: CurrentUser) -> User:
    """Ensure the Keycloak user exists in the app database."""
    result = await db.execute(
        select(User).where(User.keycloak_id == user.keycloak_id)
    )
    db_user = result.scalar_one_or_none()

    if db_user:
        # Update last login and attributes
        db_user.last_login = datetime.utcnow()
        db_user.clearance_level = user.clearance_level
        db_user.approved_compartments = user.compartments
        db_user.roles = user.roles
        db_user.organization = user.organization
        await db.commit()
        return db_user

    # Create new user record
    db_user = User(
        id=uuid4(),
        keycloak_id=user.keycloak_id,
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        organization=user.organization,
        clearance_level=user.clearance_level,
        approved_compartments=user.compartments,
        roles=user.roles,
        last_login=datetime.utcnow(),
    )
    db.add(db_user)
    await db.commit()
    return db_user


# ─── LIST RECORDS ──────────────────────────────────────────────────────────

@router.get("")
async def list_records(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """
    List all records the user has clearance to see.
    Records above the user's clearance are invisible.
    """
    await ensure_user_synced(db, user)

    result = await db.execute(
        select(Record)
        .where(Record.is_deleted == False)
        .options(selectinload(Record.cells))
        .order_by(Record.created_at.desc())
    )
    records = result.scalars().all()

    visible_records = []
    for record in records:
        allowed, reason = check_record_access(user, record.record_classification)

        if not allowed:
            # Log the denied access attempt
            await log_record_access(
                db, user, str(record.id), record.title,
                was_allowed=False, denial_reason=reason, request=request,
            )
            continue

        # Record is visible - now filter cells
        cells_data = [
            {
                "id": str(c.id),
                "field_name": c.field_name,
                "field_value": c.field_value,
                "cell_classification": c.cell_classification,
                "compartments": c.compartments or [],
            }
            for c in record.cells
        ]

        filtered_cells, cell_log = filter_record_cells(
            user, cells_data, record.title
        )

        # Log all cell access attempts
        await log_cell_access_batch(
            db, user, str(record.id), record.title, cell_log, request
        )

        # Count access stats
        total_cells = len(filtered_cells)
        accessible_cells = sum(1 for c in filtered_cells if c["accessible"])

        visible_records.append({
            "id": str(record.id),
            "title": record.title,
            "description": record.description,
            "record_classification": record.record_classification,
            "cells": filtered_cells,
            "access_stats": {
                "total_cells": total_cells,
                "accessible_cells": accessible_cells,
                "redacted_cells": total_cells - accessible_cells,
            },
            "created_at": record.created_at.isoformat() if record.created_at else None,
            "updated_at": record.updated_at.isoformat() if record.updated_at else None,
        })

    # Log the list operation
    await log_crud_event(
        db, user, "LIST_RECORDS", "record",
        details={
            "total_records": len(records),
            "visible_records": len(visible_records),
            "hidden_records": len(records) - len(visible_records),
        },
        request=request,
    )

    return {
        "records": visible_records,
        "access_summary": get_access_summary(user),
        "total_in_system": len(records),
        "visible_to_you": len(visible_records),
        "hidden_by_classification": len(records) - len(visible_records),
    }


# ─── GET SINGLE RECORD ────────────────────────────────────────────────────

@router.get("/{record_id}")
async def get_record(
    record_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Get a single record with cell-level security applied."""
    result = await db.execute(
        select(Record)
        .where(Record.id == record_id, Record.is_deleted == False)
        .options(selectinload(Record.cells))
    )
    record = result.scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")

    # Check record-level access
    allowed, reason = check_record_access(user, record.record_classification)
    await log_record_access(
        db, user, str(record.id), record.title,
        was_allowed=allowed, denial_reason=reason if not allowed else None,
        request=request,
    )

    if not allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Access denied: {reason}"
        )

    # Filter cells
    cells_data = [
        {
            "id": str(c.id),
            "field_name": c.field_name,
            "field_value": c.field_value,
            "cell_classification": c.cell_classification,
            "compartments": c.compartments or [],
        }
        for c in record.cells
    ]

    filtered_cells, cell_log = filter_record_cells(user, cells_data, record.title)
    await log_cell_access_batch(
        db, user, str(record.id), record.title, cell_log, request
    )

    total_cells = len(filtered_cells)
    accessible_cells = sum(1 for c in filtered_cells if c["accessible"])

    return {
        "id": str(record.id),
        "title": record.title,
        "description": record.description,
        "record_classification": record.record_classification,
        "cells": filtered_cells,
        "access_stats": {
            "total_cells": total_cells,
            "accessible_cells": accessible_cells,
            "redacted_cells": total_cells - accessible_cells,
        },
        "created_at": record.created_at.isoformat() if record.created_at else None,
        "updated_at": record.updated_at.isoformat() if record.updated_at else None,
    }


# ─── CREATE RECORD ────────────────────────────────────────────────────────

@router.post("", status_code=201)
async def create_record(
    data: RecordCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_role("analyst", "manager", "admin")),
):
    """Create a new record with cells. Requires analyst+ role."""
    db_user = await ensure_user_synced(db, user)

    # User can only create records up to their clearance
    from app.security import clearance_rank
    if clearance_rank(data.record_classification) > clearance_rank(user.clearance_level):
        raise HTTPException(
            status_code=403,
            detail="Cannot create records above your clearance level"
        )

    record = Record(
        id=uuid4(),
        title=data.title,
        description=data.description,
        record_classification=data.record_classification,
        created_by=db_user.id,
    )
    db.add(record)

    for cell_data in data.cells:
        cell = RecordCell(
            id=uuid4(),
            record_id=record.id,
            field_name=cell_data.field_name,
            field_value=cell_data.field_value,
            cell_classification=cell_data.cell_classification,
            compartments=cell_data.compartments,
        )
        db.add(cell)

    await db.commit()

    await log_crud_event(
        db, user, "CREATE", "record",
        resource_id=str(record.id),
        record_title=data.title,
        details={
            "classification": data.record_classification,
            "cell_count": len(data.cells),
        },
        request=request,
    )

    return {
        "id": str(record.id),
        "title": record.title,
        "message": "Record created successfully",
    }


# ─── UPDATE RECORD ────────────────────────────────────────────────────────

@router.put("/{record_id}")
async def update_record(
    record_id: UUID,
    data: RecordUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_role("analyst", "manager", "admin")),
):
    """Update a record. Requires analyst+ role and proper clearance."""
    result = await db.execute(
        select(Record).where(Record.id == record_id, Record.is_deleted == False)
        .options(selectinload(Record.cells))
    )
    record = result.scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")

    # Check record-level access
    allowed, reason = check_record_access(user, record.record_classification)
    if not allowed:
        await log_crud_event(
            db, user, "UPDATE_DENIED", "record",
            resource_id=str(record.id),
            record_title=record.title,
            details={"reason": reason},
            request=request,
        )
        raise HTTPException(status_code=403, detail=f"Access denied: {reason}")

    db_user = await ensure_user_synced(db, user)
    changes = {}

    if data.title is not None:
        changes["title"] = {"old": record.title, "new": data.title}
        record.title = data.title
    if data.description is not None:
        changes["description"] = {"old": record.description, "new": data.description}
        record.description = data.description
    if data.record_classification is not None:
        changes["classification"] = {
            "old": record.record_classification,
            "new": data.record_classification,
        }
        record.record_classification = data.record_classification

    record.updated_by = db_user.id
    record.updated_at = datetime.utcnow()

    # Update cells if provided
    if data.cells:
        for cell_update in data.cells:
            # Find existing cell
            existing = next(
                (c for c in record.cells if c.field_name == cell_update.field_name),
                None,
            )
            if existing:
                # Check cell-level access before allowing update
                from app.security import check_cell_access
                cell_allowed, cell_reason = check_cell_access(
                    user, existing.cell_classification, existing.compartments or []
                )
                if not cell_allowed:
                    await log_crud_event(
                        db, user, "CELL_UPDATE_DENIED", "cell",
                        resource_id=str(record.id),
                        field_name=cell_update.field_name,
                        details={"reason": cell_reason},
                        request=request,
                    )
                    continue  # Skip cells user can't access

                old_val = existing.field_value
                if cell_update.field_value is not None:
                    existing.field_value = cell_update.field_value
                if cell_update.cell_classification is not None:
                    existing.cell_classification = cell_update.cell_classification
                if cell_update.compartments is not None:
                    existing.compartments = cell_update.compartments
                existing.updated_at = datetime.utcnow()

                changes[f"cell:{cell_update.field_name}"] = {
                    "old": old_val,
                    "new": cell_update.field_value,
                }

    await db.commit()

    await log_crud_event(
        db, user, "UPDATE", "record",
        resource_id=str(record.id),
        record_title=record.title,
        details={"changes": changes},
        request=request,
    )

    return {"message": "Record updated", "changes": list(changes.keys())}


# ─── DELETE RECORD ─────────────────────────────────────────────────────────

@router.delete("/{record_id}")
async def delete_record(
    record_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(require_role("manager", "admin")),
):
    """Soft-delete a record. Requires manager+ role."""
    result = await db.execute(
        select(Record).where(Record.id == record_id, Record.is_deleted == False)
    )
    record = result.scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")

    allowed, reason = check_record_access(user, record.record_classification)
    if not allowed:
        raise HTTPException(status_code=403, detail=f"Access denied: {reason}")

    record.is_deleted = True
    record.updated_at = datetime.utcnow()
    await db.commit()

    await log_crud_event(
        db, user, "DELETE", "record",
        resource_id=str(record.id),
        record_title=record.title,
        request=request,
    )

    return {"message": "Record deleted"}


# ─── ACCESS SUMMARY ──────────────────────────────────────────────────────

@router.get("/me/access-summary")
async def my_access_summary(
    user: CurrentUser = Depends(get_current_user),
):
    """Get a summary of the current user's access level."""
    return get_access_summary(user)
