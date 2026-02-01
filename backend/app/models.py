"""SQLAlchemy ORM models."""
import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Boolean, DateTime, Text, Enum, ForeignKey, ARRAY, JSON
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.database import Base
import enum


class ClassificationLevel(str, enum.Enum):
    UNCLASSIFIED = "UNCLASSIFIED"
    CONFIDENTIAL = "CONFIDENTIAL"
    SECRET = "SECRET"
    TOP_SECRET = "TOP_SECRET"


# Ordered for comparison
CLASSIFICATION_ORDER = {
    ClassificationLevel.UNCLASSIFIED: 0,
    ClassificationLevel.CONFIDENTIAL: 1,
    ClassificationLevel.SECRET: 2,
    ClassificationLevel.TOP_SECRET: 3,
}


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    keycloak_id = Column(String(255), unique=True, nullable=False)
    username = Column(String(255), nullable=False)
    email = Column(String(255))
    full_name = Column(String(500))
    organization = Column(String(255), default="Unknown")
    clearance_level = Column(
        Enum("UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP_SECRET",
             name="classification_level", create_type=False),
        default="UNCLASSIFIED"
    )
    approved_compartments = Column(ARRAY(Text), default=[])
    roles = Column(ARRAY(Text), default=[])
    is_active = Column(Boolean, default=True)
    last_login = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Record(Base):
    __tablename__ = "records"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    record_classification = Column(
        Enum("UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP_SECRET",
             name="classification_level", create_type=False),
        default="UNCLASSIFIED"
    )
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    updated_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    is_deleted = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    cells = relationship("RecordCell", back_populates="record", lazy="selectin")


class RecordCell(Base):
    __tablename__ = "record_cells"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    record_id = Column(UUID(as_uuid=True), ForeignKey("records.id", ondelete="CASCADE"))
    field_name = Column(String(255), nullable=False)
    field_value = Column(Text)
    cell_classification = Column(
        Enum("UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP_SECRET",
             name="classification_level", create_type=False),
        default="UNCLASSIFIED"
    )
    compartments = Column(ARRAY(Text), default=[])
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    record = relationship("Record", back_populates="cells")


class NeedToKnowApproval(Base):
    __tablename__ = "need_to_know_approvals"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"))
    compartment = Column(String(255), nullable=False)
    approved_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    approved_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    reason = Column(Text)
    status = Column(String(50), default="ACTIVE")


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_timestamp = Column(DateTime, default=datetime.utcnow)
    user_id = Column(UUID(as_uuid=True))
    username = Column(String(255))
    organization = Column(String(255))
    user_clearance = Column(
        Enum("UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP_SECRET",
             name="classification_level", create_type=False)
    )
    action = Column(String(50), nullable=False)
    resource_type = Column(String(100))
    resource_id = Column(UUID(as_uuid=True))
    record_title = Column(String(500))
    field_name = Column(String(255))
    classification_required = Column(
        Enum("UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP_SECRET",
             name="classification_level", create_type=False)
    )
    compartments_required = Column(ARRAY(Text))
    was_allowed = Column(Boolean, default=True)
    denial_reason = Column(Text)
    old_value = Column(Text)
    new_value = Column(Text)
    ip_address = Column(String(45))
    user_agent = Column(Text)
    request_path = Column(Text)
    request_method = Column(String(10))
    session_id = Column(String(255))
    details = Column(JSON, default={})
