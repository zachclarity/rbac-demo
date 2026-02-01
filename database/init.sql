-- ============================================================================
-- RBAC + Cell-Level Security Database Schema
-- ============================================================================

-- Classification levels (ordered by sensitivity)
CREATE TYPE classification_level AS ENUM (
    'UNCLASSIFIED',
    'CONFIDENTIAL',
    'SECRET',
    'TOP_SECRET'
);

-- ─── Users (synced from Keycloak on first login) ──────────────────────────
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    keycloak_id     VARCHAR(255) UNIQUE NOT NULL,
    username        VARCHAR(255) NOT NULL,
    email           VARCHAR(255),
    full_name       VARCHAR(500),
    organization    VARCHAR(255) DEFAULT 'Unknown',
    clearance_level classification_level DEFAULT 'UNCLASSIFIED',
    approved_compartments TEXT[] DEFAULT '{}',
    roles           TEXT[] DEFAULT '{}',
    is_active       BOOLEAN DEFAULT TRUE,
    last_login      TIMESTAMP,
    created_at      TIMESTAMP DEFAULT NOW(),
    updated_at      TIMESTAMP DEFAULT NOW()
);

-- ─── Records (top-level items with overall classification) ────────────────
CREATE TABLE records (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title                   VARCHAR(500) NOT NULL,
    description             TEXT,
    record_classification   classification_level NOT NULL DEFAULT 'UNCLASSIFIED',
    created_by              UUID REFERENCES users(id),
    updated_by              UUID REFERENCES users(id),
    is_deleted              BOOLEAN DEFAULT FALSE,
    created_at              TIMESTAMP DEFAULT NOW(),
    updated_at              TIMESTAMP DEFAULT NOW()
);

-- ─── Record Cells (individual fields with cell-level security) ────────────
CREATE TABLE record_cells (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    record_id           UUID REFERENCES records(id) ON DELETE CASCADE,
    field_name          VARCHAR(255) NOT NULL,
    field_value         TEXT,
    cell_classification classification_level NOT NULL DEFAULT 'UNCLASSIFIED',
    compartments        TEXT[] DEFAULT '{}',
    created_at          TIMESTAMP DEFAULT NOW(),
    updated_at          TIMESTAMP DEFAULT NOW(),
    UNIQUE(record_id, field_name)
);

-- ─── Need-to-Know Approvals ──────────────────────────────────────────────
CREATE TABLE need_to_know_approvals (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID REFERENCES users(id) ON DELETE CASCADE,
    compartment     VARCHAR(255) NOT NULL,
    approved_by     UUID REFERENCES users(id),
    approved_at     TIMESTAMP DEFAULT NOW(),
    expires_at      TIMESTAMP,
    reason          TEXT,
    status          VARCHAR(50) DEFAULT 'ACTIVE',
    UNIQUE(user_id, compartment)
);

-- ─── Comprehensive Audit Log ─────────────────────────────────────────────
CREATE TABLE audit_log (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_timestamp         TIMESTAMP DEFAULT NOW(),
    user_id                 UUID,
    username                VARCHAR(255),
    organization            VARCHAR(255),
    user_clearance          classification_level,
    action                  VARCHAR(50) NOT NULL,
    resource_type           VARCHAR(100),
    resource_id             UUID,
    record_title            VARCHAR(500),
    field_name              VARCHAR(255),
    classification_required classification_level,
    compartments_required   TEXT[],
    was_allowed             BOOLEAN DEFAULT TRUE,
    denial_reason           TEXT,
    old_value               TEXT,
    new_value               TEXT,
    ip_address              VARCHAR(45),
    user_agent              TEXT,
    request_path            TEXT,
    request_method          VARCHAR(10),
    session_id              VARCHAR(255),
    details                 JSONB DEFAULT '{}'
);

-- Indexes for audit log performance
CREATE INDEX idx_audit_timestamp ON audit_log(event_timestamp DESC);
CREATE INDEX idx_audit_user ON audit_log(user_id);
CREATE INDEX idx_audit_action ON audit_log(action);
CREATE INDEX idx_audit_resource ON audit_log(resource_type, resource_id);
CREATE INDEX idx_audit_allowed ON audit_log(was_allowed);
CREATE INDEX idx_audit_classification ON audit_log(classification_required);

-- Indexes for data queries
CREATE INDEX idx_records_classification ON records(record_classification);
CREATE INDEX idx_cells_record ON record_cells(record_id);
CREATE INDEX idx_cells_classification ON record_cells(cell_classification);
CREATE INDEX idx_users_keycloak ON users(keycloak_id);
CREATE INDEX idx_ntk_user ON need_to_know_approvals(user_id);

-- ============================================================================
-- SEED DATA: Demo records with varied classification and compartments
-- ============================================================================

-- We'll insert seed users/data via the setup container after Keycloak is ready.
-- The setup script creates users linked to Keycloak IDs and demo records.

-- Helper function: Check if a user can access a classification level
CREATE OR REPLACE FUNCTION can_access_classification(
    user_clearance classification_level,
    required_classification classification_level
) RETURNS BOOLEAN AS $$
BEGIN
    RETURN CASE user_clearance
        WHEN 'TOP_SECRET' THEN TRUE
        WHEN 'SECRET' THEN required_classification IN ('UNCLASSIFIED', 'CONFIDENTIAL', 'SECRET')
        WHEN 'CONFIDENTIAL' THEN required_classification IN ('UNCLASSIFIED', 'CONFIDENTIAL')
        WHEN 'UNCLASSIFIED' THEN required_classification = 'UNCLASSIFIED'
        ELSE FALSE
    END;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- Helper function: Check if user has all required compartments
CREATE OR REPLACE FUNCTION has_compartments(
    user_compartments TEXT[],
    required_compartments TEXT[]
) RETURNS BOOLEAN AS $$
BEGIN
    IF required_compartments IS NULL OR array_length(required_compartments, 1) IS NULL THEN
        RETURN TRUE;
    END IF;
    RETURN required_compartments <@ user_compartments;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- View for easy audit reporting
CREATE OR REPLACE VIEW audit_summary AS
SELECT
    event_timestamp,
    username,
    organization,
    action,
    resource_type,
    record_title,
    field_name,
    classification_required::TEXT,
    compartments_required,
    was_allowed,
    denial_reason,
    ip_address
FROM audit_log
ORDER BY event_timestamp DESC;
