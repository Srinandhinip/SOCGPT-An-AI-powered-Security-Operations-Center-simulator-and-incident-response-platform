-- ============================================================
-- SOCGPT — Full Database Schema
-- Postgres 15+ (requires pgvector extension for RAG embeddings)
-- ============================================================

CREATE EXTENSION IF NOT EXISTS vector;   -- for RAG (incident_embeddings)
CREATE EXTENSION IF NOT EXISTS pgcrypto; -- for gen_random_uuid() if needed

-- ------------------------------------------------------------
-- 1. USERS & ROLES  (role-based access)
-- ------------------------------------------------------------
CREATE TABLE users (
    user_id       SERIAL PRIMARY KEY,
    username      VARCHAR(50) UNIQUE NOT NULL,
    email         VARCHAR(120) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          VARCHAR(20) NOT NULL DEFAULT 'analyst'
                  CHECK (role IN ('analyst', 'soc_manager', 'admin')),
    created_at    TIMESTAMP DEFAULT now()
);

-- ------------------------------------------------------------
-- 2. RAW SECURITY EVENTS  (from Attack Simulator / Detection Engine)
-- ------------------------------------------------------------
CREATE TABLE security_events (
    event_id     SERIAL PRIMARY KEY,
    source_ip    VARCHAR(45) NOT NULL,
    event_type   VARCHAR(50) NOT NULL,       -- e.g. 'recon', 'brute_force', 'sqli'
    mitre_id     VARCHAR(10),                -- e.g. 'T1110'
    stage_order  INT,                        -- position in an attack chain, if any
    raw_payload  JSONB,                      -- raw log/event data for evidence
    detected_at  TIMESTAMP DEFAULT now()
);

CREATE INDEX idx_events_ip_time
    ON security_events (source_ip, detected_at);

-- ------------------------------------------------------------
-- 3. INCIDENT CHAINS  (multi-stage attack chains)
-- ------------------------------------------------------------
CREATE TABLE incident_chains (
    chain_id      SERIAL PRIMARY KEY,
    description   TEXT,                      -- LLM-generated attack path summary
    overall_risk  INT CHECK (overall_risk BETWEEN 0 AND 100),
    status        VARCHAR(20) DEFAULT 'ACTIVE'
                  CHECK (status IN ('ACTIVE', 'CONTAINED', 'RESOLVED')),
    source_ip     VARCHAR(45),                -- the attacker the chain is built around
    stages        INT DEFAULT 1,              -- number of distinct kill-chain stages seen
    created_at    TIMESTAMP DEFAULT now(),
    updated_at    TIMESTAMP DEFAULT now()
);

CREATE INDEX idx_chains_ip_status ON incident_chains (source_ip, status);

-- ------------------------------------------------------------
-- 4. INCIDENTS
-- ------------------------------------------------------------
CREATE TABLE incidents (
    incident_id   SERIAL PRIMARY KEY,
    event_id      INT REFERENCES security_events(event_id),
    chain_id      INT REFERENCES incident_chains(chain_id),   -- NULL if standalone
    severity      VARCHAR(20) NOT NULL,       -- LOW / MEDIUM / HIGH / CRITICAL
    risk_score    INT CHECK (risk_score BETWEEN 0 AND 100),   -- risk scoring feature
    risk_factors  TEXT,                       -- JSON text: why the score is what it is
    csf_function  VARCHAR(20),                -- NIST CSF: Govern/Identify/.../Recover
    status        VARCHAR(20) DEFAULT 'OPEN'
                  CHECK (status IN ('OPEN', 'INVESTIGATING', 'AWAITING_APPROVAL',
                                     'REMEDIATED', 'CLOSED')),
    created_at    TIMESTAMP DEFAULT now()
);

CREATE INDEX idx_incidents_chain ON incidents (chain_id);
CREATE INDEX idx_incidents_status ON incidents (status);

-- ------------------------------------------------------------
-- 5. AI INVESTIGATION REPORTS
-- ------------------------------------------------------------
CREATE TABLE investigation_reports (
    report_id     SERIAL PRIMARY KEY,
    incident_id   INT REFERENCES incidents(incident_id) ON DELETE CASCADE,
    summary       TEXT NOT NULL,
    evidence      TEXT,                       -- JSON text: structured evidence points
    classification VARCHAR(50),                -- attack type classification
    confidence    NUMERIC(4,2),                -- 0.00 - 1.00
    impact        TEXT,
    generated_at  TIMESTAMP DEFAULT now()
);

-- ------------------------------------------------------------
-- 6. REMEDIATION PLANS
-- ------------------------------------------------------------
CREATE TABLE remediation_plans (
    plan_id       SERIAL PRIMARY KEY,
    incident_id   INT REFERENCES incidents(incident_id) ON DELETE CASCADE,
    steps         TEXT NOT NULL,              -- JSON text: ordered containment->prevention steps
    status        VARCHAR(20) DEFAULT 'PENDING'
                  CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'EXECUTED')),
    approved_by   INT REFERENCES users(user_id),
    approved_at   TIMESTAMP,
    created_at    TIMESTAMP DEFAULT now()
);

-- ------------------------------------------------------------
-- 7. INCIDENT EMBEDDINGS  (RAG over past incidents)
-- ------------------------------------------------------------
CREATE TABLE incident_embeddings (
    embedding_id  SERIAL PRIMARY KEY,
    incident_id   INT REFERENCES incidents(incident_id) ON DELETE CASCADE,
    summary_text  TEXT NOT NULL,              -- text that was embedded
    embedding     vector(768),                -- adjust dim to your embedding model
    created_at    TIMESTAMP DEFAULT now()
);

-- One embedding per incident (re-indexing replaces it).
-- No ANN index on purpose: ivfflat has poor recall on small tables, and exact
-- search is instant at this scale. Add an HNSW index if you ever pass ~100k rows.
CREATE UNIQUE INDEX ux_incident_embeddings_incident ON incident_embeddings (incident_id);

-- ------------------------------------------------------------
-- 8. AUDIT LOG  (compliance trail — supports NIST CSF "Govern")
-- ------------------------------------------------------------
CREATE TABLE audit_log (
    log_id        SERIAL PRIMARY KEY,
    user_id       INT REFERENCES users(user_id),
    action        VARCHAR(100) NOT NULL,      -- e.g. 'APPROVE_REMEDIATION'
    target_type   VARCHAR(50),                -- e.g. 'incident', 'remediation_plan'
    target_id     INT,
    details       TEXT,
    created_at    TIMESTAMP DEFAULT now()
);

CREATE INDEX idx_audit_log_user_time ON audit_log (user_id, created_at);

-- ------------------------------------------------------------
-- 9. NOTIFICATIONS  (email alert integration)
-- ------------------------------------------------------------
CREATE TABLE notifications (
    notification_id SERIAL PRIMARY KEY,
    incident_id     INT REFERENCES incidents(incident_id) ON DELETE CASCADE,
    channel         VARCHAR(20) DEFAULT 'email',
    recipient       VARCHAR(120) NOT NULL,
    sent_at         TIMESTAMP,
    status          VARCHAR(20) DEFAULT 'PENDING'
                    CHECK (status IN ('PENDING', 'SENT', 'FAILED')),
    subject         VARCHAR(200),
    error           TEXT,
    created_at      TIMESTAMP DEFAULT now()
);

-- ------------------------------------------------------------
-- Notes:
-- * Incident PDFs are generated on demand from the tables above - no storage table needed.
-- * JSON-ish columns (evidence, steps, details, risk_factors) are TEXT holding JSON,
--   which keeps the Java entities simple.
-- * MTTR and other metrics-dashboard numbers are computed via queries
--   over incidents.created_at / incidents.status transitions, not stored directly.
-- ============================================================