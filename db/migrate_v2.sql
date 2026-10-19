-- ============================================================
-- SOCGPT v2 migration  (safe to run more than once)
-- Adds: risk factors, attack-chain columns, RAG fixes, richer notifications.
-- Run:  Get-Content db\migrate_v2.sql | docker exec -i socgpt-db psql -U socgpt -d socgpt
-- ============================================================

-- 0) Column types the Java entities expect (you ran some of these by hand already)
ALTER TABLE security_events     ALTER COLUMN source_ip TYPE VARCHAR(45);
ALTER TABLE remediation_plans   ALTER COLUMN steps     TYPE TEXT USING steps::text;
ALTER TABLE investigation_reports ALTER COLUMN evidence TYPE TEXT USING evidence::text;
ALTER TABLE audit_log           ALTER COLUMN details   TYPE TEXT USING details::text;

-- 1) Risk scoring: store *why* an incident got its score
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS risk_factors TEXT;

-- 2) Multi-stage attack chains
ALTER TABLE incident_chains ADD COLUMN IF NOT EXISTS source_ip  VARCHAR(45);
ALTER TABLE incident_chains ADD COLUMN IF NOT EXISTS stages     INT DEFAULT 1;
ALTER TABLE incident_chains ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT now();
CREATE INDEX IF NOT EXISTS idx_chains_ip_status ON incident_chains (source_ip, status);

-- 3) RAG: the ivfflat index gives poor recall on small tables (Postgres warns about it).
--    Exact search is instant at this scale; add an HNSW index later if you reach 100k+ rows.
DROP INDEX IF EXISTS idx_incident_embeddings_vec;
CREATE UNIQUE INDEX IF NOT EXISTS ux_incident_embeddings_incident ON incident_embeddings (incident_id);

-- 4) Email alerts: keep the subject and any error for each send
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS subject    VARCHAR(200);
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS error      TEXT;
ALTER TABLE notifications ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT now();
