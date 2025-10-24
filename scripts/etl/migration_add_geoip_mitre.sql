-- ============================================================================
-- HoneyNetV2 Database Migration Script
-- ============================================================================
-- Purpose: Add GeoIP and MITRE ATT&CK columns to existing tables
-- Usage: docker exec honeynet-clickhouse clickhouse-client < migration_add_geoip_mitre.sql
-- ============================================================================

USE honeynet;

-- ============================================================================
-- ADD GEOIP COLUMNS
-- ============================================================================

-- Add source_ip_country to ids_alerts (if not exists)
ALTER TABLE ids_alerts ADD COLUMN IF NOT EXISTS source_ip_country String DEFAULT '';

-- Add source_ip_country to network_connections (if not exists)
ALTER TABLE network_connections ADD COLUMN IF NOT EXISTS source_ip_country String DEFAULT '';

-- Add source_ip_country to http_requests (if not exists)
ALTER TABLE http_requests ADD COLUMN IF NOT EXISTS source_ip_country String DEFAULT '';

-- ============================================================================
-- ADD MITRE ATT&CK COLUMNS
-- ============================================================================

-- Add MITRE ATT&CK fields to ids_alerts (if not exists)
ALTER TABLE ids_alerts ADD COLUMN IF NOT EXISTS mitre_technique_id String DEFAULT '';
ALTER TABLE ids_alerts ADD COLUMN IF NOT EXISTS mitre_tactic String DEFAULT '';

-- Add index on MITRE technique (if not exists)
-- Note: ClickHouse doesn't support adding indexes after table creation
-- This is handled in the schema for new tables

-- ============================================================================
-- CREATE NEW MATERIALIZED VIEWS
-- ============================================================================

-- MITRE ATT&CK statistics view
CREATE MATERIALIZED VIEW IF NOT EXISTS mitre_attack_stats
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(date)
ORDER BY (date, mitre_tactic, mitre_technique_id)
AS SELECT
    toDate(timestamp) AS date,
    mitre_tactic,
    mitre_technique_id,
    count() AS technique_count,
    uniq(source_ip_hash) AS unique_attackers,
    uniq(dest_port) AS unique_targets
FROM ids_alerts
WHERE mitre_technique_id != ''
GROUP BY date, mitre_tactic, mitre_technique_id;

-- Geographic attack distribution view
CREATE MATERIALIZED VIEW IF NOT EXISTS geographic_attack_stats
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(date)
ORDER BY (date, source_ip_country, honeypot_type)
AS SELECT
    toDate(timestamp) AS date,
    source_ip_country,
    honeypot_type,
    count() AS attack_count,
    uniq(source_ip_hash) AS unique_attackers,
    uniq(dest_port) AS unique_ports_targeted
FROM honeypot_events
WHERE source_ip_country != ''
GROUP BY date, source_ip_country, honeypot_type;

-- Attacker profile aggregator
CREATE MATERIALIZED VIEW IF NOT EXISTS attacker_profile_aggregator
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(date)
ORDER BY (source_ip_hash, date)
AS SELECT
    source_ip_hash,
    toDate(timestamp) AS date,
    minState(timestamp) AS first_seen,
    maxState(timestamp) AS last_seen,
    countState() AS total_events,
    groupUniqArrayState(dest_port) AS unique_ports,
    groupUniqArrayState(protocol) AS protocols,
    groupUniqArrayState(source_ip_country) AS countries,
    groupUniqArrayState(event_type) AS attack_types
FROM honeypot_events
GROUP BY source_ip_hash, date;

-- ============================================================================
-- VERIFY MIGRATION
-- ============================================================================

-- Check that columns were added successfully
SELECT
    table,
    name,
    type
FROM system.columns
WHERE database = 'honeynet'
  AND table IN ('ids_alerts', 'network_connections', 'http_requests')
  AND name IN ('source_ip_country', 'mitre_technique_id', 'mitre_tactic')
ORDER BY table, name;

-- Check materialized views
SELECT
    name,
    engine
FROM system.tables
WHERE database = 'honeynet'
  AND name IN ('mitre_attack_stats', 'geographic_attack_stats', 'attacker_profile_aggregator')
ORDER BY name;

-- Display summary
SELECT '========================================' AS '';
SELECT 'Migration completed successfully!' AS status;
SELECT '========================================' AS '';
SELECT 'New columns added:' AS '';
SELECT '  - source_ip_country (ids_alerts, network_connections, http_requests)' AS '';
SELECT '  - mitre_technique_id (ids_alerts)' AS '';
SELECT '  - mitre_tactic (ids_alerts)' AS '';
SELECT '' AS '';
SELECT 'New materialized views created:' AS '';
SELECT '  - mitre_attack_stats' AS '';
SELECT '  - geographic_attack_stats' AS '';
SELECT '  - attacker_profile_aggregator' AS '';
SELECT '========================================' AS '';
