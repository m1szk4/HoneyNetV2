-- HoneyNetV2 ClickHouse Database Schema
-- This script initializes the database and tables for honeypot data

-- Create database
CREATE DATABASE IF NOT EXISTS honeynet;

USE honeynet;

-- ============================================================================
-- HONEYPOT EVENTS TABLE
-- Stores events from all honeypots (Cowrie, Dionaea, Conpot, RTSP)
-- ============================================================================

CREATE TABLE IF NOT EXISTS honeypot_events (
    timestamp DateTime,
    event_id String,
    honeypot_type Enum8('cowrie'=1, 'dionaea'=2, 'conpot'=3, 'rtsp'=4),
    source_ip_hash String,  -- Anonymized IP hash
    source_ip_country String,
    source_port UInt16,
    dest_ip String,
    dest_port UInt16,
    protocol String,
    event_type String,
    username String DEFAULT '',
    password String DEFAULT '',
    command String DEFAULT '',
    session_id String DEFAULT '',
    success Boolean DEFAULT false,
    raw_data String DEFAULT '',
    INDEX idx_timestamp timestamp TYPE minmax GRANULARITY 3,
    INDEX idx_source_hash source_ip_hash TYPE bloom_filter GRANULARITY 1,
    INDEX idx_event_type event_type TYPE set(100) GRANULARITY 1
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, honeypot_type, source_ip_hash)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- ============================================================================
-- IDS ALERTS TABLE (Suricata)
-- Stores network intrusion detection alerts
-- ============================================================================

CREATE TABLE IF NOT EXISTS ids_alerts (
    timestamp DateTime,
    alert_id String,
    source_ip_hash String,  -- Anonymized
    source_ip_country String DEFAULT '',  -- GeoIP country code
    source_port UInt16,
    dest_ip String,
    dest_port UInt16,
    protocol String,
    alert_signature String,
    alert_category String,
    alert_severity UInt8,
    signature_id UInt32,
    revision UInt16,
    payload String DEFAULT '',
    mitre_technique_id String DEFAULT '',  -- MITRE ATT&CK technique (e.g., T1190)
    mitre_tactic String DEFAULT '',  -- MITRE ATT&CK tactic (e.g., initial-access)
    INDEX idx_timestamp timestamp TYPE minmax GRANULARITY 3,
    INDEX idx_signature signature_id TYPE set(1000) GRANULARITY 1,
    INDEX idx_category alert_category TYPE set(50) GRANULARITY 1,
    INDEX idx_mitre_technique mitre_technique_id TYPE set(100) GRANULARITY 1
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, alert_severity, source_ip_hash)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- ============================================================================
-- NETWORK CONNECTIONS TABLE (Zeek)
-- Stores all network connections analyzed by Zeek
-- ============================================================================

CREATE TABLE IF NOT EXISTS network_connections (
    timestamp DateTime,
    uid String,
    source_ip_hash String,  -- Anonymized
    source_ip_country String DEFAULT '',  -- GeoIP country code
    source_port UInt16,
    dest_ip String,
    dest_port UInt16,
    protocol String,
    service String DEFAULT '',
    duration Float32,
    orig_bytes UInt64 DEFAULT 0,
    resp_bytes UInt64 DEFAULT 0,
    conn_state String,
    local_orig Boolean,
    local_resp Boolean,
    missed_bytes UInt64 DEFAULT 0,
    history String DEFAULT '',
    orig_pkts UInt32 DEFAULT 0,
    resp_pkts UInt32 DEFAULT 0,
    INDEX idx_timestamp timestamp TYPE minmax GRANULARITY 3,
    INDEX idx_service service TYPE set(100) GRANULARITY 1
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, source_ip_hash, dest_port)
TTL timestamp + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

-- ============================================================================
-- HTTP REQUESTS TABLE
-- Stores HTTP requests captured by honeypots and IDS
-- ============================================================================

CREATE TABLE IF NOT EXISTS http_requests (
    timestamp DateTime,
    source_ip_hash String,  -- Anonymized
    source_ip_country String DEFAULT '',  -- GeoIP country code
    source_port UInt16,
    dest_ip String,
    dest_port UInt16,
    method String,
    host String,
    uri String,
    user_agent String DEFAULT '',
    referrer String DEFAULT '',
    status_code UInt16 DEFAULT 0,
    response_body_len UInt32 DEFAULT 0,
    request_body String DEFAULT '',
    INDEX idx_timestamp timestamp TYPE minmax GRANULARITY 3,
    INDEX idx_method method TYPE set(10) GRANULARITY 1,
    INDEX idx_status status_code TYPE set(50) GRANULARITY 1
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, source_ip_hash, uri)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- ============================================================================
-- DOWNLOADED FILES TABLE
-- Stores information about files downloaded during attacks
-- ============================================================================

CREATE TABLE IF NOT EXISTS downloaded_files (
    timestamp DateTime,
    file_id String,
    source_ip_hash String,  -- Anonymized
    honeypot_type String,
    filename String,
    file_size UInt64,
    mime_type String DEFAULT '',
    md5_hash String,
    sha1_hash String DEFAULT '',
    sha256_hash String DEFAULT '',
    download_url String DEFAULT '',
    file_path String DEFAULT '',
    INDEX idx_timestamp timestamp TYPE minmax GRANULARITY 3,
    INDEX idx_md5 md5_hash TYPE bloom_filter GRANULARITY 1,
    INDEX idx_sha256 sha256_hash TYPE bloom_filter GRANULARITY 1
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, md5_hash)
TTL timestamp + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;

-- ============================================================================
-- CREDENTIALS TABLE
-- Stores all credential attempts (username/password combinations)
-- ============================================================================

CREATE TABLE IF NOT EXISTS credentials (
    timestamp DateTime,
    source_ip_hash String,  -- Anonymized
    honeypot_type String,
    protocol String,
    username String,
    password String,
    success Boolean,
    session_id String DEFAULT '',
    INDEX idx_timestamp timestamp TYPE minmax GRANULARITY 3
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, username, password)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- ============================================================================
-- RTSP ATTACKS TABLE
-- Stores RTSP-specific attack events (CVE-2014-8361 and other exploits)
-- ============================================================================

CREATE TABLE IF NOT EXISTS rtsp_attacks (
    timestamp DateTime,
    attack_id String,
    source_ip_hash String,  -- Anonymized
    source_ip_country String DEFAULT '',
    source_port UInt16,
    dest_ip String,
    dest_port UInt16,
    attack_type String,
    rtsp_method String DEFAULT '',
    rtsp_url String DEFAULT '',
    attack_details String DEFAULT '',  -- JSON string with attack metadata
    INDEX idx_timestamp timestamp TYPE minmax GRANULARITY 3,
    INDEX idx_attack_type attack_type TYPE set(20) GRANULARITY 1,
    INDEX idx_source_hash source_ip_hash TYPE bloom_filter GRANULARITY 1
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, attack_type, source_ip_hash)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- ============================================================================
-- ATTACKER PROFILES TABLE
-- Aggregated information about unique attackers
-- ============================================================================

CREATE TABLE IF NOT EXISTS attacker_profiles (
    source_ip_hash String,
    first_seen DateTime,
    last_seen DateTime,
    total_events UInt64,
    unique_ports_targeted Array(UInt16),
    protocols_used Array(String),
    countries Array(String),
    attack_types Array(String),
    credential_attempts UInt32,
    successful_logins UInt32,
    files_downloaded UInt32,
    INDEX idx_first_seen first_seen TYPE minmax GRANULARITY 3
) ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(first_seen)
ORDER BY (source_ip_hash, first_seen)
SETTINGS index_granularity = 8192;

-- ============================================================================
-- MATERIALIZED VIEWS FOR REAL-TIME AGGREGATIONS
-- ============================================================================

-- Daily attack statistics
CREATE MATERIALIZED VIEW IF NOT EXISTS daily_attack_stats
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(date)
ORDER BY (date, honeypot_type, event_type)
AS SELECT
    toDate(timestamp) AS date,
    honeypot_type,
    event_type,
    count() AS event_count,
    uniq(source_ip_hash) AS unique_attackers,
    uniq(dest_port) AS unique_ports
FROM honeypot_events
GROUP BY date, honeypot_type, event_type;

-- Top attacked services
CREATE MATERIALIZED VIEW IF NOT EXISTS top_attacked_services
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(date)
ORDER BY (date, dest_port, protocol)
AS SELECT
    toDate(timestamp) AS date,
    dest_port,
    protocol,
    count() AS connection_count,
    uniq(source_ip_hash) AS unique_sources
FROM network_connections
GROUP BY date, dest_port, protocol;

-- Credential statistics
CREATE MATERIALIZED VIEW IF NOT EXISTS credential_stats
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(date)
ORDER BY (date, username, password)
AS SELECT
    toDate(timestamp) AS date,
    username,
    password,
    count() AS attempt_count,
    uniq(source_ip_hash) AS unique_sources,
    countIf(success) AS success_count
FROM credentials
GROUP BY date, username, password;

-- Attacker profile aggregation (populated via scheduled INSERT)
-- This view helps aggregate attacker data for the attacker_profiles table
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

-- Grant permissions (will be used by Logstash)
-- Note: User creation is handled in users.xml
