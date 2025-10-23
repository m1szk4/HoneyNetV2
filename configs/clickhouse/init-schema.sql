-- HoneyNetV2 ClickHouse Database Schema
-- This script initializes the database and tables for honeypot data

-- Create database
CREATE DATABASE IF NOT EXISTS honeynet;

USE honeynet;

-- ============================================================================
-- HONEYPOT EVENTS TABLE
-- Stores events from all honeypots (Cowrie, Dionaea, Conpot)
-- ============================================================================

CREATE TABLE IF NOT EXISTS honeypot_events (
    timestamp DateTime,
    event_id String,
    honeypot_type Enum8('cowrie'=1, 'dionaea'=2, 'conpot'=3),
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
    INDEX idx_timestamp timestamp TYPE minmax GRANULARITY 3,
    INDEX idx_signature signature_id TYPE set(1000) GRANULARITY 1,
    INDEX idx_category alert_category TYPE set(50) GRANULARITY 1
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

-- Grant permissions (will be used by Logstash)
-- Note: User creation is handled in users.xml
