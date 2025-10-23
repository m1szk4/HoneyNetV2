-- ClickHouse Database Schema for IoT Honeypot
-- Database: honeynet
-- Purpose: Store and analyze honeypot events, IDS alerts, and attack data
-- GDPR Compliant: IP anonymization, 90-day retention

-- Create database
CREATE DATABASE IF NOT EXISTS honeynet;

-- ============================================================================
-- Main Events Table
-- Purpose: Universal table for all network events from honeypots and Zeek
-- ============================================================================

CREATE TABLE IF NOT EXISTS honeynet.events
(
    -- Identifiers and timestamps
    event_id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime DEFAULT now(),
    event_date Date MATERIALIZED toDate(timestamp),

    -- Event classification
    event_type LowCardinality(String) DEFAULT '',
    honeypot_name LowCardinality(String) DEFAULT '',

    -- Network information (anonymized)
    source_ip_anon FixedString(64) DEFAULT '',  -- HMAC-SHA256 hash
    source_port UInt16 DEFAULT 0,
    dest_ip IPv4 DEFAULT toIPv4('0.0.0.0'),
    dest_port UInt16 DEFAULT 0,
    protocol LowCardinality(String) DEFAULT '',

    -- Geolocation
    country_code FixedString(2) DEFAULT 'XX',
    asn String DEFAULT '',

    -- Attack classification (MITRE ATT&CK)
    attack_technique LowCardinality(String) DEFAULT '',
    attack_tactic LowCardinality(String) DEFAULT '',
    severity Enum8('info'=0, 'low'=1, 'medium'=2, 'high'=3, 'critical'=4) DEFAULT 'info',

    -- Session and payload information
    session_id String DEFAULT '',
    duration Float32 DEFAULT 0,
    payload String CODEC(ZSTD(3)) DEFAULT '',
    payload_size UInt32 DEFAULT 0,

    -- HTTP-specific fields
    user_agent String DEFAULT '',
    url String DEFAULT '',
    http_method LowCardinality(String) DEFAULT '',

    -- Credentials (hashed)
    username String DEFAULT '',
    password_hash FixedString(64) DEFAULT '',

    -- File information
    file_hash String DEFAULT '',
    file_size UInt32 DEFAULT 0,

    -- Flags
    is_malicious UInt8 DEFAULT 1,
    is_bruteforce UInt8 DEFAULT 0,
    is_exploit UInt8 DEFAULT 0,

    -- Additional metadata (JSON format)
    metadata String CODEC(ZSTD(3)) DEFAULT ''
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, dest_port, source_ip_anon)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- Add comment
COMMENT ON TABLE honeynet.events IS 'Main events table storing all network activity from honeypots and Zeek';

-- ============================================================================
-- SSH Events Table (Cowrie)
-- Purpose: Detailed SSH/Telnet honeypot events from Cowrie
-- ============================================================================

CREATE TABLE IF NOT EXISTS honeynet.ssh_events
(
    -- Identifiers and timestamps
    event_id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime DEFAULT now(),
    event_date Date MATERIALIZED toDate(timestamp),

    -- Event type
    event_type LowCardinality(String) DEFAULT '',
    honeypot_sensor String DEFAULT '',

    -- Network information
    source_ip_anon FixedString(64) DEFAULT '',
    source_port UInt16 DEFAULT 0,
    dest_ip IPv4 DEFAULT toIPv4('0.0.0.0'),
    dest_port UInt16 DEFAULT 0,
    protocol LowCardinality(String) DEFAULT 'tcp',

    -- Geolocation
    country_code FixedString(2) DEFAULT 'XX',

    -- Attack classification
    attack_technique LowCardinality(String) DEFAULT '',
    attack_tactic LowCardinality(String) DEFAULT '',
    severity Enum8('info'=0, 'low'=1, 'medium'=2, 'high'=3, 'critical'=4) DEFAULT 'info',

    -- Session information
    session_id String DEFAULT '',
    duration Float32 DEFAULT 0,

    -- Authentication
    username String DEFAULT '',
    password_hash FixedString(64) DEFAULT '',
    success UInt8 DEFAULT 0,

    -- Command executed
    command String CODEC(ZSTD(3)) DEFAULT '',

    -- File operations
    filename String DEFAULT '',
    file_hash String DEFAULT '',
    download_url String DEFAULT '',

    -- Flags
    is_bruteforce UInt8 DEFAULT 0,

    -- Additional metadata
    metadata String CODEC(ZSTD(3)) DEFAULT ''
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, event_type, source_ip_anon)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

COMMENT ON TABLE honeynet.ssh_events IS 'SSH/Telnet events from Cowrie honeypot';

-- ============================================================================
-- HTTP Events Table (Dionaea, Conpot)
-- Purpose: HTTP/Web attack events
-- ============================================================================

CREATE TABLE IF NOT EXISTS honeynet.http_events
(
    -- Identifiers and timestamps
    event_id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime DEFAULT now(),
    event_date Date MATERIALIZED toDate(timestamp),

    -- Event classification
    event_type LowCardinality(String) DEFAULT '',
    honeypot_name LowCardinality(String) DEFAULT '',

    -- Network information
    source_ip_anon FixedString(64) DEFAULT '',
    source_port UInt16 DEFAULT 0,
    dest_ip IPv4 DEFAULT toIPv4('0.0.0.0'),
    dest_port UInt16 DEFAULT 80,
    protocol LowCardinality(String) DEFAULT 'http',

    -- Geolocation
    country_code FixedString(2) DEFAULT 'XX',

    -- Attack classification
    attack_technique LowCardinality(String) DEFAULT '',
    attack_tactic LowCardinality(String) DEFAULT '',
    severity Enum8('info'=0, 'low'=1, 'medium'=2, 'high'=3, 'critical'=4) DEFAULT 'info',

    -- HTTP request details
    http_method LowCardinality(String) DEFAULT '',
    url String DEFAULT '',
    user_agent String DEFAULT '',
    referer String DEFAULT '',

    -- Response information
    status_code UInt16 DEFAULT 0,
    response_size UInt32 DEFAULT 0,

    -- Exploit detection
    is_exploit UInt8 DEFAULT 0,
    exploit_type LowCardinality(String) DEFAULT '',

    -- Payload
    payload String CODEC(ZSTD(3)) DEFAULT '',

    -- Additional metadata
    metadata String CODEC(ZSTD(3)) DEFAULT ''
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, http_method, source_ip_anon)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

COMMENT ON TABLE honeynet.http_events IS 'HTTP/Web attack events from Dionaea and other honeypots';

-- ============================================================================
-- IDS Alerts Table (Suricata)
-- Purpose: Intrusion detection system alerts
-- ============================================================================

CREATE TABLE IF NOT EXISTS honeynet.ids_alerts
(
    -- Identifiers and timestamps
    event_id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime DEFAULT now(),
    event_date Date MATERIALIZED toDate(timestamp),

    -- Network information
    source_ip_anon FixedString(64) DEFAULT '',
    source_port UInt16 DEFAULT 0,
    dest_ip IPv4 DEFAULT toIPv4('0.0.0.0'),
    dest_port UInt16 DEFAULT 0,
    protocol LowCardinality(String) DEFAULT '',

    -- Geolocation
    country_code FixedString(2) DEFAULT 'XX',
    asn String DEFAULT '',

    -- Alert information
    alert_signature String DEFAULT '',
    alert_category LowCardinality(String) DEFAULT '',
    alert_severity Enum8('info'=0, 'low'=1, 'medium'=2, 'high'=3, 'critical'=4) DEFAULT 'info',
    signature_id UInt32 DEFAULT 0,
    revision UInt16 DEFAULT 0,

    -- MITRE ATT&CK mapping
    mitre_technique LowCardinality(String) DEFAULT '',
    mitre_tactic LowCardinality(String) DEFAULT '',

    -- Packet payload
    payload String CODEC(ZSTD(3)) DEFAULT '',

    -- Additional metadata
    metadata String CODEC(ZSTD(3)) DEFAULT ''
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, signature_id, source_ip_anon)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

COMMENT ON TABLE honeynet.ids_alerts IS 'IDS alerts from Suricata';

-- ============================================================================
-- Downloaded Files Table
-- Purpose: Track malware and files downloaded by attackers
-- ============================================================================

CREATE TABLE IF NOT EXISTS honeynet.downloaded_files
(
    -- Identifiers and timestamps
    file_id UUID DEFAULT generateUUIDv4(),
    timestamp DateTime DEFAULT now(),
    event_date Date MATERIALIZED toDate(timestamp),

    -- File information
    file_hash FixedString(64) DEFAULT '',  -- SHA256
    file_size UInt32 DEFAULT 0,
    file_type String DEFAULT '',
    filename String DEFAULT '',

    -- Download source
    download_url String DEFAULT '',
    honeypot_name LowCardinality(String) DEFAULT '',

    -- Attacker information (anonymized)
    source_ip_anon FixedString(64) DEFAULT '',
    country_code FixedString(2) DEFAULT 'XX',

    -- Malware classification
    is_malware UInt8 DEFAULT 0,
    malware_family String DEFAULT '',
    virustotal_positives UInt8 DEFAULT 0,
    virustotal_total UInt8 DEFAULT 0,

    -- Additional metadata
    metadata String CODEC(ZSTD(3)) DEFAULT ''
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, file_hash)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

COMMENT ON TABLE honeynet.downloaded_files IS 'Malware and files downloaded by attackers';

-- ============================================================================
-- Attack Statistics Materialized View
-- Purpose: Pre-aggregated statistics for dashboards
-- ============================================================================

CREATE MATERIALIZED VIEW IF NOT EXISTS honeynet.attack_stats_hourly
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (hour, country_code, attack_technique)
AS
SELECT
    toStartOfHour(timestamp) AS hour,
    country_code,
    attack_technique,
    attack_tactic,
    honeypot_name,
    count() AS event_count,
    uniq(source_ip_anon) AS unique_attackers
FROM honeynet.events
WHERE attack_technique != ''
GROUP BY hour, country_code, attack_technique, attack_tactic, honeypot_name;

-- ============================================================================
-- Top Attackers Materialized View
-- Purpose: Track most active attacking IPs (anonymized)
-- ============================================================================

CREATE MATERIALIZED VIEW IF NOT EXISTS honeynet.top_attackers_daily
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(day)
ORDER BY (day, source_ip_anon)
AS
SELECT
    toDate(timestamp) AS day,
    source_ip_anon,
    country_code,
    count() AS attack_count,
    uniqArray(groupArray(attack_technique)) AS techniques_used,
    max(severity) AS max_severity
FROM honeynet.events
WHERE source_ip_anon != ''
GROUP BY day, source_ip_anon, country_code;

-- ============================================================================
-- Indexes for faster queries
-- ============================================================================

-- Index on country for geographic analysis
ALTER TABLE honeynet.events ADD INDEX idx_country country_code TYPE set(0) GRANULARITY 4;
ALTER TABLE honeynet.ssh_events ADD INDEX idx_country country_code TYPE set(0) GRANULARITY 4;
ALTER TABLE honeynet.http_events ADD INDEX idx_country country_code TYPE set(0) GRANULARITY 4;
ALTER TABLE honeynet.ids_alerts ADD INDEX idx_country country_code TYPE set(0) GRANULARITY 4;

-- Index on attack technique for MITRE filtering
ALTER TABLE honeynet.events ADD INDEX idx_technique attack_technique TYPE set(0) GRANULARITY 4;
ALTER TABLE honeynet.ids_alerts ADD INDEX idx_technique mitre_technique TYPE set(0) GRANULARITY 4;

-- Index on severity for filtering by threat level
ALTER TABLE honeynet.events ADD INDEX idx_severity severity TYPE set(0) GRANULARITY 4;
ALTER TABLE honeynet.ids_alerts ADD INDEX idx_severity alert_severity TYPE set(0) GRANULARITY 4;

-- ============================================================================
-- Useful Queries (for reference/testing)
-- ============================================================================

-- Total events by country (top 10)
-- SELECT country_code, count() AS total FROM honeynet.events GROUP BY country_code ORDER BY total DESC LIMIT 10;

-- Attack timeline (events per hour)
-- SELECT toStartOfHour(timestamp) AS hour, count() AS events FROM honeynet.events GROUP BY hour ORDER BY hour;

-- Top MITRE techniques
-- SELECT attack_technique, attack_tactic, count() AS occurrences FROM honeynet.events WHERE attack_technique != '' GROUP BY attack_technique, attack_tactic ORDER BY occurrences DESC LIMIT 20;

-- Unique attackers per day
-- SELECT toDate(timestamp) AS day, uniq(source_ip_anon) AS unique_ips FROM honeynet.events GROUP BY day ORDER BY day;

-- Brute force attempts (Cowrie)
-- SELECT username, count() AS attempts FROM honeynet.ssh_events WHERE event_type = 'cowrie.login.failed' GROUP BY username ORDER BY attempts DESC LIMIT 20;

-- Most triggered IDS signatures
-- SELECT alert_signature, count() AS triggers FROM honeynet.ids_alerts GROUP BY alert_signature ORDER BY triggers DESC LIMIT 20;

-- Downloaded malware samples
-- SELECT file_hash, file_type, file_size, count() AS download_count FROM honeynet.downloaded_files GROUP BY file_hash, file_type, file_size ORDER BY download_count DESC;

-- ============================================================================
-- Grant permissions (adjust as needed for your setup)
-- ============================================================================

-- CREATE USER IF NOT EXISTS logstash IDENTIFIED WITH plaintext_password BY 'your_password_here';
-- GRANT INSERT ON honeynet.* TO logstash;

-- CREATE USER IF NOT EXISTS grafana IDENTIFIED WITH plaintext_password BY 'your_password_here';
-- GRANT SELECT ON honeynet.* TO grafana;

-- ============================================================================
-- Data retention policy enforcement
-- ============================================================================

-- TTL is already set on tables (90 days)
-- ClickHouse will automatically delete old partitions

OPTIMIZE TABLE honeynet.events FINAL;
OPTIMIZE TABLE honeynet.ssh_events FINAL;
OPTIMIZE TABLE honeynet.http_events FINAL;
OPTIMIZE TABLE honeynet.ids_alerts FINAL;
OPTIMIZE TABLE honeynet.downloaded_files FINAL;
