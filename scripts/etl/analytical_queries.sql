-- ============================================================================
-- HoneyNetV2 Analytical Queries
-- ============================================================================
-- This file contains useful analytical queries for exploring honeypot data
-- and maintaining aggregated statistics.

-- ============================================================================
-- ATTACKER PROFILING
-- ============================================================================

-- Populate attacker_profiles table from honeypot_events
-- Run this periodically (e.g., daily via cron) to update attacker profiles
INSERT INTO honeynet.attacker_profiles
SELECT
    source_ip_hash,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_events,
    groupUniqArray(dest_port) AS unique_ports_targeted,
    groupUniqArray(protocol) AS protocols_used,
    groupUniqArray(source_ip_country) AS countries,
    groupUniqArray(event_type) AS attack_types,
    0 AS credential_attempts,
    0 AS successful_logins,
    0 AS files_downloaded
FROM honeynet.honeypot_events
WHERE timestamp >= now() - INTERVAL 1 DAY
GROUP BY source_ip_hash;

-- Update credential statistics in attacker_profiles
-- This query enriches profiles with credential attempt data
ALTER TABLE honeynet.attacker_profiles
UPDATE
    credential_attempts = (
        SELECT count()
        FROM honeynet.credentials c
        WHERE c.source_ip_hash = attacker_profiles.source_ip_hash
    ),
    successful_logins = (
        SELECT countIf(success)
        FROM honeynet.credentials c
        WHERE c.source_ip_hash = attacker_profiles.source_ip_hash
    )
WHERE source_ip_hash IN (
    SELECT DISTINCT source_ip_hash
    FROM honeynet.credentials
    WHERE timestamp >= now() - INTERVAL 1 DAY
);

-- Update file download statistics
ALTER TABLE honeynet.attacker_profiles
UPDATE
    files_downloaded = (
        SELECT count()
        FROM honeynet.downloaded_files df
        WHERE df.source_ip_hash = attacker_profiles.source_ip_hash
    )
WHERE source_ip_hash IN (
    SELECT DISTINCT source_ip_hash
    FROM honeynet.downloaded_files
    WHERE timestamp >= now() - INTERVAL 1 DAY
);

-- ============================================================================
-- DASHBOARD QUERIES
-- ============================================================================

-- Attack Overview - Daily attack statistics
SELECT
    toDate(timestamp) AS date,
    count() AS total_attacks,
    uniq(source_ip_hash) AS unique_attackers,
    uniq(dest_port) AS unique_ports_targeted,
    countIf(honeypot_type = 'cowrie') AS ssh_attacks,
    countIf(honeypot_type = 'dionaea') AS dionaea_attacks,
    countIf(honeypot_type = 'conpot') AS ics_attacks
FROM honeynet.honeypot_events
WHERE timestamp >= now() - INTERVAL 30 DAY
GROUP BY date
ORDER BY date DESC;

-- Top Attacked Ports (Last 7 Days)
SELECT
    dest_port,
    protocol,
    count() AS connection_count,
    uniq(source_ip_hash) AS unique_attackers,
    any(protocol) AS service_protocol
FROM honeynet.honeypot_events
WHERE timestamp >= now() - INTERVAL 7 DAY
GROUP BY dest_port, protocol
ORDER BY connection_count DESC
LIMIT 20;

-- Geographic Attack Distribution (Last 30 Days)
SELECT
    source_ip_country,
    count() AS attack_count,
    uniq(source_ip_hash) AS unique_attackers,
    round(attack_count * 100.0 / sum(attack_count) OVER (), 2) AS percentage
FROM honeynet.honeypot_events
WHERE timestamp >= now() - INTERVAL 30 DAY
  AND source_ip_country != ''
GROUP BY source_ip_country
ORDER BY attack_count DESC
LIMIT 50;

-- MITRE ATT&CK Technique Distribution
SELECT
    mitre_tactic,
    mitre_technique_id,
    any(alert_signature) AS example_alert,
    count() AS occurrence_count,
    uniq(source_ip_hash) AS unique_attackers
FROM honeynet.ids_alerts
WHERE timestamp >= now() - INTERVAL 30 DAY
  AND mitre_technique_id != ''
GROUP BY mitre_tactic, mitre_technique_id
ORDER BY occurrence_count DESC
LIMIT 30;

-- ============================================================================
-- CREDENTIAL ANALYSIS
-- ============================================================================

-- Most Common Username/Password Combinations
SELECT
    username,
    password,
    count() AS attempt_count,
    uniq(source_ip_hash) AS unique_sources,
    countIf(success) AS successful_attempts,
    round(countIf(success) * 100.0 / count(), 2) AS success_rate
FROM honeynet.credentials
WHERE timestamp >= now() - INTERVAL 30 DAY
GROUP BY username, password
ORDER BY attempt_count DESC
LIMIT 100;

-- Most Targeted Usernames
SELECT
    username,
    count() AS total_attempts,
    uniq(source_ip_hash) AS unique_attackers,
    uniq(password) AS unique_passwords_tried,
    countIf(success) AS successful_logins
FROM honeynet.credentials
WHERE timestamp >= now() - INTERVAL 30 DAY
GROUP BY username
ORDER BY total_attempts DESC
LIMIT 50;

-- Password Analysis - Weak Password Detection
SELECT
    password,
    count() AS usage_count,
    uniq(source_ip_hash) AS used_by_attackers,
    length(password) AS password_length,
    multiIf(
        password IN ('123456', 'password', 'admin', '12345678', 'root'), 'Very Common',
        length(password) < 6, 'Too Short',
        password = lower(password) AND match(password, '^[a-z]+$'), 'All Lowercase',
        'Other'
    ) AS weakness_category
FROM honeynet.credentials
WHERE timestamp >= now() - INTERVAL 30 DAY
GROUP BY password
ORDER BY usage_count DESC
LIMIT 100;

-- ============================================================================
-- ICS/SCADA THREAT INTELLIGENCE
-- ============================================================================

-- ICS Protocol Attack Statistics
SELECT
    protocol,
    event_type,
    count() AS attack_count,
    uniq(source_ip_hash) AS unique_attackers,
    any(command) AS example_command
FROM honeynet.honeypot_events
WHERE honeypot_type = 'conpot'
  AND timestamp >= now() - INTERVAL 30 DAY
GROUP BY protocol, event_type
ORDER BY attack_count DESC;

-- ============================================================================
-- LATERAL MOVEMENT DETECTION
-- ============================================================================

-- Detect potential lateral movement between honeypots
-- (attacks originating from DMZ subnet 172.20.0.0/24)
SELECT
    timestamp,
    source_ip_hash,
    dest_ip,
    dest_port,
    protocol,
    event_type,
    'Potential Lateral Movement' AS alert_type
FROM honeynet.honeypot_events
WHERE dest_ip LIKE '172.20.0.%'
  AND timestamp >= now() - INTERVAL 7 DAY
ORDER BY timestamp DESC
LIMIT 100;

-- IDS Alerts for Lateral Movement (Suricata SID 2000035)
SELECT
    timestamp,
    alert_signature,
    source_ip_hash,
    dest_ip,
    dest_port,
    payload
FROM honeynet.ids_alerts
WHERE signature_id = 2000035
  AND timestamp >= now() - INTERVAL 7 DAY
ORDER BY timestamp DESC;

-- ============================================================================
-- ATTACK CAMPAIGN DETECTION
-- ============================================================================

-- Identify potential attack campaigns (same attacker, multiple days, multiple services)
SELECT
    source_ip_hash,
    min(timestamp) AS campaign_start,
    max(timestamp) AS campaign_end,
    count(DISTINCT toDate(timestamp)) AS active_days,
    count() AS total_events,
    groupUniqArray(dest_port) AS targeted_ports,
    groupUniqArray(event_type) AS attack_types,
    uniq(honeypot_type) AS honeypots_attacked
FROM honeynet.honeypot_events
WHERE timestamp >= now() - INTERVAL 30 DAY
GROUP BY source_ip_hash
HAVING active_days >= 3 AND honeypots_attacked >= 2
ORDER BY total_events DESC
LIMIT 50;

-- ============================================================================
-- MALWARE ANALYSIS
-- ============================================================================

-- Downloaded File Statistics
SELECT
    md5_hash,
    sha256_hash,
    any(filename) AS filename,
    any(mime_type) AS mime_type,
    count() AS download_count,
    uniq(source_ip_hash) AS unique_downloaders,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen
FROM honeynet.downloaded_files
WHERE timestamp >= now() - INTERVAL 30 DAY
GROUP BY md5_hash, sha256_hash
ORDER BY download_count DESC
LIMIT 50;

-- ============================================================================
-- ALERT RANKING AND FALSE POSITIVE DETECTION
-- ============================================================================

-- Most Frequent IDS Alerts (for tuning)
SELECT
    signature_id,
    any(alert_signature) AS signature,
    any(alert_category) AS category,
    count() AS alert_count,
    uniq(source_ip_hash) AS unique_sources,
    round(alert_count * 100.0 / sum(alert_count) OVER (), 2) AS percentage
FROM honeynet.ids_alerts
WHERE timestamp >= now() - INTERVAL 7 DAY
GROUP BY signature_id
ORDER BY alert_count DESC
LIMIT 50;

-- ============================================================================
-- CORRELATION QUERIES
-- ============================================================================

-- Correlate IDS alerts with honeypot events (within 10 second window)
SELECT
    h.timestamp AS honeypot_time,
    i.timestamp AS ids_time,
    h.source_ip_hash,
    h.honeypot_type,
    h.dest_port,
    h.event_type,
    i.alert_signature,
    i.mitre_technique_id
FROM honeynet.honeypot_events h
INNER JOIN honeynet.ids_alerts i
    ON h.source_ip_hash = i.source_ip_hash
    AND abs(toUnixTimestamp(h.timestamp) - toUnixTimestamp(i.timestamp)) <= 10
WHERE h.timestamp >= now() - INTERVAL 1 DAY
ORDER BY h.timestamp DESC
LIMIT 100;

-- ============================================================================
-- DATA QUALITY CHECKS
-- ============================================================================

-- Check for missing GeoIP data
SELECT
    'honeypot_events' AS table_name,
    countIf(source_ip_country = '') AS missing_country,
    count() AS total_records,
    round(missing_country * 100.0 / total_records, 2) AS missing_percentage
FROM honeynet.honeypot_events
WHERE timestamp >= now() - INTERVAL 1 DAY
UNION ALL
SELECT
    'ids_alerts' AS table_name,
    countIf(source_ip_country = '') AS missing_country,
    count() AS total_records,
    round(missing_country * 100.0 / total_records, 2) AS missing_percentage
FROM honeynet.ids_alerts
WHERE timestamp >= now() - INTERVAL 1 DAY;

-- Check for missing MITRE ATT&CK data in IDS alerts
SELECT
    countIf(mitre_technique_id = '') AS without_mitre,
    count() AS total_alerts,
    round(without_mitre * 100.0 / total_alerts, 2) AS missing_percentage
FROM honeynet.ids_alerts
WHERE timestamp >= now() - INTERVAL 1 DAY;
