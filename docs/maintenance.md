# HoneyNetV2 Maintenance and Operations Guide

## Overview

This document provides operational procedures for maintaining HoneyNetV2 in production, including updates, monitoring, backups, and troubleshooting.

**Last Updated**: 2025-10-24

---

## Table of Contents

1. [Daily Operations](#daily-operations)
2. [System Updates](#system-updates)
3. [Backup and Recovery](#backup-and-recovery)
4. [Log Management](#log-management)
5. [Performance Monitoring](#performance-monitoring)
6. [Rule Updates](#rule-updates)
7. [Incident Response](#incident-response)

---

## Daily Operations

### Morning Checklist

```bash
#!/bin/bash
# Daily morning checks

# 1. Verify all containers running
docker-compose ps

# 2. Check system health
./scripts/monitoring/health_check.sh

# 3. Review overnight alerts
docker logs honeynet-grafana | grep ALERT | tail -20

# 4. Check disk space
df -h | grep -E '(Filesystem|/data|/var/lib/docker)'

# 5. Quick attack summary
docker exec honeynet-clickhouse clickhouse-client --query="
SELECT
    toDate(timestamp) as date,
    count() as events,
    uniq(source_ip_hash) as unique_attackers
FROM honeynet.honeypot_events
WHERE timestamp >= today() - 1
GROUP BY date
"
```

### Automated Daily Tasks

Add to crontab (`crontab -e`):

```cron
# Daily health check (6 AM)
0 6 * * * /opt/HoneyNetV2/scripts/monitoring/health_check.sh > /var/log/honeynet_health.log 2>&1

# Daily report (8 AM)
0 8 * * * /opt/HoneyNetV2/scripts/monitoring/daily_report.sh

# Log rotation (2 AM)
0 2 * * * /opt/HoneyNetV2/scripts/maintenance/log_rotation.sh

# ClickHouse optimization (3 AM)
0 3 * * * docker exec honeynet-clickhouse clickhouse-client --query="OPTIMIZE TABLE honeynet.honeypot_events"
```

---

## System Updates

### Update Frequency

| Component | Update Schedule | Priority |
|-----------|----------------|----------|
| Docker images | Monthly | High |
| Suricata rules | Weekly | Critical |
| OS packages | Monthly | Medium |
| ClickHouse | Quarterly | Medium |

### Docker Image Updates

```bash
# 1. Backup current state
cd /opt/HoneyNetV2
ansible-playbook -i ansible/inventory/hosts.ini ansible/playbooks/99-backup.yml

# 2. Pull latest images
docker-compose pull

# 3. Restart services (with brief downtime)
docker-compose down
docker-compose up -d

# 4. Verify services
sleep 30
docker-compose ps
python3 tests/test_e2e.py

# 5. Check logs for errors
docker-compose logs --tail=50 | grep -i error
```

### Rolling Updates (Zero Downtime)

For critical services, update one at a time:

```bash
# Update Cowrie only
docker-compose pull cowrie
docker-compose up -d --no-deps cowrie

# Wait and verify
sleep 10
docker logs honeynet-cowrie --tail=20

# Repeat for other services
docker-compose up -d --no-deps dionaea
docker-compose up -d --no-deps conpot
```

---

## Backup and Recovery

### Backup Strategy

**3-2-1 Rule**:
- 3 copies of data
- 2 different storage types
- 1 off-site copy

### Automated Backup

```bash
# Run Ansible backup playbook
ansible-playbook -i ansible/inventory/hosts.ini ansible/playbooks/99-backup.yml

# Or with custom retention
EXPORT_DAYS=30 ansible-playbook -i ansible/inventory/hosts.ini ansible/playbooks/99-backup.yml
```

### Manual Backup

```bash
#!/bin/bash
# Manual backup script

BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/opt/honeynet_backups/$BACKUP_DATE"

mkdir -p "$BACKUP_DIR"

# 1. ClickHouse database export
docker exec honeynet-clickhouse clickhouse-client --query="
BACKUP DATABASE honeynet TO Disk('backups', 'honeynet_$BACKUP_DATE.zip')
"

# 2. Configuration files
tar -czf "$BACKUP_DIR/configs.tar.gz" configs/

# 3. Docker compose
cp docker-compose.yml "$BACKUP_DIR/"
cp .env "$BACKUP_DIR/env.backup"

# 4. Grafana dashboards
tar -czf "$BACKUP_DIR/grafana_dashboards.tar.gz" data/grafana/

# 5. Parquet exports
for table in honeypot_events ids_alerts credentials downloaded_files; do
    docker exec honeynet-clickhouse clickhouse-client --query="
    SELECT * FROM honeynet.$table
    WHERE timestamp >= now() - INTERVAL 7 DAY
    FORMAT Parquet
    " > "$BACKUP_DIR/${table}.parquet"
done

# 6. Create manifest
cat > "$BACKUP_DIR/MANIFEST.txt" <<EOF
Backup Date: $(date)
HoneyNetV2 Version: 2.0
Contains:
- ClickHouse database backup
- Configuration files
- Grafana dashboards
- Parquet exports (7 days)
- Docker compose configuration
EOF

echo "Backup completed: $BACKUP_DIR"
```

### Recovery Procedures

#### Restore ClickHouse Database

```bash
# 1. Stop ClickHouse
docker-compose stop clickhouse

# 2. Restore from backup
docker exec honeynet-clickhouse clickhouse-client --query="
RESTORE DATABASE honeynet FROM Disk('backups', 'honeynet_20251024.zip')
"

# 3. Restart
docker-compose start clickhouse

# 4. Verify
docker exec honeynet-clickhouse clickhouse-client --query="
SELECT count() FROM honeynet.honeypot_events
"
```

#### Restore Configuration

```bash
# Extract backup
tar -xzf /opt/honeynet_backups/20251024_103000/configs.tar.gz -C /opt/HoneyNetV2/

# Restart affected services
docker-compose restart suricata zeek logstash
```

---

## Log Management

### Log Rotation

**Automated**: `scripts/maintenance/log_rotation.sh`

```bash
# Configuration (in script)
MAX_LOG_SIZE=100M           # Rotate logs > 100MB
LOG_RETENTION_DAYS=30       # Archive after 30 days
ARCHIVE_DIR=/opt/honeynet_logs_archive
```

### Manual Log Rotation

```bash
# Rotate Cowrie logs
cd /opt/HoneyNetV2/data/cowrie
mv cowrie.json cowrie.json.$(date +%Y%m%d)
gzip cowrie.json.$(date +%Y%m%d)

# Signal Cowrie to reopen log file
docker exec honeynet-cowrie kill -HUP 1
```

### Log Cleanup

```bash
# Delete logs older than 90 days
find /opt/HoneyNetV2/data/*/logs -name "*.json.*" -mtime +90 -delete

# Compress uncompressed logs
find /opt/HoneyNetV2/data -name "*.log" -size +10M -exec gzip {} \;
```

### Log Analysis

```bash
# Find errors in Logstash
docker logs honeynet-logstash --since 1h | grep -i error | less

# Check Suricata stats
docker exec honeynet-suricata cat /var/log/suricata/stats.log | tail -20

# ClickHouse query log (slow queries)
docker exec honeynet-clickhouse tail -f /var/log/clickhouse-server/clickhouse-server.log | grep "query_duration_ms"
```

---

## Performance Monitoring

### Real-Time Monitoring

```bash
# Container resource usage
docker stats honeynet-suricata honeynet-zeek honeynet-clickhouse honeynet-logstash

# Disk I/O
iostat -x 5

# Network traffic
iftop -i eth0
```

### Grafana System Dashboard

Create dashboard with panels:

1. **Event Ingestion Rate**:
   ```sql
   SELECT
       toStartOfMinute(timestamp) as minute,
       count() / 60 as events_per_second
   FROM honeynet.honeypot_events
   WHERE timestamp >= now() - INTERVAL 1 HOUR
   GROUP BY minute
   ORDER BY minute
   ```

2. **Logstash Lag**:
   Monitor sincedb positions vs actual file sizes

3. **ClickHouse Query Performance**:
   ```sql
   SELECT
       query_duration_ms,
       query,
       event_time
   FROM system.query_log
   WHERE type = 'QueryFinish'
     AND event_time >= now() - INTERVAL 1 HOUR
   ORDER BY query_duration_ms DESC
   LIMIT 10
   ```

### Performance Alerts

```sql
-- Create alert for high event rate
SELECT count() as events_per_minute
FROM honeynet.honeypot_events
WHERE timestamp >= now() - INTERVAL 1 MINUTE
HAVING events_per_minute > 1000
```

Configure Grafana alert to send email when threshold exceeded.

---

## Rule Updates

### Suricata Rules

#### Monthly Update Procedure

```bash
# 1. Backup current rules
cp -r /opt/HoneyNetV2/configs/suricata/rules /opt/HoneyNetV2/configs/suricata/rules.backup.$(date +%Y%m%d)

# 2. Review new IoT vulnerabilities
# Sources:
# - CISA ICS Advisories: https://www.cisa.gov/uscert/ics/advisories
# - NVD: https://nvd.nist.gov/
# - MITRE ATT&CK updates: https://attack.mitre.org/

# 3. Add new rules to honeypot-custom.rules
nano configs/suricata/rules/honeypot-custom.rules

# 4. Validate syntax
docker exec honeynet-suricata suricata -T -c /etc/suricata/suricata.yaml

# 5. Reload rules (no downtime)
docker exec honeynet-suricata kill -USR2 1

# 6. Verify rules loaded
docker exec honeynet-suricata suricata --dump-config | grep "rule-files"
```

#### Rule Testing

```bash
# Test new rule with PCAP
docker exec honeynet-suricata suricata \
    -r /data/test.pcap \
    -c /etc/suricata/suricata.yaml \
    -l /data/test_output/

# Check alerts generated
docker exec honeynet-suricata cat /data/test_output/fast.log
```

### Zeek Scripts

```bash
# Update Zeek scripts
cd /opt/HoneyNetV2/configs/zeek
nano detect-iot-attacks.zeek

# Test syntax
docker exec honeynet-zeek zeek -C -i /usr/local/zeek/site/detect-iot-attacks.zeek

# Restart Zeek
docker-compose restart zeek
```

---

## Incident Response

### Suspicious Activity Detection

#### Alert Triage

```sql
-- High-severity alerts (last hour)
SELECT
    timestamp,
    signature,
    source_ip_hash,
    source_ip_country,
    dest_port,
    mitre_technique_id
FROM honeynet.ids_alerts
WHERE severity = 1
  AND timestamp >= now() - INTERVAL 1 HOUR
ORDER BY timestamp DESC;
```

#### Investigate Attacker

```sql
-- Attacker profile
SELECT
    source_ip_hash,
    min(timestamp) as first_seen,
    max(timestamp) as last_seen,
    count() as total_events,
    groupUniqArray(dest_port) as ports_targeted,
    groupUniqArray(protocol) as protocols_used
FROM honeynet.honeypot_events
WHERE source_ip_hash = 'ATTACKER_HASH_HERE'
GROUP BY source_ip_hash;

-- Credentials tried
SELECT username, password, success
FROM honeynet.credentials
WHERE source_ip_hash = 'ATTACKER_HASH_HERE'
ORDER BY timestamp;

-- Files downloaded
SELECT filename, file_hash, download_url
FROM honeynet.downloaded_files
WHERE source_ip_hash = 'ATTACKER_HASH_HERE';
```

### Compromised Honeypot

If a honeypot is exploited beyond expected behavior:

```bash
# 1. Isolate container (block network)
docker network disconnect honeynet_honeypot_net honeynet-cowrie

# 2. Capture container state
docker commit honeynet-cowrie forensics-cowrie-$(date +%Y%m%d)

# 3. Export logs immediately
docker logs honeynet-cowrie > /tmp/cowrie_incident_$(date +%Y%m%d).log

# 4. Investigate
docker exec honeynet-cowrie ps aux
docker exec honeynet-cowrie netstat -tulpn

# 5. Restore from clean image
docker-compose stop cowrie
docker-compose rm -f cowrie
docker-compose up -d cowrie
```

### Data Breach Response

**If anonymization key compromised**:

1. **Rotate secret immediately**:
   ```bash
   # Generate new key
   NEW_KEY=$(openssl rand -hex 32)

   # Update .env
   sed -i "s/ANON_SECRET_KEY=.*/ANON_SECRET_KEY=$NEW_KEY/" .env

   # Restart Logstash
   docker-compose restart logstash
   ```

2. **Note**: Historical data cannot be re-anonymized; consider truncating:
   ```sql
   TRUNCATE TABLE honeynet.honeypot_events;
   ```

---

## Capacity Planning

### Storage Growth Estimation

```sql
-- Average daily data size
SELECT
    toDate(timestamp) as date,
    sum(length(toString(*))) / 1024 / 1024 as data_mb
FROM honeynet.honeypot_events
WHERE timestamp >= now() - INTERVAL 7 DAY
GROUP BY date
ORDER BY date;
```

**Estimate**:
- 100 events/minute = ~15GB/month (compressed)
- 1000 events/minute = ~150GB/month

### Scaling Triggers

**Scale up when**:
- CPU usage consistently >80%
- Memory usage >90%
- Disk >85% full
- Event processing lag >60 seconds

**Scaling options**:
1. Increase container resources (mem_limit)
2. Add more pipeline workers (Logstash)
3. Migrate to larger host
4. Implement ClickHouse cluster (horizontal scaling)

---

## Decommissioning

### Safe Shutdown

```bash
# 1. Final backup
EXPORT_DAYS=90 ansible-playbook -i ansible/inventory/hosts.ini ansible/playbooks/99-backup.yml

# 2. Export all data
docker exec honeynet-clickhouse clickhouse-client --query="
BACKUP DATABASE honeynet TO Disk('backups', 'final_backup.zip')
"

# 3. Stop services gracefully
docker-compose down

# 4. Archive data
tar -czf /opt/honeynet_final_$(date +%Y%m%d).tar.gz /opt/HoneyNetV2/data/

# 5. Remove containers (optional)
docker-compose down -v  # WARNING: Deletes volumes!
```

---

## References

- [Docker Maintenance](https://docs.docker.com/config/pruning/)
- [ClickHouse Operations](https://clickhouse.com/docs/en/operations/)
- [Incident Response Plan Template](https://www.cisa.gov/incident-response)

---

**Document Version**: 1.0
**Author**: Agent #6b - Testing & Documentation
