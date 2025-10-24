# HoneyNetV2 Deployment Checklist

## Pre-Deployment Checklist

Use this checklist before starting long-term data collection (e.g., November 2025 campaign).

**Target Deployment Date**: 2025-11-01
**Checklist Date**: 2025-10-24

---

## Phase 1: Infrastructure Preparation

### ☐ 1.1 Hardware Requirements

- [ ] **CPU**: Minimum 4 cores, 8 cores recommended
- [ ] **RAM**: Minimum 8GB, 16GB recommended
- [ ] **Disk**: 100GB+ free space (SSD recommended)
- [ ] **Network**: Public IP address or port forwarding configured
- [ ] **Bandwidth**: Adequate for expected attack volume

**Verification**:
```bash
# Check resources
lscpu | grep -E "^CPU\(s\)|Model name"
free -h
df -h /
```

---

### ☐ 1.2 Operating System

- [ ] Ubuntu 20.04+ or Debian 11+ installed
- [ ] System fully updated
- [ ] Firewall installed (ufw or iptables)
- [ ] SSH access configured (key-based authentication recommended)

**Verification**:
```bash
lsb_release -a
apt update && apt upgrade -y
ufw status
```

---

### ☐ 1.3 Docker Installation

- [ ] Docker Engine 20.10+ installed
- [ ] Docker Compose 2.0+ installed
- [ ] Docker service running
- [ ] User added to docker group (if non-root)

**Verification**:
```bash
docker --version
docker-compose --version
docker ps
```

---

## Phase 2: Configuration

### ☐ 2.1 Environment Variables

- [ ] Copied `.env.example` to `.env`
- [ ] **CRITICAL**: Changed `ANON_SECRET_KEY` to unique random value
- [ ] **CRITICAL**: Changed `CLICKHOUSE_PASSWORD` from default
- [ ] **CRITICAL**: Changed `GRAFANA_ADMIN_PASSWORD` from default
- [ ] **CRITICAL**: Changed `JUPYTER_TOKEN` from default
- [ ] Set `TZ` to appropriate timezone
- [ ] Configured `ALERT_EMAIL` for notifications
- [ ] Set `EXPORT_DAYS` (default: 7)
- [ ] Set `LOG_RETENTION_DAYS` (default: 30)
- [ ] Set `DATA_RETENTION_DAYS` (default: 90)

**Verification**:
```bash
grep -E "ANON_SECRET_KEY|CLICKHOUSE_PASSWORD|GRAFANA_ADMIN_PASSWORD" .env
# Ensure none are default values!
```

**Generate Strong Secrets**:
```bash
# ANON_SECRET_KEY
openssl rand -hex 32

# JUPYTER_TOKEN
python3 -c "import secrets; print(secrets.token_urlsafe(32))"

# Passwords
openssl rand -base64 24
```

---

### ☐ 2.2 Network Configuration

- [ ] DMZ network configured (172.20.0.0/24)
- [ ] Management network configured (172.21.0.0/24)
- [ ] Host firewall rules configured
- [ ] Egress from DMZ blocked (critical!)
- [ ] Port forwarding configured (if behind NAT)

**Firewall Rules**:
```bash
# Allow honeypot ports
ufw allow 22/tcp    # SSH
ufw allow 23/tcp    # Telnet
ufw allow 80/tcp    # HTTP
ufw allow 443/tcp   # HTTPS
ufw allow 445/tcp   # SMB
ufw allow 502/tcp   # Modbus
ufw allow 161/udp   # SNMP

# Block egress from DMZ (critical!)
iptables -A FORWARD -s 172.20.0.0/24 -j DROP
iptables-save > /etc/iptables/rules.v4

# Verify
iptables -L FORWARD -v -n
```

---

### ☐ 2.3 Honeypot Configuration

- [ ] Reviewed `configs/cowrie/cowrie.cfg`
- [ ] Customized `configs/cowrie/userdb.txt` (optional)
- [ ] Reviewed `configs/dionaea/dionaea.cfg`
- [ ] Reviewed `configs/conpot/conpot.cfg`
- [ ] Selected appropriate Conpot template (default: generic ICS)

---

### ☐ 2.4 IDS Rules

- [ ] Reviewed `configs/suricata/rules/honeypot-custom.rules`
- [ ] Verified MITRE ATT&CK metadata in rules
- [ ] Reviewed `configs/suricata/rules/iot-botnet.rules`
- [ ] Reviewed `configs/suricata/rules/lateral_movement.rules`
- [ ] Configured rule thresholds appropriately
- [ ] Added any custom rules for specific threats

**Verify Rule Syntax**:
```bash
docker-compose up -d suricata
docker exec honeynet-suricata suricata -T -c /etc/suricata/suricata.yaml
# Should show: "Configuration provided was successfully loaded"
```

---

### ☐ 2.5 Data Pipeline

- [ ] Reviewed Logstash pipelines in `configs/logstash/pipelines/`
- [ ] Verified GeoIP filter enabled (before anonymization)
- [ ] Verified IP anonymization using ANON_SECRET_KEY
- [ ] Verified MITRE extraction in Suricata pipeline
- [ ] Verified exploit detection patterns (Shellshock, SQLi, etc.)

---

## Phase 3: Deployment

### ☐ 3.1 Initial Deployment

- [ ] Created data directories: `mkdir -p data/{cowrie,dionaea,conpot,suricata,zeek,clickhouse,grafana,logstash}`
- [ ] Set proper permissions: `chown -R 1000:1000 data/` (adjust UID if needed)
- [ ] Started services: `docker-compose up -d`
- [ ] Waited for services to stabilize (60+ seconds)
- [ ] Verified all containers running: `docker-compose ps`

**Expected Output**:
```
NAME                    STATUS
honeynet-cowrie         Up
honeynet-dionaea        Up
honeynet-conpot         Up
honeynet-suricata       Up
honeynet-zeek           Up
honeynet-clickhouse     Up (healthy)
honeynet-logstash       Up
honeynet-grafana        Up (healthy)
honeynet-jupyter        Up
```

---

### ☐ 3.2 Service Verification

- [ ] Ran `python3 tests/test_ports.py` - all ports accessible
- [ ] Ran `python3 tests/test_isolation.py` - DMZ isolation working
- [ ] Ran `python3 tests/test_e2e.py` - all containers healthy
- [ ] ClickHouse accessible: `curl http://localhost:8123/ping` → "Ok."
- [ ] Grafana accessible: `http://localhost:3000` (login works)
- [ ] Jupyter accessible: `http://localhost:8888` (token works)

---

### ☐ 3.3 Database Initialization

- [ ] ClickHouse schema initialized (check `init-schema.sql` was applied)
- [ ] Verified tables exist:
  ```sql
  docker exec honeynet-clickhouse clickhouse-client --query="SHOW TABLES FROM honeynet"
  ```
  Expected: `honeypot_events`, `ids_alerts`, `network_connections`, `http_requests`, `credentials`, `downloaded_files`, `attacker_profiles`

- [ ] Verified materialized views created:
  ```sql
  docker exec honeynet-clickhouse clickhouse-client --query="
  SHOW CREATE TABLE honeynet.attacker_profile_aggregator
  "
  ```

---

## Phase 4: Testing & Validation

### ☐ 4.1 Functional Testing

- [ ] Ran attack scenario tests: `python3 tests/test_scenarios.py --scenario all`
- [ ] **True Positive Rate (TPR)**: ≥80% achieved
- [ ] **False Positive Rate (FPR)**: ≤5% achieved
- [ ] All attack scenarios detected by honeypot or IDS

**Test Results**:
```
Total Scenarios: 9
Executed: 9
Honeypot Detected: ___ (___%)
IDS Detected: ___ (___%)
TPR: ___% (Required: ≥80%)
```

---

### ☐ 4.2 Data Pipeline Validation

- [ ] Events appearing in `honeypot_events` table
- [ ] Alerts appearing in `ids_alerts` table
- [ ] `source_ip_country` populated (GeoIP working)
- [ ] `mitre_technique_id` populated in alerts
- [ ] IP addresses anonymized (no plain IPs in database)

**Verification Queries**:
```sql
-- Check recent events
SELECT count() FROM honeynet.honeypot_events WHERE timestamp >= now() - INTERVAL 1 HOUR;

-- Check GeoIP working
SELECT source_ip_country, count() FROM honeynet.honeypot_events
WHERE timestamp >= now() - INTERVAL 1 HOUR GROUP BY source_ip_country;

-- Check MITRE mapping
SELECT mitre_technique_id, count() FROM honeynet.ids_alerts
WHERE timestamp >= now() - INTERVAL 1 HOUR AND mitre_technique_id != ''
GROUP BY mitre_technique_id;
```

---

### ☐ 4.3 Detection Effectiveness

**SSH Brute-Force Test**:
- [ ] Executed: `hydra -l root -P passwords.txt ssh://localhost`
- [ ] Detected in Cowrie: `SELECT * FROM credentials WHERE timestamp >= now() - INTERVAL 5 MINUTE;`
- [ ] Detected in Suricata: `SELECT * FROM ids_alerts WHERE signature_id IN (2000005, 1000001) AND timestamp >= now() - INTERVAL 5 MINUTE;`

**Shellshock Test**:
- [ ] Executed: `curl -H "User-Agent: () { :; }; echo test" http://localhost/`
- [ ] Detected in Dionaea: `SELECT * FROM honeypot_events WHERE is_exploit='1' AND timestamp >= now() - INTERVAL 5 MINUTE;`
- [ ] Detected in Suricata: `SELECT * FROM ids_alerts WHERE signature_id IN (2000008, 2000009) AND timestamp >= now() - INTERVAL 5 MINUTE;`

**Lateral Movement Test**:
- [ ] Executed: `docker exec honeynet-cowrie ssh root@172.20.0.11`
- [ ] Detected in IDS: `SELECT * FROM ids_alerts WHERE signature_id = 2000035 AND timestamp >= now() - INTERVAL 5 MINUTE;`

---

### ☐ 4.4 PCAP Offline Testing (Optional)

- [ ] Downloaded attack PCAPs to `tests/pcaps/`
- [ ] Ran Suricata offline: `docker exec honeynet-suricata suricata -r /data/pcaps/test.pcap ...`
- [ ] Verified expected alerts generated
- [ ] Compared with known good baseline

---

## Phase 5: Monitoring & Automation

### ☐ 5.1 Automated Monitoring

- [ ] Health check script tested: `./scripts/monitoring/health_check.sh`
- [ ] Daily report script tested: `./scripts/monitoring/daily_report.sh`
- [ ] Email alerts configured and tested
- [ ] Cron jobs added:
  ```bash
  # Health check (6 AM)
  0 6 * * * /opt/HoneyNetV2/scripts/monitoring/health_check.sh

  # Daily report (8 AM)
  0 8 * * * /opt/HoneyNetV2/scripts/monitoring/daily_report.sh

  # Log rotation (2 AM)
  0 2 * * * /opt/HoneyNetV2/scripts/maintenance/log_rotation.sh

  # ClickHouse optimization (3 AM)
  0 3 * * * docker exec honeynet-clickhouse clickhouse-client --query="OPTIMIZE TABLE honeynet.honeypot_events"
  ```

---

### ☐ 5.2 Backup Configuration

- [ ] Backup playbook tested: `ansible-playbook -i ansible/inventory/hosts.ini ansible/playbooks/99-backup.yml`
- [ ] Backup directory configured: `/opt/honeynet_backups/`
- [ ] Automated daily backup scheduled:
  ```bash
  # Daily backup (4 AM)
  0 4 * * * EXPORT_DAYS=1 ansible-playbook -i /opt/HoneyNetV2/ansible/inventory/hosts.ini /opt/HoneyNetV2/ansible/playbooks/99-backup.yml
  ```
- [ ] Off-site backup configured (S3, SCP, or rsync)
- [ ] Backup restoration tested successfully

---

### ☐ 5.3 Alerting

- [ ] Grafana alerts configured for:
  - High event rate (>1000 events/minute)
  - Service downtime
  - Disk space critical (>85%)
  - High-severity IDS alerts
- [ ] Email notifications tested
- [ ] Alert thresholds tuned to avoid noise

---

## Phase 6: Performance & Stability

### ☐ 6.1 Resource Monitoring

- [ ] Baseline resource usage documented:
  ```bash
  docker stats --no-stream > /tmp/baseline_stats.txt
  ```
- [ ] No container exceeding memory limits
- [ ] CPU usage stable (<80% average)
- [ ] Disk I/O acceptable
- [ ] Network throughput adequate

---

### ☐ 6.2 Load Testing

- [ ] Stress test executed:
  - High connection rate (100+ connections/minute)
  - Sustained attack for 1 hour
  - Multiple protocols simultaneously
- [ ] System remained stable under load
- [ ] No event loss detected
- [ ] Logstash processing lag <60 seconds

**Verification**:
```sql
-- Check event ingestion rate
SELECT
    toStartOfMinute(timestamp) as minute,
    count() as events
FROM honeynet.honeypot_events
WHERE timestamp >= now() - INTERVAL 1 HOUR
GROUP BY minute
ORDER BY minute;
```

---

### ☐ 6.3 Data Integrity

- [ ] No duplicate events in database
- [ ] Timestamps correct (UTC)
- [ ] All expected fields populated
- [ ] No data corruption detected

---

## Phase 7: Documentation & Knowledge Transfer

### ☐ 7.1 Documentation Complete

- [ ] `docs/architecture.md` reviewed and accurate
- [ ] `docs/testing_guide.md` complete
- [ ] `docs/data_schema.md` matches actual schema
- [ ] `docs/configuration.md` reflects deployment
- [ ] `docs/maintenance.md` procedures documented
- [ ] `README.md` updated with new documentation links

---

### ☐ 7.2 Runbooks

- [ ] Incident response procedures documented
- [ ] Backup/restore procedures tested and documented
- [ ] Troubleshooting guide complete
- [ ] Contact information for on-call support

---

### ☐ 7.3 Team Training

- [ ] Team trained on:
  - Accessing Grafana dashboards
  - Querying ClickHouse
  - Running Jupyter notebooks
  - Responding to alerts
  - Backup/restore procedures

---

## Phase 8: Security Review

### ☐ 8.1 Security Hardening

- [ ] All default passwords changed
- [ ] SSH key-based authentication configured
- [ ] Unnecessary services disabled
- [ ] Host firewall configured correctly
- [ ] Docker socket not exposed externally
- [ ] Grafana/Jupyter not exposed to public internet (use SSH tunnel or VPN)

---

### ☐ 8.2 Isolation Verification

- [ ] Honeypot containers CANNOT reach internet:
  ```bash
  docker exec honeynet-cowrie curl -v http://google.com --connect-timeout 5
  # Should FAIL
  ```
- [ ] Lateral movement between honeypots triggers alerts
- [ ] No unexpected network connections from containers

---

### ☐ 8.3 Privacy Compliance

- [ ] IP anonymization working (no plain IPs in database)
- [ ] ANON_SECRET_KEY stored securely (not in git)
- [ ] Data retention policy configured (90 days)
- [ ] GDPR compliance reviewed (if applicable)

---

## Phase 9: Production Readiness

### ☐ 9.1 Final Checks

- [ ] All containers have `restart: unless-stopped` in docker-compose.yml
- [ ] System survives reboot test:
  ```bash
  sudo reboot
  # After reboot:
  docker-compose ps  # All containers should auto-start
  ```
- [ ] Logs rotating properly
- [ ] Disk space projections calculated (won't fill up during campaign)

**Disk Space Projection**:
```
Current daily growth: ___ GB/day
Campaign duration: 30 days
Estimated space needed: ___ GB
Available space: ___ GB
Safety margin: ___ GB
```

---

### ☐ 9.2 Monitoring Dashboard

- [ ] Grafana dashboards imported and configured:
  - Attack Overview
  - Honeypot Health
  - MITRE ATT&CK Heatmap
  - Geographic Distribution
  - Credential Analysis
- [ ] Dashboard access tested from analyst workstation
- [ ] Real-time data updating correctly

---

### ☐ 9.3 Data Analysis Environment

- [ ] Jupyter accessible and notebooks tested
- [ ] Python libraries installed (pandas, numpy, matplotlib, clickhouse-driver)
- [ ] Sample analysis notebook created
- [ ] Data export tested (Parquet format)

---

## Phase 10: Go-Live

### ☐ 10.1 Pre-Launch

- [ ] **Final backup** before production:
  ```bash
  EXPORT_DAYS=30 ansible-playbook -i ansible/inventory/hosts.ini ansible/playbooks/99-backup.yml
  ```
- [ ] **Baseline metrics** captured for comparison
- [ ] **Go-live date** scheduled: **2025-11-01**
- [ ] **Team notified** of deployment
- [ ] **On-call schedule** established for first week

---

### ☐ 10.2 Launch Day

- [ ] All systems online and healthy
- [ ] First attacks detected and logged correctly
- [ ] Dashboards updating in real-time
- [ ] Alerts functioning
- [ ] No critical errors in logs

**Launch Day Verification** (run every hour):
```bash
# Quick health check
docker-compose ps
./scripts/monitoring/health_check.sh

# Check event ingestion
docker exec honeynet-clickhouse clickhouse-client --query="
SELECT count() as events_last_hour
FROM honeynet.honeypot_events
WHERE timestamp >= now() - INTERVAL 1 HOUR
"
```

---

### ☐ 10.3 Post-Launch Monitoring (First 48 Hours)

- [ ] Monitor continuously for first 24 hours
- [ ] Check for anomalies or unexpected behavior
- [ ] Verify TPR/FPR remain within thresholds
- [ ] Adjust alert thresholds if needed
- [ ] Document any issues and resolutions

---

## Phase 11: Campaign Execution (November 2025)

### ☐ 11.1 Weekly Tasks

- [ ] **Monday**: Review weekly report
- [ ] **Wednesday**: Check disk space, backup status
- [ ] **Friday**: Update IDS rules if new threats emerge
- [ ] **Daily**: Brief review of Grafana dashboard (5 minutes)

---

### ☐ 11.2 Monthly Tasks

- [ ] Full system health audit
- [ ] Review and update IDS rules
- [ ] Analyze attacker trends
- [ ] Backup verification (test restore)
- [ ] Disk space projection update

---

## Sign-Off

### Deployment Team

- [ ] **System Administrator**: _____________________ Date: _______
- [ ] **Security Analyst**: _____________________ Date: _______
- [ ] **Project Lead**: _____________________ Date: _______

### Final Approval

- [ ] **READY FOR PRODUCTION**: YES / NO
- [ ] **Go-Live Date**: 2025-11-01
- [ ] **Expected Duration**: 30 days (2025-11-01 to 2025-11-30)

---

## Emergency Contacts

**On-Call Support**:
- Name: _____________________
- Phone: _____________________
- Email: _____________________

**Escalation**:
- Name: _____________________
- Phone: _____________________
- Email: _____________________

---

## Post-Campaign

### ☐ After Campaign Ends (2025-12-01)

- [ ] **Final backup** with full data export:
  ```bash
  EXPORT_DAYS=30 ansible-playbook -i ansible/inventory/hosts.ini ansible/playbooks/99-backup.yml
  ```
- [ ] Data exported to Parquet for Agent #8 analysis
- [ ] Effectiveness report generated (TPR/FPR final statistics)
- [ ] System kept running or gracefully shut down (decision required)

---

**Checklist Version**: 1.0
**Last Updated**: 2025-10-24
**Author**: Agent #6b - Testing & Documentation
