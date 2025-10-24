# HoneyNetV2 Maintenance Scripts

This directory contains maintenance and utility scripts for the HoneyNetV2 honeypot system.

## Scripts Overview

### 1. `log_rotation.sh` 📁
**Purpose**: Automatic log rotation, compression, and archival

**Features**:
- Rotates large log files (>100MB for honeypots, >500MB for Suricata)
- Compresses old logs with gzip -9
- Archives logs older than `LOG_RETENTION_DAYS`
- Cleans up archived files older than 90 days
- Covers all components: Cowrie, Dionaea, Conpot, Suricata, Zeek

**Usage**:
```bash
# Manual execution
/opt/iot-honeynet/scripts/maintenance/log_rotation.sh

# Check log
tail -f /opt/iot-honeynet/logs/log_rotation.log
```

**Cron Setup**:
```bash
# Add to crontab (runs daily at 2 AM)
0 2 * * * /opt/iot-honeynet/scripts/maintenance/log_rotation.sh
```

**Configuration** (in `.env`):
```bash
LOG_RETENTION_DAYS=30  # Days before archiving
```

---

### 2. `update_attacker_profiles.sh` 👤
**Purpose**: Update attacker profiles with latest activity data

**Features**:
- Creates new attacker profiles from last 24h events
- Updates credential attempt statistics
- Updates file download counts
- Displays top 10 most active attackers
- Sends email summary (if configured)

**Usage**:
```bash
# Manual execution
/opt/iot-honeynet/scripts/maintenance/update_attacker_profiles.sh

# Check log
tail -f /opt/iot-honeynet/logs/attacker_profiles.log
```

**Cron Setup**:
```bash
# Add to crontab (runs daily at 4 AM)
0 4 * * * /opt/iot-honeynet/scripts/maintenance/update_attacker_profiles.sh
```

**What it does**:
1. Reads last 24h of `honeypot_events`
2. Creates new profiles for previously unseen attackers
3. Updates existing profiles with:
   - Credential attempts from `credentials` table
   - File downloads from `downloaded_files` table
4. Generates statistics and summary

---

### 3. `system_status.sh` 📊
**Purpose**: Display comprehensive system health and statistics

**Features**:
- Docker container status check
- Database event statistics (last 24h)
- Geographic attack distribution
- MITRE ATT&CK technique detection
- Data quality checks (GeoIP and MITRE coverage)
- Lateral movement detection
- Disk space usage
- Recent errors from logs
- Top 10 attackers

**Usage**:
```bash
# Run status check
/opt/iot-honeynet/scripts/maintenance/system_status.sh

# Example output includes:
# - Container health: ✓ Running / ⚠ Warning / ✗ Error
# - Event counts per table
# - Top attacking countries
# - MITRE techniques observed
# - Data quality metrics
# - Disk usage
```

**When to use**:
- Daily health monitoring
- Pre-deployment verification
- Troubleshooting issues
- Monthly reporting

---

## Recommended Cron Schedule

Add these to your crontab for automated maintenance:

```bash
# Edit crontab
crontab -e

# Add these lines:

# Log rotation - Daily at 2 AM
0 2 * * * /opt/iot-honeynet/scripts/maintenance/log_rotation.sh

# Attacker profiles update - Daily at 4 AM
0 4 * * * /opt/iot-honeynet/scripts/maintenance/update_attacker_profiles.sh

# Weekly backup - Sundays at 3 AM
0 3 * * 0 EXPORT_DAYS=7 /usr/local/bin/ansible-playbook /opt/iot-honeynet/ansible/playbooks/99-backup.yml

# Daily system status email - 8 AM (if email configured)
0 8 * * * /opt/iot-honeynet/scripts/maintenance/system_status.sh | mail -s "HoneyNetV2 Daily Status" admin@example.com

# Monthly full export - 1st day of month at 1 AM
0 1 1 * * EXPORT_DAYS=30 /usr/local/bin/ansible-playbook /opt/iot-honeynet/ansible/playbooks/99-backup.yml
```

---

## Configuration

All scripts use environment variables that can be set in `.env`:

```bash
# Project root directory
PROJECT_ROOT=/opt/iot-honeynet

# ClickHouse container name
CLICKHOUSE_CONTAINER=honeynet-clickhouse

# Log retention (days before archiving)
LOG_RETENTION_DAYS=30

# Email for notifications (optional)
ALERT_EMAIL=admin@example.com

# Parquet export time range (days)
EXPORT_DAYS=7
```

---

## Logging

All scripts create logs in `/opt/iot-honeynet/logs/`:

| Script | Log File | Purpose |
|--------|----------|---------|
| `log_rotation.sh` | `log_rotation.log` | Rotation operations, file sizes |
| `update_attacker_profiles.sh` | `attacker_profiles.log` | Profile updates, statistics |

**Viewing logs**:
```bash
# Latest log rotation
tail -f /opt/iot-honeynet/logs/log_rotation.log

# Latest profile updates
tail -f /opt/iot-honeynet/logs/attacker_profiles.log

# Last 24 hours of all logs
find /opt/iot-honeynet/logs -type f -mtime -1 -exec tail {} \;
```

---

## Troubleshooting

### Script Permission Denied

**Issue**: `bash: ./script.sh: Permission denied`

**Solution**:
```bash
chmod +x /opt/iot-honeynet/scripts/maintenance/*.sh
```

### ClickHouse Connection Failed

**Issue**: Scripts can't connect to ClickHouse

**Checks**:
1. Container running: `docker ps | grep clickhouse`
2. Container name: `docker ps -f name=honeynet-clickhouse`
3. Network access: `docker exec honeynet-clickhouse clickhouse-client --query="SELECT 1"`

**Solution**:
```bash
# Restart ClickHouse
docker-compose restart clickhouse

# Check logs
docker logs honeynet-clickhouse --tail 50
```

### Disk Space Full

**Issue**: Log rotation fails due to disk space

**Checks**:
```bash
# Check disk usage
df -h

# Check Docker volumes
docker system df -v

# Check data directories
du -sh /opt/iot-honeynet/data/*
```

**Solution**:
```bash
# Emergency cleanup
docker system prune -a --volumes  # WARNING: Removes ALL unused data

# Or selective cleanup
find /opt/iot-honeynet/archives -type f -mtime +90 -delete
find /opt/iot-honeynet/data -name "*.gz" -mtime +60 -delete
```

### Email Notifications Not Working

**Issue**: Scripts don't send emails

**Checks**:
1. `ALERT_EMAIL` set in `.env`
2. `mail` command available: `which mail`
3. SMTP configured on system

**Solution**:
```bash
# Install mailutils
apt-get install mailutils

# Or use sendmail
apt-get install sendmail

# Test email
echo "Test" | mail -s "Test" your-email@example.com
```

---

## Integration with Ansible

These scripts are complementary to Ansible playbooks:

| Task | Tool | Frequency |
|------|------|-----------|
| Full system backup | Ansible `99-backup.yml` | Weekly |
| Log rotation | `log_rotation.sh` | Daily |
| Profile updates | `update_attacker_profiles.sh` | Daily |
| System status | `system_status.sh` | On-demand |

---

## Performance Considerations

| Script | CPU Impact | Duration | Best Time |
|--------|------------|----------|-----------|
| `log_rotation.sh` | Low-Medium (compression) | 5-15 min | 2-3 AM (low traffic) |
| `update_attacker_profiles.sh` | Medium (SQL queries) | 2-5 min | 4 AM (after rotation) |
| `system_status.sh` | Low (read-only queries) | 30-60 sec | Anytime |

**Tips**:
- Run resource-intensive tasks during low-activity hours (2-5 AM)
- Stagger cron jobs to avoid overlapping execution
- Monitor system resources during first runs

---

## Security Notes

### Script Execution
- Run scripts as `root` or with appropriate `sudo` permissions
- Docker commands require user to be in `docker` group
- Sensitive data (IP hashes) remains anonymized in all outputs

### Log File Security
```bash
# Set appropriate permissions
chmod 750 /opt/iot-honeynet/scripts/maintenance/
chmod 640 /opt/iot-honeynet/logs/*.log

# Logs contain:
# ✓ Anonymized IP hashes
# ✓ Statistics and counts
# ✗ NO raw IP addresses
# ✗ NO sensitive credentials
```

---

## Maintenance Checklist

### Daily
- [x] Automated log rotation (cron)
- [x] Automated profile updates (cron)
- [ ] Review system status output
- [ ] Check disk space usage

### Weekly
- [ ] Review top attackers
- [ ] Check GeoIP and MITRE coverage
- [ ] Verify Parquet backups
- [ ] Test restore procedure (monthly)

### Monthly
- [ ] Full 30-day data export
- [ ] Archive cleanup (>90 days)
- [ ] Review and tune IDS rules
- [ ] Update GeoIP database

### Quarterly
- [ ] System security audit
- [ ] Database optimization (OPTIMIZE TABLE)
- [ ] Review and update documentation
- [ ] Test disaster recovery procedures

---

## Getting Help

1. **Check logs first**: All scripts log to `/opt/iot-honeynet/logs/`
2. **Run system status**: `./system_status.sh` provides diagnostics
3. **Review main docs**: See `/opt/iot-honeynet/docs/AGENT_6A_ENHANCEMENTS.md`
4. **Container logs**: `docker logs <container-name>`

---

## Change Log

### 2025-10-24 - Agent #6a
- ✅ Created `log_rotation.sh`
- ✅ Created `update_attacker_profiles.sh`
- ✅ Created `system_status.sh`
- ✅ Added comprehensive error handling
- ✅ Added email notifications
- ✅ Added detailed logging

---

**Version**: 1.0
**Last Updated**: 2025-10-24
**Maintainer**: HoneyNetV2 Team
