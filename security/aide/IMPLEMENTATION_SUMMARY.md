# AIDE Implementation Summary for HoneyNetV2

## Implementation Status

✅ **COMPLETED** - AIDE configuration for HoneyNetV2 host integrity monitoring

## Files Created

| File | Purpose | Location |
|------|---------|----------|
| `aide.conf` | AIDE configuration with monitoring rules | `security/aide/aide.conf` |
| `aide-init.sh` | Installation and initialization script | `security/aide/aide-init.sh` |
| `aide-cron-setup.sh` | Automated scanning configuration | `security/aide/aide-cron-setup.sh` |
| `aide-test.sh` | Security validation testing suite | `security/aide/aide-test.sh` |
| `README.md` | Comprehensive documentation | `security/aide/README.md` |
| `QUICK_REFERENCE.md` | Quick command reference | `security/aide/QUICK_REFERENCE.md` |

## What AIDE Monitors

### System Components
- System binaries: `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`
- System libraries: `/lib`, `/lib64`, `/usr/lib`
- Boot files: `/boot`
- System configuration: `/etc`
- SSH configuration: `/etc/ssh/`, `/root/.ssh/`
- Network configuration: `/etc/network/`, `/etc/netplan/`, `/etc/hosts`
- Systemd services: `/etc/systemd/system/`
- Cron jobs: `/etc/cron.*`, `/var/spool/cron/`
- PAM configuration: `/etc/pam.d/`
- Sudoers: `/etc/sudoers`, `/etc/sudoers.d/`
- Docker configuration: `/etc/docker/`

### HoneyNetV2 Components
- **Honeypot implementations**:
  - `honeypots/rtsp/rtsp_honeypot.py`
  - `honeypots/upnp/upnp_honeypot.py`
- **All scripts**:
  - Monitoring scripts: `scripts/monitoring/`
  - Maintenance scripts: `scripts/maintenance/`
  - Deployment scripts: `scripts/deployment/`
  - PCAP scripts: `scripts/pcap/`
  - ETL scripts: `scripts/etl/`
- **Configuration files**: All files in `configs/`
- **Docker configuration**: `docker-compose.yml`
- **Documentation**: README and implementation docs
- **Test files**: Files in `tests/` directory

## Notification Options

You have **three notification methods** to choose from:

### Option 1: Email Notifications (Traditional)

**Requirements**:
- Configured SMTP server or local mail system
- Mail Transfer Agent (MTA) like Postfix, Sendmail, or Exim
- Valid administrator email address

**Advantages**:
- Standard, well-established method
- Easy to integrate with existing email workflows
- Good for organizations with email-based alerting

**Setup**:
```bash
sudo ./aide-cron-setup.sh
# Select option 1 (Email)
# Provide admin email address
```

**Email Configuration**:
If you don't have an MTA configured, the script can install `mailutils` which provides basic mail functionality. For production environments, consider:

1. **Local SMTP relay**:
   ```bash
   sudo apt install postfix
   sudo dpkg-reconfigure postfix
   # Select "Internet Site" and configure your domain
   ```

2. **External SMTP relay** (Gmail, SendGrid, etc.):
   Configure Postfix to relay through external SMTP:
   ```bash
   sudo apt install postfix libsasl2-modules
   # Edit /etc/postfix/main.cf with relay settings
   ```

3. **Simple mail forwarding**:
   Use `ssmtp` for basic forwarding to external SMTP:
   ```bash
   sudo apt install ssmtp
   # Edit /etc/ssmtp/ssmtp.conf
   ```

### Option 2: Log File Only (Recommended for Testing)

**Requirements**:
- None (built-in)

**Advantages**:
- No external dependencies
- Always works
- Good for initial testing
- Suitable if you have log aggregation system

**Setup**:
```bash
sudo ./aide-cron-setup.sh
# Select option 2 (Log file only)
```

**Log location**: `/var/log/aide/aide-check-YYYYMMDD_HHMMSS.log`

**Usage**:
- View logs: `sudo ls -lht /var/log/aide/`
- Read latest: `sudo tail -100 /var/log/aide/aide-check-*.log`
- Integrate with log aggregation (Splunk, ELK, etc.)

### Option 3: Discord Webhook (Modern, Real-time)

**Requirements**:
- Discord server (free)
- Webhook URL (generated in Discord server settings)

**Advantages**:
- Real-time notifications
- Rich formatting with embeds
- Easy to set up
- Mobile notifications via Discord app
- Good for team collaboration

**Setup**:

1. Create Discord webhook:
   - Open Discord server settings
   - Go to: Server Settings → Integrations → Webhooks
   - Click "New Webhook"
   - Name it "AIDE Alerts" or similar
   - Copy webhook URL

2. Configure AIDE:
   ```bash
   sudo ./aide-cron-setup.sh
   # Select option 3 (Discord webhook)
   # Paste webhook URL when prompted
   ```

**Example Discord alert**:
```
🔔 AIDE ALERT: Changes Detected!
Status: Changes Detected ⚠️
Timestamp: 2025-01-24T02:00:00Z
Log File: /var/log/aide/aide-check-20250124_020000.log
```

### Option 4: Multiple Methods (Recommended for Production)

**Requirements**:
- Email + Discord configured

**Advantages**:
- Redundancy (if one fails, other still works)
- Email for formal records
- Discord for quick notifications

**Setup**:
```bash
sudo ./aide-cron-setup.sh
# Select option 4 (Multiple methods)
# Provide both email and Discord webhook
```

## Recommended Configuration by Environment

### Development/Testing
- **Recommendation**: Log file only (Option 2)
- **Reason**: Simple, no external dependencies
- **Command**:
  ```bash
  sudo ./aide-cron-setup.sh
  # Select option 2
  ```

### Small Production Deployment
- **Recommendation**: Discord webhook (Option 3)
- **Reason**: Easy setup, real-time alerts, no mail server needed
- **Command**:
  ```bash
  sudo ./aide-cron-setup.sh
  # Select option 3
  # Use webhook: https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN
  ```

### Enterprise Production
- **Recommendation**: Email + Discord (Option 4)
- **Reason**: Redundancy, formal records, team collaboration
- **Command**:
  ```bash
  sudo ./aide-cron-setup.sh
  # Select option 4
  # Email: security@yourdomain.com
  # Discord: Your webhook URL
  ```

## Scan Schedule

**Default schedule**: Daily at 2:00 AM (`0 2 * * *`)

You can customize this during setup. Common schedules:

| Schedule | Cron Expression | Description |
|----------|----------------|-------------|
| Daily at 2 AM | `0 2 * * *` | Default, low-impact |
| Twice daily | `0 2,14 * * *` | 2 AM and 2 PM |
| Every 6 hours | `0 */6 * * *` | 4 times per day |
| Hourly | `0 * * * *` | Maximum frequency |
| Weekly | `0 2 * * 0` | Every Sunday at 2 AM |

## Installation Instructions

### Step 1: Initialize AIDE (One-time)

```bash
cd /opt/HoneyNetV2/security/aide
sudo ./aide-init.sh
```

This will:
1. Install AIDE package
2. Copy configuration to `/etc/aide/aide.conf`
3. Customize paths for your HoneyNetV2 installation
4. Initialize baseline database (may take 5-10 minutes)
5. Set proper permissions

**Duration**: 5-15 minutes depending on system size

### Step 2: Configure Automated Scans

```bash
sudo ./aide-cron-setup.sh
```

Follow the interactive prompts to:
1. Choose notification method
2. Configure email/Discord (if selected)
3. Set scan schedule
4. Optionally run test scan

**Duration**: 2-5 minutes

### Step 3: Validate Installation

```bash
sudo ./aide-test.sh
```

This runs 5 security tests:
1. File creation detection
2. File modification detection
3. Permission change detection
4. File deletion detection
5. HoneyNetV2 script tampering detection

**Duration**: 5-10 minutes (interactive)

## Important Notes

### Database Updates

**Critical**: After making authorized changes to monitored files, you MUST update the AIDE database:

```bash
sudo aide --update
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

**When to update**:
- After system updates (`apt upgrade`)
- After modifying honeypot scripts
- After changing configuration files
- After installing new software in monitored directories

### Database Protection

The AIDE database is the baseline for integrity checking. If an attacker modifies it, they can hide their tracks.

**Best practices**:
1. **Store offline copy**: Keep read-only copy on external media
   ```bash
   sudo cp /var/lib/aide/aide.db /media/usb/aide-backup/aide.db.$(date +%Y%m%d)
   ```

2. **Use filesystem immutability** (optional):
   ```bash
   sudo chattr +i /var/lib/aide/aide.db
   # Remove before updating:
   sudo chattr -i /var/lib/aide/aide.db
   ```

3. **Remote storage**: Copy to secure remote server
   ```bash
   scp /var/lib/aide/aide.db backup@remote:/secure/aide-backup/
   ```

### First Scan Results

The first automated scan after initialization should show:
```
AIDE found no differences between database and filesystem.
```

If the first scan shows changes, this means files changed between initialization and first scan. Review carefully and update database if changes are legitimate.

## Integration with HoneyNetV2 Monitoring

AIDE complements other HoneyNetV2 security components:

| Component | Purpose | What it Detects |
|-----------|---------|----------------|
| **Suricata** | Network IDS | Network-based attacks |
| **Zeek** | Network monitoring | Protocol anomalies |
| **Honeypots** | Attacker capture | Attack techniques |
| **AIDE** | Host integrity | System compromise |
| **Grafana** | Visualization | Centralized alerting |

### Attack Detection Scenario

1. **Suricata** detects exploit attempt → Alerts to Grafana
2. **Honeypot** captures attacker session → Logs to ClickHouse
3. **AIDE** detects system file changes → Emails admin + Discord alert
4. **Admin** correlates all three data sources → Confirms compromise

### Potential Grafana Integration

While AIDE doesn't directly integrate with Grafana, you can:

1. **Parse AIDE logs** with Logstash
2. **Index to ClickHouse** or Elasticsearch
3. **Create Grafana dashboard** showing:
   - Last scan time
   - Number of changes detected
   - Recent alerts
   - Scan status (success/failure)

This can be added as a future enhancement.

## Questions & Answers

### Q: What email address should receive AIDE reports?

**A**: This depends on your organization:

- **Small deployment**: Personal email (e.g., `admin@yourdomain.com`)
- **Team environment**: Security team email or distribution list
- **Enterprise**: SOC/incident response team email

**Recommendation**: Use a monitored email address that is checked daily. Consider using an email alias that forwards to multiple team members for redundancy.

### Q: Is SMTP configured in the environment?

**A**: This varies by installation. Check with:
```bash
which mail sendmail postfix
systemctl status postfix  # or sendmail, exim
```

If not configured, options:
1. **Install and configure**: See email configuration section above
2. **Use Discord instead**: Easier setup, no SMTP needed
3. **Use log files**: Always works, integrate with existing log monitoring

**Our recommendation**: For quick start, use Discord webhook (Option 3) or log files (Option 2). Configure email later if needed.

### Q: Can we integrate with existing alerting systems?

**A**: Yes! Several options:

1. **Email** → Forward to ticketing system (Jira, ServiceNow)
2. **Discord** → Connect to other services via Discord bots
3. **Log files** → Parse with Logstash/Fluentd → Send to SIEM
4. **Custom script** → Modify `/usr/local/bin/aide-check.sh` to call your API

### Q: How do we test without triggering false alarms?

**A**: Use the provided testing script:
```bash
sudo ./aide-test.sh
```

This performs controlled tests and cleans up afterward. It won't trigger production alerts unless you've already configured automated scans.

## Next Steps

1. **Review this document** and choose notification method
2. **Run initialization**: `sudo ./aide-init.sh`
3. **Configure scron**: `sudo ./aide-cron-setup.sh`
4. **Run validation tests**: `sudo ./aide-test.sh`
5. **Monitor first scan** results (next day at scheduled time)
6. **Document** your AIDE configuration in operations runbook
7. **Train team** on interpreting AIDE alerts

## Support

- **Full documentation**: `security/aide/README.md`
- **Quick reference**: `security/aide/QUICK_REFERENCE.md`
- **AIDE manual**: `man aide`
- **HoneyNetV2 docs**: `docs/` directory

## Conclusion

AIDE provides critical host-based integrity monitoring for the HoneyNetV2 system. Combined with network-based detection (Suricata, Zeek) and honeypot capture, it creates a comprehensive security monitoring solution.

**Estimated total setup time**: 20-30 minutes
**Maintenance effort**: 5-10 minutes per day (reviewing alerts)
**Value**: Early detection of system compromise

---

**Implementation Date**: 2025-01-24
**Status**: Ready for deployment
**Recommended Action**: Proceed with installation following Step 1-3 above
