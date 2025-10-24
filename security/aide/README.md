# AIDE Configuration for HoneyNetV2

## Overview

This directory contains the AIDE (Advanced Intrusion Detection Environment) configuration and management scripts for the HoneyNetV2 host system. AIDE provides file integrity monitoring to detect unauthorized changes to critical system files and honeypot components.

## What is AIDE?

AIDE is a host-based intrusion detection system that:
- Creates a database of file checksums and attributes
- Monitors files for unauthorized changes
- Detects modifications, additions, and deletions
- Helps identify security breaches and system compromises

## Directory Structure

```
security/aide/
├── README.md                 # This file
├── aide.conf                 # AIDE configuration file
├── aide-init.sh              # Installation and initialization script
├── aide-cron-setup.sh        # Automated scanning configuration
└── aide-test.sh              # Security validation tests
```

## Quick Start

### Prerequisites

- Root/sudo access on the host system
- Ubuntu/Debian or RHEL/CentOS Linux distribution
- At least 500MB free disk space for AIDE database

### Installation Steps

1. **Initialize AIDE** (first-time setup):
   ```bash
   cd /opt/HoneyNetV2/security/aide
   sudo ./aide-init.sh
   ```

   This script will:
   - Install AIDE package
   - Configure monitoring rules
   - Create initial baseline database
   - Set proper permissions

2. **Configure Automated Scanning**:
   ```bash
   sudo ./aide-cron-setup.sh
   ```

   Choose your notification method:
   - **Email**: Requires SMTP configuration
   - **Log file only**: Saves reports to `/var/log/aide/`
   - **Discord webhook**: Real-time alerts via Discord
   - **Multiple methods**: Combine email and Discord

3. **Run Security Tests**:
   ```bash
   sudo ./aide-test.sh
   ```

   Validates AIDE can detect:
   - File creation
   - File modification
   - Permission changes
   - File deletion
   - Honeypot script tampering

## Configuration Details

### Monitored Locations

The AIDE configuration monitors:

#### System Files
- **Binaries**: `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/local/bin`
- **Libraries**: `/lib`, `/lib64`, `/usr/lib`, `/usr/lib64`
- **Boot files**: `/boot`
- **System configuration**: `/etc`
- **SSH configuration**: `/etc/ssh/`, `/root/.ssh/`
- **Network configuration**: `/etc/network/`, `/etc/netplan/`, `/etc/hosts`
- **Systemd services**: `/etc/systemd/system/`, `/usr/lib/systemd/system/`
- **Cron jobs**: `/etc/cron.*`, `/var/spool/cron/`
- **PAM configuration**: `/etc/pam.d/`
- **Sudoers**: `/etc/sudoers`, `/etc/sudoers.d/`

#### HoneyNetV2 Components
- **Honeypots**: `honeypots/rtsp/`, `honeypots/upnp/`
- **Scripts**: All scripts in `scripts/` directory
- **Configuration**: All files in `configs/` directory
- **Docker**: `docker-compose.yml`, `/etc/docker/`
- **Documentation**: README files and implementation docs
- **Tests**: Test files (to detect tampering)

### Exclusions

The following are excluded from monitoring (frequent changes expected):
- Temporary directories (`/tmp`, `/var/tmp`)
- Process information (`/proc`, `/sys`, `/dev`)
- Package manager caches (`/var/lib/apt`, `/var/lib/dpkg`)
- Docker runtime data (`/var/lib/docker`)
- Container runtime (`/run`, `/var/run`)
- Log rotations and compressed logs

## Usage

### Manual Integrity Check

Run an immediate check:
```bash
sudo aide --check
```

View detailed output:
```bash
sudo aide --check | less
```

Save report to file:
```bash
sudo aide --check > /tmp/aide-report-$(date +%Y%m%d).txt
```

### After Authorized Changes

When you make legitimate changes to monitored files:

```bash
# Update the baseline database
sudo aide --update

# Install the new database
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

**Important**: Always update AIDE after:
- System updates
- Configuration changes
- Installing new software
- Modifying honeypot scripts

### View Logs

Check AIDE scan logs:
```bash
sudo ls -lh /var/log/aide/
sudo tail -f /var/log/aide/aide-check-*.log
```

### Cron Job Management

View configured cron job:
```bash
sudo cat /etc/cron.d/aide-honeynet
```

Disable automated scans (temporary):
```bash
sudo chmod -x /usr/local/bin/aide-check.sh
```

Re-enable automated scans:
```bash
sudo chmod +x /usr/local/bin/aide-check.sh
```

## Notification Configuration

### Email Notifications

**Requirements**:
- Configured SMTP server
- `mail` or `sendmail` command available
- Valid administrator email address

**Testing email delivery**:
```bash
echo "Test message" | mail -s "AIDE Test" admin@example.com
```

### Discord Webhook Notifications

**Setup**:
1. Create a Discord webhook in your server settings
2. Copy the webhook URL
3. Provide it during `aide-cron-setup.sh` configuration

**Webhook format**:
```
https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN
```

### Log File Only

Reports are saved to `/var/log/aide/` with timestamps:
```
/var/log/aide/aide-check-20250124_020000.log
```

## Interpreting AIDE Reports

### Clean Report (No Changes)

```
AIDE found no differences between database and filesystem.
```

This is the desired state - no unauthorized changes detected.

### Changes Detected

AIDE reports changes in this format:

```
Summary:
  Total number of files:        15234
  Added files:                  1
  Removed files:                0
  Changed files:                2

Added files:
  /etc/malicious.conf

Changed files:
  /etc/ssh/sshd_config

Detailed information about changes:
File: /etc/ssh/sshd_config
  Perm     : -rw-r--r--                       , -rw-rw-rw--
  Size     : 3264                             , 3290
  Mtime    : 2025-01-20 15:30:45              , 2025-01-24 03:15:22
  SHA256   : abc123...                        , def456...
```

**Key indicators**:
- **Added files**: New files created (investigate if unauthorized)
- **Removed files**: Files deleted (investigate if critical)
- **Changed files**: Modified files (review changes carefully)

### Investigating Changes

When AIDE detects changes:

1. **Review the report** carefully
2. **Verify if authorized** - Did you or your team make these changes?
3. **Check for indicators of compromise**:
   - Unexpected changes to `/etc/passwd`, `/etc/shadow`, or `/etc/sudoers`
   - Modified SSH configurations
   - New or changed binaries in `/bin`, `/sbin`, `/usr/bin`
   - New cron jobs
   - Changes to honeypot scripts you didn't make
4. **Correlate with other logs** (Suricata, Zeek, system logs)
5. **Update database** if changes were legitimate

## Security Best Practices

### 1. Protect the AIDE Database

The AIDE database is critical - if attackers modify it, they can hide their tracks.

**Recommendations**:
- Store a read-only copy on external media or remote server
- Use filesystem immutability: `sudo chattr +i /var/lib/aide/aide.db`
- Mount database on read-only filesystem
- Implement database verification with external checksums

### 2. Regular Monitoring

- Review AIDE reports daily
- Investigate all unexpected changes immediately
- Don't ignore alerts - even small changes can indicate compromise

### 3. Database Updates

- Update AIDE database after authorized changes
- Document all updates with reason and timestamp
- Keep change logs for audit trail

### 4. Integration with Incident Response

- Include AIDE alerts in your incident response plan
- Correlate AIDE findings with other security tools
- Use AIDE reports as forensic evidence

### 5. Testing and Validation

- Run `aide-test.sh` periodically to ensure AIDE is working
- Test notification delivery regularly
- Verify database integrity

## Troubleshooting

### AIDE Check Takes Too Long

**Solution**: Reduce monitored files or increase resources
```bash
# Check database size
sudo du -sh /var/lib/aide/aide.db

# Reduce scope by modifying aide.conf to exclude less critical directories
```

### Email Notifications Not Received

**Check**:
```bash
# Verify mail command exists
which mail sendmail

# Check mail logs
sudo tail /var/log/mail.log

# Test mail delivery
echo "test" | mail -s "Test" your@email.com
```

### Discord Webhook Not Working

**Verify**:
```bash
# Test webhook directly
curl -H "Content-Type: application/json" \
     -d '{"content":"Test from AIDE"}' \
     YOUR_WEBHOOK_URL
```

### Database Initialization Fails

**Common causes**:
- Insufficient disk space
- Permission issues
- Corrupted configuration

**Solution**:
```bash
# Check disk space
df -h /var/lib/aide

# Verify permissions
sudo ls -la /var/lib/aide

# Remove and reinitialize
sudo rm -f /var/lib/aide/aide.db*
sudo aide --init
```

### False Positives

Some files change frequently (logs, caches). If you see too many false positives:

1. Review which files are changing
2. Edit `/etc/aide/aide.conf`
3. Add exclusion for those paths
4. Reinitialize database

Example exclusion:
```bash
!/path/to/noisy/file
```

## Integration with HoneyNetV2

AIDE complements other HoneyNetV2 security components:

- **Suricata**: Network intrusion detection
- **Zeek**: Network security monitoring
- **AIDE**: Host-based file integrity monitoring
- **Grafana**: Centralized visualization and alerting

Together, these provide comprehensive security monitoring:
1. Suricata/Zeek detect network attacks
2. Honeypots capture attacker behavior
3. AIDE detects if attackers compromise the host
4. Grafana provides unified dashboard

## Advanced Configuration

### Custom Rules

Edit `/etc/aide/aide.conf` to add custom monitoring rules:

```bash
# Monitor specific file with specific checks
/path/to/critical/file NORMAL

# Monitor directory but exclude subdirectories
/path/to/dir NORMAL
!/path/to/dir/subdir

# Use different rule for log files
/var/log/custom.log LOG

# Monitor only for size growth
/var/log/growing.log GROWING
```

### Database Signing

For additional security, cryptographically sign the AIDE database:

```bash
# Generate GPG key (if not exists)
gpg --gen-key

# Sign database
gpg --detach-sign /var/lib/aide/aide.db

# Verify signature before each check
gpg --verify /var/lib/aide/aide.db.sig /var/lib/aide/aide.db
```

### Remote Database Storage

Store AIDE database on remote server:

```bash
# Copy database to remote server
scp /var/lib/aide/aide.db backup@remote:/secure/aide-backup/

# Compare against remote database
scp backup@remote:/secure/aide-backup/aide.db /tmp/aide.db.remote
aide --compare /tmp/aide.db.remote
```

## Support and References

### Documentation
- AIDE Official: https://aide.github.io/
- AIDE Manual: `man aide`
- Configuration Manual: `man aide.conf`

### HoneyNetV2 Resources
- Main README: `/opt/HoneyNetV2/README.md`
- Security Documentation: `/opt/HoneyNetV2/docs/`

### Getting Help

1. Check AIDE logs: `/var/log/aide/`
2. Review configuration: `/etc/aide/aide.conf`
3. Run tests: `sudo ./aide-test.sh`
4. Check system logs: `sudo journalctl -u cron`

## License

This AIDE configuration is part of the HoneyNetV2 project. Refer to the main project LICENSE file for details.

## Changelog

- **2025-01-24**: Initial AIDE configuration for HoneyNetV2
  - Comprehensive host and honeypot monitoring
  - Multi-channel notifications (email/Discord)
  - Automated testing suite
  - Security hardening guidelines
