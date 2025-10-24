# AIDE Quick Reference for HoneyNetV2

## Installation (One-Time Setup)

```bash
cd /opt/HoneyNetV2/security/aide
sudo ./aide-init.sh
sudo ./aide-cron-setup.sh
```

## Common Commands

### Run Manual Check
```bash
sudo aide --check
```

### Update Database (After Authorized Changes)
```bash
sudo aide --update
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

### View Recent Logs
```bash
sudo ls -lht /var/log/aide/ | head -10
sudo tail -100 /var/log/aide/aide-check-*.log
```

### Test AIDE Detection
```bash
sudo /opt/HoneyNetV2/security/aide/aide-test.sh
```

### Manual Check Script (with notifications)
```bash
sudo /usr/local/bin/aide-check.sh
```

## Configuration Files

| File | Purpose |
|------|---------|
| `/etc/aide/aide.conf` | Main AIDE configuration |
| `/var/lib/aide/aide.db` | Baseline database |
| `/var/log/aide/` | Scan reports |
| `/etc/cron.d/aide-honeynet` | Automated scan schedule |
| `/usr/local/bin/aide-check.sh` | Check script with notifications |

## Common Tasks

### After System Update
```bash
# Update AIDE baseline after apt upgrade
sudo apt update && sudo apt upgrade
sudo aide --update
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

### After Modifying HoneyNetV2
```bash
# After editing honeypot scripts or configs
sudo aide --update
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

### Temporarily Disable Scans
```bash
sudo chmod -x /usr/local/bin/aide-check.sh
```

### Re-enable Scans
```bash
sudo chmod +x /usr/local/bin/aide-check.sh
```

### View Cron Schedule
```bash
sudo cat /etc/cron.d/aide-honeynet
```

## Interpreting Results

### No Changes (Good)
```
AIDE found no differences between database and filesystem.
```

### Changes Detected (Investigate)
```
Summary:
  Added files:    2
  Removed files:  0
  Changed files:  1
```

### Critical Changes to Investigate

- **System binaries**: `/bin`, `/sbin`, `/usr/bin`
- **SSH configuration**: `/etc/ssh/`
- **Cron jobs**: `/etc/cron.*`
- **Sudoers**: `/etc/sudoers`
- **Honeypot scripts**: `honeypots/*/`

## Emergency Procedures

### Suspected Compromise
1. Isolate system from network
2. Run immediate AIDE check: `sudo aide --check > /tmp/aide-incident.log`
3. Review all changes carefully
4. Compare with external AIDE database copy (if available)
5. Correlate with Suricata/Zeek logs
6. Contact security team

### Database Corruption
```bash
# Backup current database
sudo cp /var/lib/aide/aide.db /var/lib/aide/aide.db.corrupt

# Reinitialize
sudo aide --init
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

### Test Email/Discord Notifications
```bash
# Run manual check (sends notifications)
sudo /usr/local/bin/aide-check.sh
```

## Troubleshooting

### Check AIDE Status
```bash
aide --version
sudo ls -la /var/lib/aide/aide.db
```

### Check Last Scan
```bash
sudo ls -lht /var/log/aide/ | head -1
```

### Test Mail Delivery
```bash
echo "AIDE test" | mail -s "Test" admin@example.com
```

### Test Discord Webhook
```bash
curl -H "Content-Type: application/json" \
     -d '{"content":"AIDE test"}' \
     YOUR_WEBHOOK_URL
```

### View Cron Logs
```bash
sudo journalctl -u cron | grep aide
```

## Security Best Practices

1. **Store database copy offline** - Keep read-only copy on external media
2. **Review reports daily** - Check all AIDE alerts promptly
3. **Update after changes** - Always update baseline after authorized changes
4. **Protect the database** - Consider filesystem immutability:
   ```bash
   sudo chattr +i /var/lib/aide/aide.db
   # Remove immutability when updating:
   sudo chattr -i /var/lib/aide/aide.db
   ```
5. **Correlate with other logs** - Check Suricata/Zeek for context

## Integration with HoneyNetV2

### Check HoneyNetV2 Component Integrity
```bash
# Monitor specific honeypot
sudo aide --check | grep "honeypots/rtsp"

# Monitor all scripts
sudo aide --check | grep "scripts/"

# Monitor configurations
sudo aide --check | grep "configs/"
```

### After Docker Updates
```bash
# AIDE monitors host system, not containers
# Update after modifying docker-compose.yml:
sudo aide --update
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

## Resources

- **Full Documentation**: `/opt/HoneyNetV2/security/aide/README.md`
- **AIDE Manual**: `man aide`
- **Configuration Manual**: `man aide.conf`
- **HoneyNetV2 Docs**: `/opt/HoneyNetV2/docs/`

## Support

1. Check logs: `sudo tail /var/log/aide/aide-check-*.log`
2. Run tests: `sudo ./aide-test.sh`
3. Review configuration: `sudo cat /etc/aide/aide.conf`
4. Consult full documentation in `README.md`
