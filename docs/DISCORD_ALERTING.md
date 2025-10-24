# Discord Alerting Integration for HoneyNetV2

## Overview

HoneyNetV2 uses Grafana's Unified Alerting system to send real-time security notifications to Discord channels. This integration enables immediate awareness of critical security events, coordinated attack patterns, and infrastructure issues.

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐     ┌──────────────┐
│  ClickHouse │────▶│   Grafana    │────▶│   Discord   │────▶│  Security    │
│  Database   │     │   Alerting   │     │   Webhook   │     │    Team      │
└─────────────┘     └──────────────┘     └─────────────┘     └──────────────┘
       ▲                    │
       │                    │
       │                    ▼
┌─────────────┐     ┌──────────────┐
│  Honeypots  │     │  Alert Rules │
│  & IDS      │     │  Evaluation  │
└─────────────┘     └──────────────┘
```

## Features

### Alert Categories

1. **Critical Alerts** (sent to critical channel with @here mention):
   - High rate of Suricata alerts (>1000/min)
   - Excessive honeypot connections (>500/min)
   - ICS/SCADA protocol attacks

2. **High Severity Alerts** (sent to main security channel):
   - Malware capture events
   - Brute force attacks (>50 attempts in 10 min)
   - Infrastructure issues

3. **Warning Alerts** (sent to main security channel):
   - Log processing pipeline delays
   - Resource constraints
   - Unusual patterns

### Alert Rules

#### 1. Suricata High Alert Rate
- **Trigger**: >1000 alerts per minute
- **Duration**: 2 minutes sustained
- **Purpose**: Detect scanning/attack campaigns
- **Severity**: Critical

#### 2. Honeypot Connection Spike
- **Trigger**: >500 connections per minute across all honeypots
- **Duration**: 3 minutes sustained
- **Purpose**: Identify coordinated attacks or botnets
- **Severity**: Critical

#### 3. Malware Captured
- **Trigger**: Any malware binary captured by Dionaea
- **Duration**: 1 minute
- **Purpose**: Immediate notification of malware activity
- **Severity**: High

#### 4. SSH/Telnet Brute Force Attack
- **Trigger**: >50 failed auth attempts from single IP in 10 minutes
- **Duration**: 5 minutes sustained
- **Purpose**: Track credential stuffing attempts
- **Severity**: High

#### 5. ICS/SCADA Protocol Attack
- **Trigger**: >10 write/command operations on industrial protocols
- **Duration**: 5 minutes sustained
- **Purpose**: Detect targeting of critical infrastructure
- **Severity**: High

#### 6. Log Processing Pipeline Lag
- **Trigger**: >5 minutes delay in log processing
- **Duration**: 5 minutes sustained
- **Purpose**: Ensure data pipeline health
- **Severity**: Warning

## Setup Instructions

### Step 1: Create Discord Webhook

1. **Open Discord** and navigate to your server
2. **Server Settings** → **Integrations** → **Webhooks**
3. **Create Webhook** or **New Webhook**
4. **Configure webhook**:
   - Name: `HoneyNet Security Alerts`
   - Channel: Select your security alerts channel (e.g., `#security-alerts`)
   - Copy the **Webhook URL**
5. **(Optional)** Create a second webhook for critical alerts:
   - Name: `HoneyNet Critical Alerts`
   - Channel: Select critical alerts channel (e.g., `#critical-incidents`)
   - Copy the **Webhook URL**

### Step 2: Configure Environment Variables

1. **Copy environment template** (if not already done):
   ```bash
   cp .env.example .env
   ```

2. **Edit `.env` file** and add your Discord webhook URLs:
   ```bash
   # Main security alerts webhook (REQUIRED)
   DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/1234567890/abcdefghijklmnopqrstuvwxyz

   # Critical alerts webhook (OPTIONAL - uses main webhook if not set)
   DISCORD_WEBHOOK_CRITICAL_URL=https://discord.com/api/webhooks/0987654321/zyxwvutsrqponmlkjihgfedcba
   ```

3. **Save the file**

### Step 3: Restart Grafana

After configuring webhooks, restart Grafana to load the new alerting configuration:

```bash
docker-compose restart grafana
```

Or restart the entire stack:

```bash
docker-compose down
docker-compose up -d
```

### Step 4: Verify Configuration

1. **Check Grafana logs** for any errors:
   ```bash
   docker-compose logs grafana | grep -i alert
   ```

2. **Access Grafana UI**:
   - Navigate to: http://localhost:3000
   - Login with credentials from `.env` file
   - Go to: **Alerting** → **Contact points**
   - Verify "Discord Security Alerts" and "Discord Critical Alerts" are present

3. **Check alert rules**:
   - Go to: **Alerting** → **Alert rules**
   - Verify all 6 alert rules are loaded
   - Check that rules are in "Normal" or "Pending" state

## Testing Alerts

### Test Script

A test script is provided to simulate attack scenarios and trigger alerts:

```bash
# Make script executable
chmod +x scripts/test/test_discord_alerts.sh

# Run all alert tests
./scripts/test/test_discord_alerts.sh all

# Test specific alert
./scripts/test/test_discord_alerts.sh suricata
./scripts/test/test_discord_alerts.sh brute-force
./scripts/test/test_discord_alerts.sh malware
```

### Manual Testing

#### Test 1: Send Test Alert from Grafana UI

1. Open Grafana → **Alerting** → **Contact points**
2. Click **"Discord Security Alerts"**
3. Click **"Test"** button
4. Check Discord channel for test message

#### Test 2: Trigger Suricata High Alert Rate

```bash
# Generate 1500 test connections to trigger alert
for i in {1..1500}; do
    # Test SSH honeypot
    timeout 1 nc localhost 22 &
    # Test HTTP honeypot
    timeout 1 curl http://localhost:80 &
done
wait

# Wait 2-3 minutes for alert evaluation
echo "Alert should trigger in ~2 minutes. Check Discord channel."
```

#### Test 3: Trigger Brute Force Alert

```bash
# Attempt multiple SSH connections to Cowrie
for i in {1..60}; do
    sshpass -p "wrong_password" ssh -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        test@localhost -p 22 2>/dev/null &
done
wait

# Alert should trigger after 5 minutes of sustained attempts
```

## Alert Message Format

### Standard Alert
```
HoneyNetV2 Security Alert

Alert Name: SuricataHighAlertRate
Severity: critical
Status: Firing

Summary: High rate of Suricata alerts detected

Details:
- Source: suricata
- Value: 1250 alerts/min
- Time: 2025-10-24 14:32:15 UTC
- Description: Suricata is generating more than 1000 alerts per minute...

Dashboard: [View in Grafana](http://localhost:3000)
```

### Critical Alert
```
🚨 CRITICAL SECURITY INCIDENT 🚨

@here IMMEDIATE ATTENTION REQUIRED

Alert: SuricataHighAlertRate
Severity: CRITICAL
Status: Firing

Summary: High rate of Suricata alerts detected

Critical Details:
⚠️ Source: suricata
📈 Value: 1250 alerts/min
🕐 Triggered: 2025-10-24 14:32:15 UTC
📝 Description: Suricata is generating more than 1000 alerts per minute...
📖 Runbook: Check Suricata logs and investigate source IPs...

Action Required: Review the dashboard immediately
🔗 Dashboard: http://localhost:3000
```

## Alert Routing

Alerts are routed to appropriate channels based on severity labels:

| Severity | Channel | Group Interval | Repeat Interval | Notes |
|----------|---------|----------------|-----------------|-------|
| Critical | Discord Critical Alerts | 2 min | 1 hour | @here mention |
| High | Discord Security Alerts | 5 min | 2 hours | Standard |
| Warning | Discord Security Alerts | 10 min | 6 hours | Standard |

## Customization

### Modifying Alert Rules

Alert rules are defined in: `configs/grafana/provisioning/alerting/rules.yml`

To modify thresholds:

1. Edit the rule file
2. Adjust `params` values in threshold conditions
3. Restart Grafana: `docker-compose restart grafana`

Example - Change Suricata alert threshold to 500/min:

```yaml
conditions:
  - evaluator:
      params:
        - 500  # Changed from 1000
      type: gt
```

### Customizing Message Templates

Message templates are in: `configs/grafana/provisioning/alerting/contactpoints.yml`

Modify the `message` field to change alert format:

```yaml
message: |-
  **Custom Alert Format**
  Alert: {{ .CommonLabels.alertname }}
  Value: {{ .ValueString }}
```

### Adding New Alert Rules

1. Edit `configs/grafana/provisioning/alerting/rules.yml`
2. Add new rule under the `rules` section
3. Define query, condition, and labels
4. Restart Grafana

Template:

```yaml
- uid: your-custom-alert
  title: Your Custom Alert
  condition: C
  data:
    - refId: A
      model:
        rawSql: |
          SELECT count() FROM your_table
          WHERE conditions
  annotations:
    summary: "Alert description"
    description: "Detailed alert information"
  labels:
    severity: critical
    source: your_source
    alertname: YourCustomAlert
```

## Troubleshooting

### Alerts Not Sending

1. **Check webhook URLs**:
   ```bash
   # Verify environment variables
   docker-compose exec grafana env | grep DISCORD
   ```

2. **Test webhook manually**:
   ```bash
   curl -X POST "YOUR_WEBHOOK_URL" \
     -H "Content-Type: application/json" \
     -d '{"content": "Test message from HoneyNetV2"}'
   ```

3. **Check Grafana logs**:
   ```bash
   docker-compose logs -f grafana | grep -i "discord\|alert\|error"
   ```

4. **Verify alert rule state**:
   - Open Grafana UI
   - Navigate to: **Alerting** → **Alert rules**
   - Check rule state (should be "Normal", "Pending", or "Firing")
   - Click rule to see evaluation details

### Alert Rules Not Evaluating

1. **Check ClickHouse connection**:
   ```bash
   # Test connection from Grafana container
   docker-compose exec grafana wget -qO- \
     "http://clickhouse:8123/?query=SELECT%201"
   ```

2. **Verify data exists**:
   ```bash
   # Check if tables have recent data
   docker-compose exec clickhouse clickhouse-client \
     --query "SELECT max(timestamp) FROM suricata_alerts"
   ```

3. **Check alert rule queries**:
   - Open Grafana UI
   - Navigate to rule → **Preview**
   - Execute query to verify it returns data

### High False Positive Rate

If alerts are triggering too frequently:

1. **Adjust thresholds** in `rules.yml`
2. **Increase `for` duration** to require sustained conditions
3. **Increase `repeat_interval`** in `policies.yml`
4. **Add more specific conditions** to queries

## Best Practices

### Channel Organization

Recommended Discord channel structure:

```
📁 SECURITY MONITORING
├── 📢 #critical-incidents (Critical alerts, @here enabled)
├── 📋 #security-alerts (High/warning alerts)
├── 📊 #security-metrics (Periodic reports, optional)
└── 🔧 #alert-testing (Test alerts)
```

### Alert Response Workflow

1. **Alert Received** → Check Discord notification
2. **Triage** → Review Grafana dashboard for context
3. **Investigation** → Analyze logs in ClickHouse or Jupyter
4. **Documentation** → Record findings in incident log
5. **Response** → Block IPs, update rules, etc.
6. **Post-mortem** → Update alert thresholds if needed

### Rate Limiting

Discord has rate limits:
- 30 requests per 60 seconds per webhook
- Grafana grouping helps prevent hitting limits
- Configure `group_interval` appropriately

### Security Considerations

1. **Protect webhook URLs**:
   - Never commit webhooks to Git
   - Use environment variables only
   - Rotate webhooks if compromised

2. **Channel permissions**:
   - Restrict who can view security channels
   - Use role-based access control
   - Enable audit logging

3. **Alert fatigue**:
   - Tune thresholds to reduce noise
   - Group related alerts
   - Use appropriate severity levels

## Integration with Other Tools

### Slack (Alternative to Discord)

To use Slack instead of Discord:

1. Create Slack App and Incoming Webhook
2. Update contact point type to `slack`
3. Adjust message format for Slack markdown

### Email Notifications

To add email alongside Discord:

1. Configure SMTP in `.env`:
   ```bash
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USER=your-email@gmail.com
   SMTP_PASSWORD=your-app-password
   ```

2. Add email contact point in `contactpoints.yml`
3. Update notification policy to route to both channels

### PagerDuty / Opsgenie

For 24/7 incident management:

1. Configure PagerDuty integration in Grafana
2. Create separate notification policy for critical alerts
3. Route critical incidents to PagerDuty
4. Keep Discord for general awareness

## Maintenance

### Regular Tasks

- **Weekly**: Review alert effectiveness and false positive rate
- **Monthly**: Update alert thresholds based on traffic patterns
- **Quarterly**: Review and update runbooks in alert annotations

### Updating Alert Configuration

1. Edit configuration files in `configs/grafana/provisioning/alerting/`
2. Restart Grafana: `docker-compose restart grafana`
3. Verify changes in Grafana UI
4. Test alerts after changes

### Backup

Alert configurations are version-controlled in Git:
```bash
git add configs/grafana/provisioning/alerting/
git commit -m "Update alert configurations"
```

## References

- [Grafana Unified Alerting Docs](https://grafana.com/docs/grafana/latest/alerting/)
- [Discord Webhook Documentation](https://discord.com/developers/docs/resources/webhook)
- [HoneyNetV2 Architecture](../README.md)
- [ClickHouse Query Performance](https://clickhouse.com/docs/en/sql-reference/)

## Support

For issues or questions:
1. Check Grafana logs: `docker-compose logs grafana`
2. Review this documentation
3. Test alerts manually
4. Open GitHub issue with details

---

**Version**: 1.0
**Last Updated**: 2025-10-24
**Maintained by**: HoneyNetV2 Security Team
