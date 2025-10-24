# RTSP Honeypot - Deployment Guide

## Overview

This guide provides step-by-step instructions for deploying the RTSP honeypot as part of HoneyNetV2 infrastructure.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    RTSP Honeypot Flow                       │
└─────────────────────────────────────────────────────────────┘

[Attacker] ──(RTSP/554)──> [RTSP Honeypot Container]
                                    │
                                    ├──> [JSON Logs] ──> [Logstash]
                                    │                         │
                                    │                         ├──> [ClickHouse]
                                    │                         │         │
                                    │                         │         └──> [Grafana]
                                    │                         │
                                    │                         └──> [rtsp_attacks table]
                                    │
                                    └──> [Suricata IDS] ──> [SID 2000015 Alert]
                                    │
                                    └──> [Zeek Monitor] ──> [IoT_Exploit_Attempt Notice]
```

## Prerequisites

1. **Docker** and **Docker Compose** installed
2. **HoneyNetV2** base infrastructure deployed
3. Minimum **256MB RAM** and **0.25 CPU cores** available for RTSP container
4. Port **554/TCP** available on host

## Deployment Steps

### 1. Verify Files

Ensure all RTSP honeypot files are in place:

```bash
# Honeypot implementation
ls -la honeypots/rtsp/
  - rtsp_honeypot.py
  - Dockerfile
  - README.md

# Configuration
ls -la configs/logstash/pipelines/
  - rtsp.conf

# Tests
ls -la tests/rtsp/
  - test_rtsp_honeypot.py
  - test_cve_2014_8361.sh
```

### 2. Create Data Directory

```bash
mkdir -p data/rtsp
chmod 755 data/rtsp
```

This directory will store RTSP honeypot JSON logs.

### 3. Build RTSP Honeypot Image

```bash
cd /path/to/HoneyNetV2
docker-compose build rtsp
```

Expected output:
```
Building rtsp
Step 1/10 : FROM python:3.11-slim
...
Successfully built [image-id]
Successfully tagged honeynet/rtsp:latest
```

### 4. Update ClickHouse Schema (if existing database)

If you have an existing ClickHouse database, you need to alter the `honeypot_events` table to add 'rtsp' to the enum:

```bash
# Connect to ClickHouse
docker exec -it honeynet-clickhouse clickhouse-client

# Run ALTER command
ALTER TABLE honeynet.honeypot_events
MODIFY COLUMN honeypot_type Enum8('cowrie'=1, 'dionaea'=2, 'conpot'=3, 'rtsp'=4);

# Create rtsp_attacks table
CREATE TABLE IF NOT EXISTS honeynet.rtsp_attacks (
    timestamp DateTime,
    attack_id String,
    source_ip_hash String,
    source_ip_country String DEFAULT '',
    source_port UInt16,
    dest_ip String,
    dest_port UInt16,
    attack_type String,
    rtsp_method String DEFAULT '',
    rtsp_url String DEFAULT '',
    attack_details String DEFAULT '',
    INDEX idx_timestamp timestamp TYPE minmax GRANULARITY 3,
    INDEX idx_attack_type attack_type TYPE set(20) GRANULARITY 1,
    INDEX idx_source_hash source_ip_hash TYPE bloom_filter GRANULARITY 1
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, attack_type, source_ip_hash)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

# Exit
exit;
```

**Note**: For new deployments, this is handled automatically by `init-schema.sql`.

### 5. Start RTSP Honeypot

```bash
# Start only RTSP service
docker-compose up -d rtsp

# Or restart entire stack
docker-compose up -d
```

Verify container is running:

```bash
docker-compose ps rtsp
```

Expected output:
```
Name                Command               State           Ports
-------------------------------------------------------------------------
honeynet-rtsp   python3 -u /app/rtsp_hon ...   Up      0.0.0.0:554->554/tcp
```

### 6. Verify Logs

Check container logs:

```bash
docker-compose logs -f rtsp
```

Expected output:
```
[*] RTSP Honeypot started on 0.0.0.0:554
[*] Device: Generic IoT Device IP-Camera-001
[*] Firmware: v2.4.0-beta
[*] Logging to: /var/log/rtsp/rtsp.json
[*] Simulating CVE-2014-8361 vulnerability
[*] Waiting for connections...
```

Check JSON logs:

```bash
tail -f data/rtsp/rtsp.json
```

### 7. Restart Logstash

Logstash needs to be restarted to load the new RTSP pipeline:

```bash
docker-compose restart logstash
docker-compose logs -f logstash | grep rtsp
```

Expected output:
```
[INFO ] Starting pipeline {:pipeline_id=>"rtsp-pipeline", ...}
```

### 8. Test Deployment

Run basic connectivity test:

```bash
# Test OPTIONS request
echo -e "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n" | nc localhost 554
```

Expected response:
```
RTSP/1.0 200 OK
CSeq: 1
Server: RTSP/1.0 DVR-Camera-NVR
Public: OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN
```

Run comprehensive test suite:

```bash
python3 tests/rtsp/test_rtsp_honeypot.py localhost 554
```

Run CVE-2014-8361 test:

```bash
./tests/rtsp/test_cve_2014_8361.sh localhost 554
```

### 9. Verify Port Accessibility

Run full port test:

```bash
python3 tests/test_ports.py
```

Look for:
```
[*] Testing Honeypot TCP Ports...
  Testing RTSP Camera (tcp/554)... ✓ OPEN
```

### 10. Verify IDS Integration

Check Suricata is detecting RTSP attacks:

```bash
# Run CVE-2014-8361 test
./tests/rtsp/test_cve_2014_8361.sh

# Check Suricata alerts
docker-compose logs suricata | grep 2000015

# Or check eve.json
jq 'select(.alert.signature_id == 2000015)' data/suricata/eve.json
```

Expected alert:
```json
{
  "timestamp": "2025-10-24T12:34:56.789Z",
  "alert": {
    "signature_id": 2000015,
    "signature": "IoT RTSP exploit - CVE-2014-8361 buffer overflow attempt",
    "category": "attempted-admin",
    "severity": 1
  },
  "src_ip": "192.168.1.100",
  "dest_ip": "172.20.0.13",
  "dest_port": 554,
  "proto": "TCP"
}
```

### 11. Verify Data in ClickHouse

Query honeypot events:

```bash
docker exec -it honeynet-clickhouse clickhouse-client --query \
  "SELECT timestamp, event_type, source_ip_hash, dest_port
   FROM honeynet.honeypot_events
   WHERE honeypot_type = 'rtsp'
   ORDER BY timestamp DESC
   LIMIT 10
   FORMAT Pretty"
```

Query RTSP attacks:

```bash
docker exec -it honeynet-clickhouse clickhouse-client --query \
  "SELECT timestamp, attack_type, rtsp_method, source_ip_country
   FROM honeynet.rtsp_attacks
   ORDER BY timestamp DESC
   LIMIT 10
   FORMAT Pretty"
```

### 12. Configure Grafana Dashboard (Optional)

Create RTSP monitoring dashboard:

1. Access Grafana at http://localhost:3000
2. Create new dashboard
3. Add panels with queries:

**RTSP Events Over Time:**
```sql
SELECT
    toStartOfHour(timestamp) as time,
    count() as events
FROM honeynet.honeypot_events
WHERE honeypot_type = 'rtsp'
GROUP BY time
ORDER BY time
```

**CVE-2014-8361 Attacks:**
```sql
SELECT
    toDate(timestamp) as date,
    count() as attacks
FROM honeynet.rtsp_attacks
WHERE attack_type LIKE '%CVE-2014-8361%'
GROUP BY date
ORDER BY date DESC
```

**Top Attacking Countries:**
```sql
SELECT
    source_ip_country as country,
    count() as attacks
FROM honeynet.rtsp_attacks
WHERE source_ip_country != ''
GROUP BY country
ORDER BY attacks DESC
LIMIT 10
```

## Troubleshooting

### Port 554 Already in Use

```bash
# Check what's using the port
sudo netstat -tulpn | grep :554

# Or with lsof
sudo lsof -i :554

# Stop conflicting service
sudo systemctl stop rtsp-server  # example
```

### Container Not Starting

```bash
# Check container logs
docker-compose logs rtsp

# Check container status
docker inspect honeynet-rtsp

# Rebuild image
docker-compose build --no-cache rtsp
docker-compose up -d rtsp
```

### No Logs Being Generated

```bash
# Check log directory permissions
ls -la data/rtsp/

# Fix permissions if needed
sudo chown -R 1000:1000 data/rtsp/

# Verify honeypot is receiving connections
docker exec honeynet-rtsp ps aux
```

### Suricata Not Detecting Attacks

```bash
# Verify rule is loaded
docker exec honeynet-suricata suricata-update list-enabled-rules | grep 2000015

# Expected output:
# 2000015 - IoT RTSP exploit - CVE-2014-8361 buffer overflow attempt

# If not found, reload rules
docker exec honeynet-suricata suricatasc -c "reload-rules"

# Check Suricata is monitoring the right interface
docker exec honeynet-suricata cat /var/log/suricata/stats.log
```

### Logstash Not Processing RTSP Logs

```bash
# Check if pipeline is running
docker exec honeynet-logstash curl -s localhost:9600/_node/pipelines | jq '.pipelines["rtsp-pipeline"]'

# Check for errors
docker-compose logs logstash | grep -i "rtsp\|error"

# Restart Logstash
docker-compose restart logstash
```

### ClickHouse Enum Error

If you see errors like `Unknown element 'rtsp' for type Enum8`:

```bash
# The honeypot_type enum needs to be updated
docker exec -it honeynet-clickhouse clickhouse-client

ALTER TABLE honeynet.honeypot_events
MODIFY COLUMN honeypot_type Enum8('cowrie'=1, 'dionaea'=2, 'conpot'=3, 'rtsp'=4);
```

## Security Considerations

### Isolation

- RTSP honeypot runs on isolated DMZ network (172.20.0.0/24)
- No outbound internet access (NAT disabled)
- Minimal capabilities (only NET_BIND_SERVICE)
- Non-root user (UID 1000)

### Resource Limits

- Memory: 256MB hard limit
- CPU: 0.25 cores (25% of one core)
- Logging: Max 10MB per file, 3 files rotation

### Data Anonymization

- All source IPs are hashed with SHA256 + salt before storage
- GeoIP country code extracted before hashing
- No raw IP addresses stored in ClickHouse

## Performance Tuning

### High-Traffic Environments

If experiencing high traffic (>100 connections/sec):

**Increase Container Resources:**

```yaml
# docker-compose.yml
rtsp:
  mem_limit: 512m
  cpus: 0.5
```

**Adjust Logstash Workers:**

```yaml
# configs/logstash/pipelines.yml
- pipeline.id: rtsp-pipeline
  pipeline.workers: 2  # increase from 1
  pipeline.batch.size: 250  # increase from 125
```

**Adjust ClickHouse Settings:**

```sql
-- Increase batch size for inserts
SET max_insert_block_size = 100000;

-- Enable async inserts
SET async_insert = 1;
```

### Low-Resource Environments

For constrained environments:

```yaml
# docker-compose.yml
rtsp:
  mem_limit: 128m
  cpus: 0.1
```

```python
# honeypots/rtsp/rtsp_honeypot.py
MAX_CONNECTIONS = 50  # reduce from 100
BUFFER_SIZE = 4096    # reduce from 8192
```

## Monitoring

### Key Metrics to Monitor

1. **Container Health**
   ```bash
   docker inspect honeynet-rtsp | jq '.[0].State.Health'
   ```

2. **Connection Rate**
   ```bash
   grep "session_start" data/rtsp/rtsp.json | wc -l
   ```

3. **Attack Detection Rate**
   ```bash
   grep "attack_detected" data/rtsp/rtsp.json | wc -l
   ```

4. **Memory Usage**
   ```bash
   docker stats honeynet-rtsp --no-stream
   ```

5. **Suricata Alert Rate**
   ```bash
   jq 'select(.alert.signature_id == 2000015)' data/suricata/eve.json | wc -l
   ```

## Maintenance

### Log Rotation

Logs are automatically rotated by Docker:
- Max size: 10MB per file
- Max files: 3
- Total max storage: 30MB per container

### Manual Cleanup

```bash
# Archive old logs
tar -czf rtsp_logs_$(date +%Y%m%d).tar.gz data/rtsp/rtsp.json

# Truncate current log
> data/rtsp/rtsp.json

# Restart container to reinitialize
docker-compose restart rtsp
```

### Updates

To update the honeypot:

```bash
# Pull latest code
git pull origin main

# Rebuild image
docker-compose build rtsp

# Restart with new image
docker-compose up -d rtsp
```

## Integration with Existing Infrastructure

### Adding to Running System

If HoneyNetV2 is already deployed:

1. Add RTSP service to `docker-compose.yml`
2. Update ClickHouse schema (ALTER TABLE)
3. Add Logstash pipeline configuration
4. Build RTSP image
5. Start RTSP service only:
   ```bash
   docker-compose up -d rtsp
   ```
6. Restart Logstash to load new pipeline

### Firewall Configuration

If using iptables/ufw, allow port 554:

```bash
# UFW
sudo ufw allow 554/tcp comment "RTSP Honeypot"

# iptables
sudo iptables -A INPUT -p tcp --dport 554 -j ACCEPT
sudo iptables-save > /etc/iptables/rules.v4
```

For NAT/port forwarding to container:

```bash
# Forward external port 554 to container
sudo iptables -t nat -A PREROUTING -p tcp --dport 554 -j DNAT --to-destination 172.20.0.13:554
```

## Expected Behavior

### Normal Operation

- Container starts within 5 seconds
- Accepts connections on port 554
- Responds to OPTIONS with 200 OK
- Responds to DESCRIBE with SDP
- Challenges SETUP with 401 Unauthorized
- Logs all events to JSON
- Does NOT crash on buffer overflow attempts

### Attack Scenarios

**CVE-2014-8361 Buffer Overflow:**
- Attacker sends DESCRIBE with >1024 byte Authorization header
- Honeypot logs attack but remains stable
- Suricata triggers SID 2000015 alert
- Event stored in both `honeypot_events` and `rtsp_attacks` tables

**Brute Force:**
- Attacker sends >5 auth attempts in 60 seconds
- Honeypot logs brute force detection
- All attempts logged to `credentials` table

**Scanning:**
- Attacker connects to port 554
- Zeek logs connection attempt
- Honeypot logs session start/end
- Geographic origin tracked

## References

- **CVE-2014-8361**: https://nvd.nist.gov/vuln/detail/CVE-2014-8361
- **RFC 2326**: RTSP Protocol Specification
- **RFC 4566**: SDP Specification
- **MITRE ATT&CK T1190**: Exploit Public-Facing Application
- **Suricata Rule SID 2000015**: configs/suricata/rules/iot-botnet.rules:181-191

## Support

For issues or questions:
1. Check container logs: `docker-compose logs rtsp`
2. Review this deployment guide
3. Check HoneyNetV2 documentation
4. Open GitHub issue with logs and error details
