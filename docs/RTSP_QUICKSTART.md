# RTSP Honeypot - Quick Start Guide

## TL;DR

```bash
# 1. Create data directory
mkdir -p data/rtsp

# 2. Build and start
docker-compose up -d rtsp

# 3. Test
echo -e "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n" | nc localhost 554

# 4. Test CVE-2014-8361
./tests/rtsp/test_cve_2014_8361.sh

# 5. Check logs
tail -f data/rtsp/rtsp.json

# 6. Verify Suricata detection
docker-compose logs suricata | grep 2000015
```

## What is it?

RTSP honeypot simulating vulnerable IP cameras and DVR/NVR systems:
- **Port**: 554/TCP (Real Time Streaming Protocol)
- **Vulnerability**: CVE-2014-8361 (buffer overflow)
- **Detection**: Suricata rule SID 2000015
- **Purpose**: Attract and log attacks on IoT camera devices

## Quick Test

### Basic Connection Test

```bash
# Test OPTIONS
echo -e "OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n" | nc localhost 554

# Expected output:
# RTSP/1.0 200 OK
# CSeq: 1
# Server: RTSP/1.0 DVR-Camera-NVR
# Public: OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN
```

### Test DESCRIBE (Get Camera Info)

```bash
echo -e "DESCRIBE rtsp://localhost:554/stream RTSP/1.0\r\nCSeq: 2\r\n\r\n" | nc localhost 554

# Expected: SDP response with H.264 video stream description
```

### Test CVE-2014-8361 (Buffer Overflow)

```bash
# Run automated test
./tests/rtsp/test_cve_2014_8361.sh

# Or manual Python test
python3 tests/rtsp/test_rtsp_honeypot.py
```

## Verify Attack Detection

### Check Honeypot Logs

```bash
# View real-time logs
tail -f data/rtsp/rtsp.json

# Look for attack events
jq 'select(.event_type == "attack_detected")' data/rtsp/rtsp.json
```

### Check Suricata Alerts

```bash
# Search for CVE-2014-8361 alerts (SID 2000015)
docker-compose logs suricata | grep 2000015

# Or query eve.json
jq 'select(.alert.signature_id == 2000015)' data/suricata/eve.json
```

Example alert:
```json
{
  "alert": {
    "signature_id": 2000015,
    "signature": "IoT RTSP exploit - CVE-2014-8361 buffer overflow attempt",
    "category": "attempted-admin"
  },
  "dest_port": 554
}
```

### Check ClickHouse

```bash
# Query RTSP events
docker exec -it honeynet-clickhouse clickhouse-client --query \
  "SELECT * FROM honeynet.honeypot_events WHERE honeypot_type = 'rtsp' LIMIT 5 FORMAT Pretty"

# Query attacks
docker exec -it honeynet-clickhouse clickhouse-client --query \
  "SELECT * FROM honeynet.rtsp_attacks LIMIT 5 FORMAT Pretty"
```

## Common Issues

### Port 554 already in use

```bash
# Find what's using the port
sudo netstat -tulpn | grep :554

# Stop the service
sudo systemctl stop <service-name>
```

### Container not starting

```bash
# Check logs
docker-compose logs rtsp

# Rebuild
docker-compose build --no-cache rtsp
docker-compose up -d rtsp
```

### No logs appearing

```bash
# Check permissions
ls -la data/rtsp/

# Fix if needed
sudo chown -R 1000:1000 data/rtsp/

# Restart
docker-compose restart rtsp
```

## Attack Scenarios

### Scenario 1: CVE-2014-8361 Exploit

**Attack**: Attacker sends DESCRIBE with >1024 byte Authorization header

**What Happens**:
1. Honeypot receives request
2. Logs attack: `{"event_type": "attack_detected", "attack_type": "CVE-2014-8361 buffer overflow"}`
3. Suricata triggers alert SID 2000015
4. Connection remains open (no crash)
5. Data stored in ClickHouse

**Test**:
```bash
./tests/rtsp/test_cve_2014_8361.sh
```

### Scenario 2: Brute Force Attack

**Attack**: Multiple authentication attempts (>5 in 60 seconds)

**What Happens**:
1. Honeypot tracks attempts per session
2. After 5 attempts, logs: `{"event_type": "attack_detected", "attack_type": "brute_force"}`
3. All credentials logged to database

**Test**:
```bash
python3 tests/rtsp/test_rtsp_honeypot.py
# Look for "Brute Force Detection" test
```

### Scenario 3: Port Scanning

**Attack**: Attacker scans port 554

**What Happens**:
1. Connection logged by honeypot
2. Zeek detects connection to port 554
3. Zeek creates notice: `IoT_Exploit_Attempt`
4. Geographic origin tracked

## Integration Points

### Logs Flow

```
RTSP Honeypot
    │
    ├─> /var/log/rtsp/rtsp.json
    │        │
    │        └─> Logstash (rtsp-pipeline)
    │                 │
    │                 ├─> ClickHouse (honeypot_events)
    │                 └─> ClickHouse (rtsp_attacks)
    │
    └─> Network traffic
             │
             ├─> Suricata (SID 2000015)
             │        └─> ClickHouse (ids_alerts)
             │
             └─> Zeek (detect-iot-attacks.zeek)
                      └─> ClickHouse (network_connections)
```

### Data Tables

**honeypot_events**: All RTSP events (session_start, options, describe, etc.)
**rtsp_attacks**: RTSP-specific attacks (CVE-2014-8361, brute force)
**ids_alerts**: Suricata detections (SID 2000015)
**network_connections**: Zeek connection logs

## Resources

- **Full Deployment Guide**: docs/RTSP_DEPLOYMENT.md
- **Honeypot README**: honeypots/rtsp/README.md
- **Test Suite**: tests/rtsp/test_rtsp_honeypot.py
- **CVE Details**: https://nvd.nist.gov/vuln/detail/CVE-2014-8361
- **Suricata Rule**: configs/suricata/rules/iot-botnet.rules (lines 181-191)

## Next Steps

1. **Monitor in Grafana**: Create RTSP dashboard
2. **Analyze Attacks**: Query ClickHouse for patterns
3. **Tune Detection**: Adjust Suricata rules if needed
4. **Expand Coverage**: Add more RTSP vulnerabilities
5. **Export Data**: Use data/rtsp/rtsp.json for external analysis

## Questions?

- Check logs: `docker-compose logs rtsp`
- Run tests: `python3 tests/rtsp/test_rtsp_honeypot.py`
- Read full guide: `docs/RTSP_DEPLOYMENT.md`
- Review code: `honeypots/rtsp/rtsp_honeypot.py`
