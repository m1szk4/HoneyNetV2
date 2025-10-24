# Lateral Movement Detection Guide

## Overview

This document describes the lateral movement detection capabilities in HoneyNetV2 and provides guidance for testing and monitoring.

## Architecture

The HoneyNetV2 system is designed to detect lateral movement attempts where an attacker, after compromising one honeypot, attempts to attack other services within the DMZ network.

### Network Setup

- **DMZ Network**: 172.20.0.0/24
  - Cowrie (SSH/Telnet): 172.20.0.10
  - Dionaea (Multi-protocol): 172.20.0.11
  - Conpot (ICS/SCADA): 172.20.0.12
- **Inter-Container Communication**: Enabled (`enable_icc: true`)
- **Monitoring**: Suricata and Zeek monitor the eth0 interface in host mode, capturing traffic on the DMZ subnet

## Detection Mechanisms

### 1. Suricata IDS Rules

The system includes a specific rule for detecting lateral movement (SSH tunneling):

**Rule ID**: SID 2000035
**File**: `configs/suricata/rules/custom.rules`

```
alert tcp $HOME_NET any -> $HOME_NET 22 (msg:"LATERAL_MOVEMENT SSH Tunneling Detected"; \
    flow:established,to_server; content:"SSH"; depth:4; \
    threshold:type limit, track by_src, count 1, seconds 60; \
    classtype:policy-violation; sid:2000035; rev:1; \
    metadata:mitre_technique_id T1572, mitre_tactic_id lateral-movement;)
```

This rule triggers when:
- Traffic flows from one DMZ host to another
- Destination port is 22 (SSH)
- SSH protocol is detected
- Limited to 1 alert per source IP per 60 seconds

### 2. Network Connection Monitoring

Zeek logs all network connections, including those between honeypots:
- Source IP: Internal DMZ address
- Destination IP: Another DMZ address
- Connection details: protocol, duration, bytes transferred

### 3. Honeypot Event Logging

All honeypots log connection attempts, including those from internal sources:
- Cowrie: Logs SSH/Telnet connections from any source
- Dionaea: Logs SMB, FTP, HTTP connections
- Conpot: Logs ICS protocol requests

## Testing Lateral Movement Detection

### Test Scenario 1: SSH from Cowrie to Dionaea

**Objective**: Verify detection of SSH scan from one honeypot to another

**Steps**:

1. Access the Cowrie container:
   ```bash
   docker exec -it honeynet-cowrie /bin/bash
   ```

2. Install SSH client (if not available):
   ```bash
   apt-get update && apt-get install -y openssh-client
   ```

3. Attempt SSH connection to Dionaea:
   ```bash
   ssh root@172.20.0.11
   ```

4. Check for detection:
   ```bash
   # Check Suricata alerts
   docker exec honeynet-clickhouse clickhouse-client --query="\
     SELECT timestamp, alert_signature, source_ip_hash, dest_ip, dest_port \
     FROM honeynet.ids_alerts \
     WHERE signature_id = 2000035 \
     ORDER BY timestamp DESC LIMIT 10"

   # Check honeypot events
   docker exec honeynet-clickhouse clickhouse-client --query="\
     SELECT timestamp, honeypot_type, source_ip_hash, dest_ip, dest_port, event_type \
     FROM honeynet.honeypot_events \
     WHERE dest_ip LIKE '172.20.0.%' \
     ORDER BY timestamp DESC LIMIT 10"
   ```

### Test Scenario 2: Port Scan Between Honeypots

**Objective**: Verify detection of port scanning activity

**Steps**:

1. Access Cowrie container and install nmap:
   ```bash
   docker exec -it honeynet-cowrie /bin/bash
   apt-get update && apt-get install -y nmap
   ```

2. Perform port scan of Dionaea:
   ```bash
   nmap -p 21,80,445,1433 172.20.0.11
   ```

3. Check network connections:
   ```bash
   docker exec honeynet-clickhouse clickhouse-client --query="\
     SELECT timestamp, dest_ip, dest_port, protocol, conn_state \
     FROM honeynet.network_connections \
     WHERE dest_ip = '172.20.0.11' \
     AND timestamp >= now() - INTERVAL 10 MINUTE \
     ORDER BY timestamp DESC"
   ```

### Test Scenario 3: HTTP Requests Between Containers

**Objective**: Test HTTP-based lateral movement

**Steps**:

1. From Cowrie, attempt HTTP connection to Dionaea:
   ```bash
   docker exec honeynet-cowrie curl http://172.20.0.11
   ```

2. Check HTTP logs:
   ```bash
   docker exec honeynet-clickhouse clickhouse-client --query="\
     SELECT timestamp, dest_ip, method, uri, user_agent \
     FROM honeynet.http_requests \
     WHERE dest_ip = '172.20.0.11' \
     ORDER BY timestamp DESC LIMIT 10"
   ```

## Monitoring and Alerting

### Real-time Monitoring Queries

**Dashboard Query - Lateral Movement Events (Last 24h)**:
```sql
SELECT
    timestamp,
    honeypot_type,
    source_ip_hash,
    dest_ip,
    dest_port,
    protocol,
    event_type
FROM honeynet.honeypot_events
WHERE dest_ip LIKE '172.20.0.%'
  AND timestamp >= now() - INTERVAL 24 HOUR
ORDER BY timestamp DESC;
```

**IDS Alerts for Lateral Movement**:
```sql
SELECT
    timestamp,
    alert_signature,
    source_ip_hash,
    dest_ip,
    dest_port,
    mitre_technique_id,
    mitre_tactic
FROM honeynet.ids_alerts
WHERE alert_signature LIKE '%LATERAL%'
  OR signature_id = 2000035
  OR mitre_tactic = 'lateral-movement'
ORDER BY timestamp DESC;
```

### Grafana Dashboard Panels

Add these panels to your Grafana dashboard:

1. **Lateral Movement Alert Count**:
   - Query: Count of events where `dest_ip LIKE '172.20.0.%'`
   - Visualization: Stat panel with trend

2. **Lateral Movement Timeline**:
   - Query: Events over time grouped by honeypot
   - Visualization: Time series graph

3. **Internal Traffic Matrix**:
   - Query: Source IP hash to destination IP mapping
   - Visualization: Heatmap or table

## Expected Behavior

### Normal Operation
- **No lateral traffic**: In normal operation, external attackers should only target exposed ports
- **No internal IPs**: Source IPs should not be from 172.20.0.0/24 range

### During Attack
- **IDS Alert**: Suricata should generate alert SID 2000035
- **Event Logging**: Targeted honeypot logs the connection attempt
- **Network Log**: Zeek records the connection details
- **Database Entry**: All events are stored in ClickHouse with appropriate tagging

## Troubleshooting

### Suricata Not Detecting Internal Traffic

**Issue**: Lateral movement not generating IDS alerts

**Checks**:
1. Verify Suricata is monitoring the correct interface:
   ```bash
   docker logs honeynet-suricata | grep "interface"
   ```

2. Confirm host mode networking:
   ```bash
   docker inspect honeynet-suricata | grep NetworkMode
   # Should show: "NetworkMode": "host"
   ```

3. Check if custom rules are loaded:
   ```bash
   docker exec honeynet-suricata suricata --dump-config | grep "rule-files"
   ```

### Honeypots Not Logging Internal Connections

**Issue**: Internal connections not appearing in honeypot logs

**Checks**:
1. Verify inter-container communication is enabled:
   ```bash
   docker network inspect honeynet_honeypot_net | grep enable_icc
   # Should show: "com.docker.network.bridge.enable_icc": "true"
   ```

2. Test connectivity between containers:
   ```bash
   docker exec honeynet-cowrie ping -c 3 172.20.0.11
   ```

3. Check firewall rules within containers:
   ```bash
   docker exec honeynet-dionaea iptables -L
   ```

### Zeek Not Capturing DMZ Traffic

**Issue**: Network connections table missing internal traffic

**Checks**:
1. Verify Zeek is running in host mode:
   ```bash
   docker inspect honeynet-zeek | grep NetworkMode
   ```

2. Check Zeek logs for errors:
   ```bash
   docker logs honeynet-zeek --tail 50
   ```

3. Verify network interface:
   ```bash
   docker exec honeynet-zeek zeek --version
   docker exec honeynet-zeek ifconfig
   ```

## Security Considerations

### False Positives

- **Container Health Checks**: May trigger internal network events
- **Legitimate Management**: Administrative tools accessing multiple services
- **Mitigation**: Use suppression rules for known management IPs

### Evasion Techniques

Attackers may attempt to evade detection:
- **Non-standard ports**: Use different ports for lateral movement
- **Encrypted tunnels**: Bypass signature-based detection
- **Low and slow**: Spread attacks over long periods

**Countermeasures**:
- Monitor all port connections in network_connections table
- Analyze connection patterns and anomalies
- Track attacker behavior across multiple days

## Integration with MITRE ATT&CK

Lateral movement detection aligns with MITRE ATT&CK framework:

- **Technique**: T1572 - Protocol Tunneling
- **Tactic**: Lateral Movement
- **Sub-techniques**:
  - T1021.004 - Remote Services: SSH
  - T1021.002 - Remote Services: SMB/Windows Admin Shares

All detected lateral movement events are tagged with appropriate MITRE technique IDs for analysis and reporting.

## Recommendations

1. **Regular Testing**: Run lateral movement tests monthly to ensure detection mechanisms are functioning
2. **Rule Tuning**: Adjust Suricata rules based on observed attack patterns
3. **Baseline Establishment**: Monitor normal traffic patterns to identify anomalies
4. **Alert Prioritization**: Lateral movement should be high-priority alerts
5. **Incident Response**: Document procedures for responding to confirmed lateral movement

## References

- Suricata Documentation: https://suricata.io/
- Zeek Network Security Monitor: https://zeek.org/
- MITRE ATT&CK - Lateral Movement: https://attack.mitre.org/tactics/TA0008/
