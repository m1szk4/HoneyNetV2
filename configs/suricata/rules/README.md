# IoT Honeypot Suricata Detection Rules

## Overview

This custom ruleset is designed specifically for IoT honeypot environments to detect botnet activity, exploitation attempts, and malicious reconnaissance targeting IoT devices. The rules are optimized for high detection rates while maintaining low false positive rates.

## Performance Metrics

- **True Positive Rate (TPR)**: > 80%
- **False Positive Rate (FPR)**: < 5%
- **Total Rules**: 38 detection rules
- **MITRE ATT&CK Coverage**: 28 techniques (21 Enterprise + 7 ICS)

## Rule Categories

### 1. Mirai Botnet Detection (SID 2000001-2000004)

**Purpose**: Detect Mirai botnet scanning, authentication attempts, and C2 communication

**Techniques Covered**:
- T1595.001 - Active Scanning: Scanning IP Blocks
- T1110.001 - Brute Force: Password Guessing
- T1071.001 - Application Layer Protocol: Web Protocols

**Rules**:
- `2000001`: Telnet login banner probe detection
- `2000002`: Telnet brute force attempts (threshold: 5 attempts/60s)
- `2000003`: Alternative Telnet port scanning (port 2323)
- `2000004`: Mirai C2 beacon communication

### 2. SSH/Telnet Brute Force (SID 2000005-2000007)

**Purpose**: Identify credential guessing and default password attacks

**Techniques Covered**:
- T1110.001 - Brute Force: Password Guessing
- T1078.001 - Valid Accounts: Default Accounts

**Rules**:
- `2000005`: SSH brute force detection (threshold: 10 attempts/120s)
- `2000006`: Default credentials "admin/admin"
- `2000007`: Default credentials "support/support"

### 3. HTTP Exploits (SID 2000008-2000013)

**Purpose**: Detect web-based exploitation attempts

**Techniques Covered**:
- T1190 - Exploit Public-Facing Application
- T1083 - File and Directory Discovery
- T1059.004 - Command and Scripting Interpreter: Unix Shell

**Rules**:
- `2000008`: Shellshock via User-Agent (CVE-2014-6271)
- `2000009`: Shellshock via HTTP header
- `2000010`: Path traversal attempts
- `2000011`: CGI-bin exploitation
- `2000012`: SQL injection attempts
- `2000013`: Command injection via HTTP parameters

### 4. Camera/RTSP Attacks (SID 2000014-2000015)

**Purpose**: Detect attacks on IP cameras and RTSP services

**Techniques Covered**:
- T1110.001 - Brute Force: Password Guessing
- T1190 - Exploit Public-Facing Application

**Rules**:
- `2000014`: RTSP authentication brute force (threshold: 5 attempts/60s)
- `2000015`: RTSP buffer overflow (CVE-2014-8361)

### 5. UPnP Abuse (SID 2000016-2000017)

**Purpose**: Identify UPnP service abuse for port forwarding and reconnaissance

**Techniques Covered**:
- T1046 - Network Service Discovery
- T1557 - Adversary-in-the-Middle

**Rules**:
- `2000016`: UPnP SSDP M-SEARCH scanning (threshold: 20 requests/60s)
- `2000017`: UPnP AddPortMapping abuse

### 6. ICS/SCADA Protocols (SID 2000018-2000021)

**Purpose**: Detect unauthorized access and manipulation of industrial control systems

**Techniques Covered** (ICS Matrix):
- T0802 - Automated Collection
- T0836 - Modify Parameter
- T0846 - Remote System Discovery
- T0855 - Unauthorized Command Message

**Rules**:
- `2000018`: Modbus unauthorized write command
- `2000019`: Modbus read holding registers reconnaissance (threshold: 10 requests/300s)
- `2000020`: BACnet device discovery (threshold: 5 requests/60s)
- `2000021`: Modbus manipulation of control (emergency stop)

### 7. SMB Exploits (SID 2000022-2000023)

**Purpose**: Detect SMB-based attacks including EternalBlue

**Techniques Covered**:
- T1210 - Exploitation of Remote Services
- T1110 - Brute Force

**Rules**:
- `2000022`: EternalBlue exploit attempt (CVE-2017-0144)
- `2000023`: SMB brute force (threshold: 10 attempts/120s)

### 8. Mass Scanners (SID 2000024-2000025)

**Purpose**: Identify automated scanning tools

**Techniques Covered**:
- T1046 - Network Service Discovery
- T1595.001 - Active Scanning: Scanning IP Blocks

**Rules**:
- `2000024`: Multi-port scanning (threshold: 8 ports/10s)
- `2000025`: Aggressive scanning (Masscan/Zmap, threshold: 50 connections/60s)

### 9. Post-Exploitation & C2 (SID 2000026-2000029)

**Purpose**: Detect command execution and malware downloads post-compromise

**Techniques Covered**:
- T1059.004 - Command and Scripting Interpreter: Unix Shell
- T1105 - Ingress Tool Transfer
- T1071 - Application Layer Protocol

**Rules**:
- `2000026`: Reverse shell connection attempts
- `2000027`: Suspicious binary downloads (.sh files)
- `2000028`: C2 beacon to suspicious ports (threshold: 3 connections/300s)
- `2000029`: Botnet downloader (MIPS binaries)

### 10. DDoS Preparation (SID 2000030-2000031)

**Purpose**: Identify DDoS tool downloads and attack patterns

**Techniques Covered**:
- T1584.005 - Compromise Infrastructure: Botnet
- T1498 - Network Denial of Service

**Rules**:
- `2000030`: XOR DDoS tool download
- `2000031`: HOIC/LOIC traffic pattern (threshold: 100 requests/60s)

### 11. Credential Access (SID 2000032)

**Purpose**: Detect credential harvesting attempts

**Techniques Covered**:
- T1056 - Input Capture

**Rules**:
- `2000032`: FTP/Telnet/HTTP login capture

### 12. Persistence (SID 2000033)

**Purpose**: Identify persistence mechanisms

**Techniques Covered**:
- T1053.003 - Scheduled Task/Job: Cron

**Rules**:
- `2000033`: Cron job creation attempts

### 13. Discovery (SID 2000034)

**Purpose**: Detect system reconnaissance commands

**Techniques Covered**:
- T1082 - System Information Discovery

**Rules**:
- `2000034`: System discovery commands (uname -a)

### 14. Lateral Movement (SID 2000035)

**Purpose**: Identify attempts to move laterally within networks

**Techniques Covered**:
- T1021.004 - Remote Services: SSH

**Rules**:
- `2000035`: SSH tunneling detection

### 15. Collection (SID 2000036)

**Purpose**: Detect data staging for exfiltration

**Techniques Covered**:
- T1074 - Data Staged

**Rules**:
- `2000036`: Archive creation (tar commands)

### 16. Impact - ICS Specific (SID 2000037-2000038)

**Purpose**: Detect attacks designed to disrupt ICS operations

**Techniques Covered** (ICS Matrix):
- T0815 - Denial of Service
- T0831 - Manipulation of View

**Rules**:
- `2000037`: Modbus flooding DoS (threshold: 100 requests/10s)
- `2000038`: Modbus register tampering

## MITRE ATT&CK Coverage Summary

### Enterprise Matrix (21 techniques)

**Reconnaissance (TA0043)**:
- T1595.001 - Active Scanning: Scanning IP Blocks

**Initial Access (TA0001)**:
- T1078.001 - Valid Accounts: Default Accounts
- T1190 - Exploit Public-Facing Application

**Execution (TA0002)**:
- T1059.004 - Command and Scripting Interpreter: Unix Shell

**Persistence (TA0003)**:
- T1053.003 - Scheduled Task/Job: Cron

**Credential Access (TA0006)**:
- T1056 - Input Capture
- T1110 - Brute Force
- T1110.001 - Brute Force: Password Guessing
- T1557 - Adversary-in-the-Middle

**Discovery (TA0007)**:
- T1046 - Network Service Discovery
- T1082 - System Information Discovery
- T1083 - File and Directory Discovery

**Lateral Movement (TA0008)**:
- T1021.004 - Remote Services: SSH
- T1210 - Exploitation of Remote Services

**Collection (TA0009)**:
- T1074 - Data Staged

**Command and Control (TA0011)**:
- T1071 - Application Layer Protocol
- T1071.001 - Application Layer Protocol: Web Protocols
- T1105 - Ingress Tool Transfer

**Impact (TA0040)**:
- T1498 - Network Denial of Service

**Resource Development (TA0042)**:
- T1584.005 - Compromise Infrastructure: Botnet

### ICS Matrix (7 techniques)

**Collection (TA0102)**:
- T0802 - Automated Collection
- T0846 - Remote System Discovery

**Impair Process Control (TA0103)**:
- T0836 - Modify Parameter

**Inhibit Response Function (TA0104)**:
- T0831 - Manipulation of View

**Impact (TA0105)**:
- T0815 - Denial of Service

**Lateral Movement (TA0109)**:
- T0855 - Unauthorized Command Message

## Optimization and Performance

### Threshold Configuration

Rules use thresholds to reduce false positives by requiring multiple suspicious events before alerting:

- **Brute force detection**: 5-10 attempts within 60-120 seconds
- **Port scanning**: 8+ ports within 10 seconds
- **Mass scanning**: 50+ connections within 60 seconds
- **C2 beacons**: 3+ connections within 300 seconds
- **DDoS patterns**: 100+ requests within 60 seconds

### Suppression

Uncomment suppression rules at the end of the file to reduce noise from:
- Known vulnerability scanners during penetration testing
- Internal security tools
- Trusted IP ranges

Example:
```
suppress gen_id 1, sig_id 2000024, track by_src, ip 192.168.1.0/24
```

### Traffic Flow

Rules utilize flow keywords to:
- Focus on established connections where appropriate
- Distinguish server-bound vs client-bound traffic
- Reduce processing overhead on irrelevant packets

## Integration with Logstash

Rules include metadata fields that are extracted by the Logstash pipeline:
- `mitre_technique_id`: Used for attack classification
- `mitre_tactic_id`: Used for tactical analysis
- `classtype`: Maps to severity levels

These fields are parsed and stored in ClickHouse for analytics.

## Maintenance and Updates

### Regular Updates

1. **Weekly**: Review alert logs and adjust thresholds based on FPR
2. **Monthly**: Update signatures based on new IoT vulnerabilities
3. **Quarterly**: Validate MITRE ATT&CK mapping accuracy

### Adding New Rules

When adding new rules:
1. Use SID range 2000039+ for custom rules
2. Include appropriate MITRE metadata
3. Set realistic thresholds based on expected traffic
4. Document in this README
5. Test with sample PCAP files before production deployment

### Testing

Test rules using:
```bash
suricata -T -c /etc/suricata/suricata.yaml
suricata -r test.pcap -c /etc/suricata/suricata.yaml -l /var/log/suricata/
```

## References

- [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [MITRE ATT&CK ICS Matrix](https://attack.mitre.org/matrices/ics/)
- [Suricata Documentation](https://suricata.readthedocs.io/)
- [IoT Botnet Analysis Reports](https://www.akamai.com/blog/security/mirai-botnet-iot-security)

## License

This ruleset is part of the HoneyNetV2 project and is provided for research and educational purposes.
