# HoneyNetV2 Architecture Documentation

## Overview

HoneyNetV2 is a comprehensive honeypot infrastructure designed for IoT/ICS threat intelligence gathering and cybersecurity research. The system employs a multi-layered architecture with isolated DMZ networks, multiple honeypot services, intrusion detection systems, and advanced analytics capabilities.

**Last Updated**: 2025-10-24
**Version**: 2.0

---

## Table of Contents

1. [Network Architecture](#network-architecture)
2. [Component Overview](#component-overview)
3. [Data Flow](#data-flow)
4. [Security Architecture](#security-architecture)
5. [Deployment Architecture](#deployment-architecture)

---

## Network Architecture

### High-Level Network Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                          INTERNET / ATTACKERS                        │
│                     (Malicious Actors, Botnets, Scanners)           │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                             │ Inbound Traffic Only
                             │ (No Egress Allowed from DMZ)
                             │
                    ┌────────▼────────┐
                    │   Host Firewall  │
                    │   (iptables)     │
                    │                  │
                    │ - NAT forwarding │
                    │ - Port mapping   │
                    │ - Egress block   │
                    └────────┬─────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
┌───────▼─────────────────────────────────────────▼──────┐
│          HONEYPOT DMZ NETWORK                          │
│          Network: 172.20.0.0/24                        │
│          Subnet: honeynet_honeypot_net                 │
│          ICC: Enabled (for lateral movement testing)   │
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │   Cowrie     │  │   Dionaea    │  │   Conpot     │ │
│  │ 172.20.0.10  │  │ 172.20.0.11  │  │ 172.20.0.12  │ │
│  │              │  │              │  │              │ │
│  │ SSH/Telnet   │  │ Multi-Proto  │  │  ICS/SCADA   │ │
│  │ Honeypot     │  │ Honeypot     │  │  Honeypot    │ │
│  │              │  │              │  │              │ │
│  │ Ports:       │  │ Ports:       │  │ Ports:       │ │
│  │ - 22 (SSH)   │  │ - 21 (FTP)   │  │ - 102 (S7)   │ │
│  │ - 23 (Telnet)│  │ - 80 (HTTP)  │  │ - 161 (SNMP) │ │
│  │ - 2323       │  │ - 443 (HTTPS)│  │ - 502 (Modbus)│
│  └──────────────┘  │ - 445 (SMB)  │  │ - 47808 (BACnet)│
│                    │ - 1433 (MSSQL)│ │ - 623 (IPMI) │ │
│                    │ - 3306 (MySQL)│ └──────────────┘ │
│                    │ - 8080 (HTTP)│                   │
│                    └──────────────┘                   │
│                                                         │
│  Network Characteristics:                              │
│  - No outbound internet access                         │
│  - Container-to-container communication enabled        │
│  - All traffic monitored by IDS                        │
└─────────────────────────────────────────────────────────┘
                             │
                             │ Traffic Mirroring
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
┌───────▼─────────┐    ┌────▼─────────┐          │
│   Suricata      │    │     Zeek     │          │
│   IDS/IPS       │    │  Network     │          │
│                 │    │  Analyzer    │          │
│ Network: host   │    │ Network: host│          │
│                 │    │              │          │
│ - Packet capture│    │ - Protocol   │          │
│ - Signature IDS │    │   analysis   │          │
│ - Alert gen.    │    │ - Metadata   │          │
│ - MITRE mapping │    │   extraction │          │
└─────────────────┘    └──────────────┘          │
        │                      │                  │
        │ eve.json logs        │ conn.log, http.log, etc.
        │                      │                  │
        └──────────┬───────────┘                  │
                   │                              │
┌──────────────────▼──────────────────────────────▼──────┐
│              MANAGEMENT NETWORK                         │
│              Network: 172.21.0.0/24                     │
│              Subnet: honeynet_management_net            │
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │  Logstash    │  │ ClickHouse   │  │   Grafana    │ │
│  │  ETL         │  │ Analytics DB │  │  Dashboards  │ │
│  │              │  │              │  │              │ │
│  │ - Log parsing│  │ - OLAP       │  │ - Viz        │ │
│  │ - IP anon.   │  │ - Fast query │  │ - Alerting   │ │
│  │ - GeoIP      │  │ - Retention  │  │ - Export     │ │
│  │ - Enrich     │  │ - Aggregation│  │              │ │
│  └───────┬──────┘  └──────┬───────┘  └──────────────┘ │
│          │                 │                           │
│          └─────► INSERT ───┘                           │
│                   Data                                 │
│                                                         │
│  ┌──────────────────────────────────────────────────┐  │
│  │              Jupyter Notebook                     │  │
│  │          Advanced Analysis & ML                   │  │
│  │                                                   │  │
│  │ - Data science notebooks                         │  │
│  │ - Attack pattern analysis                        │  │
│  │ - MITRE ATT&CK visualization                     │  │
│  │ - Threat intelligence reports                    │  │
│  └──────────────────────────────────────────────────┘  │
│                                                         │
│  Network Characteristics:                              │
│  - Full internet access (for updates, lookups)         │
│  - Internal service communication only                 │
│  - Isolated from honeypot DMZ                          │
└─────────────────────────────────────────────────────────┘
                             │
                             │
                    ┌────────▼────────┐
                    │  Admin Access   │
                    │                 │
                    │ - Grafana Web   │
                    │ - Jupyter Web   │
                    │ - SSH (host)    │
                    └─────────────────┘
```

### Network Isolation Model

```
┌─────────────────────────────────────────────────────────┐
│                    NETWORK ZONES                        │
└─────────────────────────────────────────────────────────┘

   UNTRUSTED ZONE              DMZ ZONE           MANAGEMENT ZONE
   (Internet)            (Honeypot Network)     (Analytics & Admin)

   ┌──────────┐          ┌──────────────┐       ┌──────────────┐
   │          │          │              │       │              │
   │ Attackers│─────────►│  Honeypots   │       │  ClickHouse  │
   │          │ Inbound  │              │       │              │
   │          │   Only   │   ┌──────┐   │       │   ┌──────┐   │
   └──────────┘          │   │ IDS  │   │       │   │Grafana│  │
                         │   │Mirror│   │       │   └──────┘   │
        ✗                │   └───┬──┘   │       │              │
    No Egress            │       │      │       │   ┌──────┐   │
                         │       └──────┼───────┼──►│Logstash│  │
                         │              │       │   └──────┘   │
                         │              │       │              │
                         └──────────────┘       └──────────────┘

    Traffic Flow Rules:
    ─────────► : Allowed
    ✗          : Blocked
```

---

## Component Overview

### 1. Honeypot Layer

#### Cowrie (SSH/Telnet Honeypot)

**Purpose**: Capture SSH and Telnet brute-force attacks, malware, and commands

**Capabilities**:
- Emulated shell environment
- Fake filesystem
- Command logging
- File upload/download capture
- Credential capture

**Ports Exposed**:
- 22/tcp → SSH
- 23/tcp → Telnet
- 2323/tcp → Alternate Telnet

**Logs Generated**:
- `cowrie.json` - All events (login, commands, files)
- Location: `/data/cowrie/cowrie.json*`

**ClickHouse Tables**:
- `honeypot_events` (event_type: 'cowrie_*')
- `credentials` (username, password, success)
- `downloaded_files` (if malware downloaded via wget/curl)

---

#### Dionaea (Multi-Protocol Honeypot)

**Purpose**: Capture attacks on various network protocols

**Protocols Supported**:
- FTP (21)
- HTTP/HTTPS (80, 443, 8080)
- SMB (445)
- MSSQL (1433)
- MySQL (3306)

**Capabilities**:
- Exploit detection (Shellshock, SQLi, etc.)
- Malware binary capture
- Protocol emulation
- Payload analysis

**Logs Generated**:
- `dionaea.json` - Event logs
- Binary files in `/data/dionaea/binaries/`

**ClickHouse Tables**:
- `honeypot_events` (event_type: 'dionaea_*')
- `downloaded_files` (captured binaries)

---

#### Conpot (ICS/SCADA Honeypot)

**Purpose**: Emulate industrial control systems to attract ICS-targeted attacks

**Protocols Supported**:
- Modbus (502/tcp)
- SNMP (161/udp)
- S7comm (102/tcp) - Siemens
- BACnet (47808/udp)
- IPMI (623/udp)

**Emulated Devices**:
- Siemens S7-300 PLC
- Generic Modbus RTU
- SNMP-enabled industrial device

**Logs Generated**:
- `conpot.json` - ICS protocol interactions

**ClickHouse Tables**:
- `honeypot_events` (protocol: 'modbus', 'snmp', etc.)

---

### 2. Detection Layer

#### Suricata (IDS/IPS)

**Purpose**: Network-based intrusion detection using signatures

**Detection Methods**:
- Signature-based detection
- Protocol anomaly detection
- File extraction
- TLS inspection

**Rule Categories**:
- Honeypot-specific rules (custom)
- IoT botnet signatures (Mirai, Gafgyt)
- ICS/SCADA attack patterns
- Exploit kits (Shellshock, Log4j)
- MITRE ATT&CK technique mapping

**Logs Generated**:
- `eve.json` - All alerts and events
- `fast.log` - Quick alert summary
- `stats.json` - Performance metrics

**ClickHouse Tables**:
- `ids_alerts` - All Suricata alerts with MITRE mapping

---

#### Zeek (Network Security Monitor)

**Purpose**: Deep packet inspection and protocol analysis

**Analysis Types**:
- Connection logs (all TCP/UDP flows)
- HTTP transaction logs
- DNS queries
- SSL/TLS certificate capture
- File extraction

**Logs Generated** (in `/data/zeek/`):
- `conn.log` - Network connections
- `http.log` - HTTP requests/responses
- `dns.log` - DNS queries
- `ssl.log` - TLS handshakes
- `files.log` - Transferred files

**ClickHouse Tables**:
- `network_connections` (from conn.log)
- `http_requests` (from http.log)

---

### 3. Data Processing Layer

#### Logstash (ETL Pipeline)

**Purpose**: Collect, parse, enrich, and forward logs to ClickHouse

**Processing Steps**:
1. **Input**: Read JSON logs from honeypots and IDS
2. **Filter**:
   - Parse JSON structures
   - **GeoIP Enrichment** (before anonymization)
   - **IP Anonymization** (SHA256 hash with salt)
   - Field normalization
   - Exploit pattern detection (Shellshock, SQLi, traversal)
3. **Output**: Bulk insert to ClickHouse

**Pipelines**:
- `cowrie.conf` - SSH/Telnet events
- `dionaea.conf` - Multi-protocol events
- `conpot.conf` - ICS events
- `suricata.conf` - IDS alerts (includes MITRE parsing)
- `zeek.conf` - Network analysis logs

**Key Features**:
- **IP Anonymization**: All source IPs hashed before storage (GDPR-compliant)
- **GeoIP Lookup**: Country code extracted before hashing
- **MITRE Extraction**: Parse ATT&CK technique IDs from Suricata metadata

---

### 4. Storage Layer

#### ClickHouse (OLAP Database)

**Purpose**: High-performance analytics database for honeypot data

**Schema Design**:
- Optimized for time-series queries
- Fast aggregations with materialized views
- TTL-based data retention (90 days)
- Compression for efficient storage

**Tables**:
- `honeypot_events` - All honeypot interactions
- `ids_alerts` - Suricata alerts
- `network_connections` - Zeek connection logs
- `http_requests` - HTTP transaction details
- `credentials` - Captured username/password pairs
- `downloaded_files` - Malware binaries metadata
- `attacker_profiles` - Aggregated attacker behavior

**Materialized Views**:
- `attacker_profile_aggregator` - Real-time profiling
- `mitre_attack_stats` - MITRE technique aggregation
- `daily_attack_summary` - Daily statistics

**Performance**:
- Sub-second queries on millions of events
- Efficient aggregation for dashboards
- Parquet export for external analysis

---

### 5. Visualization Layer

#### Grafana (Dashboards)

**Purpose**: Real-time monitoring and visualization

**Dashboards**:
- Attack Overview (events/hour, top countries)
- Honeypot Status (service health, event counts)
- MITRE ATT&CK Heatmap
- Geographic Attack Map (by country)
- Credential Analysis (common passwords, usernames)
- ICS/SCADA Threats

**Alerting**:
- Email notifications for critical alerts
- Threshold-based warnings
- Daily summary reports

---

#### Jupyter (Advanced Analysis)

**Purpose**: Data science and ad-hoc analysis

**Use Cases**:
- Attack pattern analysis
- Machine learning on attacker behavior
- Threat intelligence report generation
- Correlation analysis
- Custom visualizations

**Libraries**:
- pandas, numpy (data manipulation)
- matplotlib, seaborn (visualization)
- clickhouse-driver (database access)
- sklearn (machine learning)

---

## Data Flow

### Attack Event Processing Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│                    DATA FLOW DIAGRAM                            │
└─────────────────────────────────────────────────────────────────┘

Step 1: Attack Arrives
─────────────────────
   Internet
      │
      │ TCP/UDP Packet
      │
      ▼
   ┌──────────────┐
   │  Honeypot    │ ◄─── Attacker connects to exposed port
   │  (Cowrie)    │
   └──────┬───────┘
          │
          │ Logs interaction
          │
          ▼
   ┌──────────────┐
   │ cowrie.json  │ ◄─── JSON log file created
   └──────────────┘


Step 2: IDS Captures Packet
────────────────────────────
   Network Traffic
      │
      │ (Mirrored via host network mode)
      │
      ▼
   ┌──────────────┐
   │   Suricata   │ ◄─── Signature matching
   │     IDS      │
   └──────┬───────┘
          │
          │ Alert generated
          │
          ▼
   ┌──────────────┐
   │   eve.json   │ ◄─── Alert with MITRE ATT&CK metadata
   └──────────────┘


Step 3: Logstash Processes Logs
─────────────────────────────────
   ┌──────────────┐
   │ cowrie.json  │
   │  eve.json    │
   └──────┬───────┘
          │
          │ Logstash reads logs (file input plugin)
          │
          ▼
   ┌──────────────────────────────────────┐
   │         LOGSTASH PIPELINE            │
   │                                      │
   │  1. Parse JSON                       │
   │  2. Extract source IP                │
   │  3. ┌─────────────────────┐         │
   │     │ GeoIP Lookup        │         │
   │     │ (country code)      │         │
   │     └─────────────────────┘         │
   │  4. ┌─────────────────────┐         │
   │     │ IP Anonymization    │         │
   │     │ SHA256(IP + salt)   │         │
   │     └─────────────────────┘         │
   │  5. Extract MITRE metadata          │
   │  6. Normalize fields                │
   │  7. Detect exploit patterns         │
   │     (Shellshock, SQLi, etc.)        │
   └──────────────┬───────────────────────┘
                  │
                  │ Enriched & anonymized data
                  │
                  ▼
   ┌──────────────────────────────────────┐
   │      OUTPUT TO CLICKHOUSE            │
   │                                      │
   │  INSERT INTO honeypot_events (...);  │
   │  INSERT INTO ids_alerts (...);       │
   └──────────────────────────────────────┘


Step 4: ClickHouse Storage
───────────────────────────
   ┌──────────────────────────────────────┐
   │          CLICKHOUSE                  │
   │                                      │
   │  ┌────────────────────────────────┐  │
   │  │   honeypot_events              │  │
   │  │   - timestamp                  │  │
   │  │   - source_ip_hash             │  │
   │  │   - source_ip_country ◄────────┼──┼─ From GeoIP
   │  │   - dest_port                  │  │
   │  │   - event_type                 │  │
   │  │   - ...                        │  │
   │  └────────────────────────────────┘  │
   │                                      │
   │  ┌────────────────────────────────┐  │
   │  │   ids_alerts                   │  │
   │  │   - timestamp                  │  │
   │  │   - signature_id               │  │
   │  │   - mitre_technique_id ◄───────┼──┼─ From Suricata metadata
   │  │   - mitre_tactic               │  │
   │  │   - source_ip_country          │  │
   │  │   - ...                        │  │
   │  └────────────────────────────────┘  │
   │                                      │
   │  ┌────────────────────────────────┐  │
   │  │  Materialized Views            │  │
   │  │  - Auto-aggregate on insert    │  │
   │  │  - Pre-computed metrics        │  │
   │  └────────────────────────────────┘  │
   └──────────────────────────────────────┘


Step 5: Visualization & Analysis
─────────────────────────────────
   ┌──────────────────────────────────────┐
   │          CLICKHOUSE                  │
   └────────┬─────────────────┬───────────┘
            │                 │
            │ SQL Queries     │ SQL Queries
            │                 │
     ┌──────▼──────┐   ┌──────▼──────┐
     │   Grafana   │   │   Jupyter   │
     │ Dashboards  │   │  Notebooks  │
     │             │   │             │
     │ - Real-time │   │ - Ad-hoc    │
     │ - Alerts    │   │ - ML        │
     │ - Maps      │   │ - Reports   │
     └─────────────┘   └─────────────┘
            │                 │
            │                 │
            ▼                 ▼
     ┌──────────────────────────┐
     │    Security Analyst      │
     │   / Researcher           │
     └──────────────────────────┘
```

### Timeline: From Attack to Detection

```
T+0s   : Attacker sends malicious packet
T+0s   : Honeypot receives and logs interaction
T+0s   : Suricata captures packet, evaluates rules
T+0.1s : Suricata generates alert (if rule matched)
T+1s   : Logstash reads new log lines (1-second polling)
T+1.5s : Logstash processes (parse, GeoIP, anonymize)
T+2s   : ClickHouse receives INSERT, writes to table
T+2s   : Materialized views update automatically
T+3s   : Grafana dashboard refreshes (auto-refresh interval)
T+3s   : Alert visible in dashboard

Total latency: ~3 seconds from attack to visualization
```

---

## Security Architecture

### Defense in Depth

```
┌───────────────────────────────────────────────────────────┐
│              SECURITY LAYERS                              │
└───────────────────────────────────────────────────────────┘

Layer 1: Network Isolation
──────────────────────────
  ✓ DMZ honeypots cannot initiate outbound connections
  ✓ Prevents compromised honeypots from attacking others
  ✓ Docker network isolation (separate subnets)
  ✓ No routing between DMZ and management networks

Layer 2: Honeypot Containment
──────────────────────────────
  ✓ All honeypots run in isolated containers
  ✓ Restricted filesystem (read-only where possible)
  ✓ No privilege escalation (non-root processes)
  ✓ Resource limits (CPU, memory)

Layer 3: Data Privacy
──────────────────────
  ✓ IP address anonymization (irreversible SHA256 hash)
  ✓ Unique salt per deployment (ANON_SECRET_KEY)
  ✓ Country-level geolocation only (no precise location)
  ✓ GDPR-compliant (no PII stored)

Layer 4: Monitoring & Detection
────────────────────────────────
  ✓ All traffic monitored by Suricata + Zeek
  ✓ Lateral movement detection (internal DMZ traffic)
  ✓ Health checks for all services
  ✓ Automated alerting on anomalies

Layer 5: Access Control
────────────────────────
  ✓ Grafana authentication required
  ✓ Jupyter token-based access
  ✓ ClickHouse password-protected
  ✓ SSH key-only access to host (recommended)

Layer 6: Audit & Logging
─────────────────────────
  ✓ All actions logged to ClickHouse
  ✓ Centralized log aggregation
  ✓ Tamper-evident (append-only database)
  ✓ Backup and archival procedures
```

### Threat Model

**Threats Mitigated**:
1. ✅ Honeypot compromise → Contained, cannot attack external systems
2. ✅ Data breach → IPs anonymized, no PII exposed
3. ✅ Service exploitation → Honeypots are designed to be "exploited"
4. ✅ Lateral movement → Detected and logged
5. ✅ DDoS amplification → Rate limiting, egress blocked

**Residual Risks**:
1. ⚠️ Host system compromise → Require host hardening (see Ansible playbooks)
2. ⚠️ Resource exhaustion → Implement Docker resource limits
3. ⚠️ False positives → Tune IDS rules, maintain FPR < 5%

---

## Deployment Architecture

### Docker Compose Stack

```yaml
services:
  # DMZ Network (172.20.0.0/24)
  cowrie:
    networks:
      honeypot_net:
        ipv4_address: 172.20.0.10

  dionaea:
    networks:
      honeypot_net:
        ipv4_address: 172.20.0.11

  conpot:
    networks:
      honeypot_net:
        ipv4_address: 172.20.0.12

  # Host Network (IDS)
  suricata:
    network_mode: host  # ← Captures all host traffic

  zeek:
    network_mode: host

  # Management Network (172.21.0.0/24)
  clickhouse:
    networks:
      - management_net

  logstash:
    networks:
      - management_net

  grafana:
    networks:
      - management_net
```

### Volume Mounts

```
Host                          Container
────────────────────────────────────────────────
./data/cowrie         →  /data/cowrie
./data/dionaea        →  /data/dionaea
./data/suricata       →  /var/log/suricata
./configs/suricata    →  /etc/suricata (read-only)
./data/clickhouse     →  /var/lib/clickhouse
```

---

## MITRE ATT&CK Mapping

The system maps detected attacks to MITRE ATT&CK framework:

```
Suricata Rule
──────────────
metadata: mitre_technique_id T1190, mitre_tactic_id initial-access;
     │
     │ (Embedded in alert metadata)
     │
     ▼
Logstash Pipeline
──────────────────
Parse metadata array, extract MITRE fields
     │
     ▼
ClickHouse
───────────
ids_alerts.mitre_technique_id = "T1190"
ids_alerts.mitre_tactic = "initial-access"
     │
     ▼
Grafana / Jupyter
──────────────────
Visualize MITRE ATT&CK heatmap, technique ranking
```

**Supported MITRE Techniques** (examples):
- **T1110.001**: Brute Force (Password Guessing)
- **T1190**: Exploit Public-Facing Application
- **T1570**: Lateral Tool Transfer
- **T1572**: Protocol Tunneling
- **T1105**: Ingress Tool Transfer
- **T0840**: ICS Network Connection Enumeration

---

## Scalability Considerations

### Horizontal Scaling

```
┌────────────────────────────────────────────────┐
│       FUTURE: MULTI-NODE DEPLOYMENT            │
└────────────────────────────────────────────────┘

Current: Single Host
────────────────────
  All containers on one machine
  ClickHouse single node
  Suitable for: Small to medium deployments

Future: Distributed
────────────────────
  Multiple honeypot hosts (geographically distributed)
  ClickHouse cluster (replication + sharding)
  Centralized Logstash + ClickHouse
  Kafka for log buffering (high throughput)
```

---

## References

- [Docker Networking](https://docs.docker.com/network/)
- [ClickHouse Architecture](https://clickhouse.com/docs/en/development/architecture/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Suricata User Guide](https://suricata.readthedocs.io/)

---

**Document Version**: 1.0
**Author**: Agent #6b - Testing & Documentation
