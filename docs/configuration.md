# HoneyNetV2 Configuration Guide

## Overview

This document provides comprehensive configuration guidance for HoneyNetV2, including environment variables, service configurations, and tuning parameters.

**Last Updated**: 2025-10-24

---

## Table of Contents

1. [Environment Variables (.env)](#environment-variables-env)
2. [Honeypot Configuration](#honeypot-configuration)
3. [IDS Configuration](#ids-configuration)
4. [Database Configuration](#database-configuration)
5. [Network Configuration](#network-configuration)
6. [Security Settings](#security-settings)

---

## Environment Variables (.env)

### Required Variables

Copy `.env.example` to `.env` and modify:

```bash
cp .env.example .env
nano .env
```

### Core Settings

```bash
# Timezone
TZ=UTC                          # System timezone (UTC recommended)

# Database Credentials
CLICKHOUSE_USER=honeynet        # ClickHouse username
CLICKHOUSE_PASSWORD=secure_pass_here   # CHANGE THIS!
CLICKHOUSE_DB=honeynet          # Database name

# IP Anonymization
ANON_SECRET_KEY=random_secret_key_here  # MUST CHANGE! Used for IP hashing
# Generate with: openssl rand -hex 32

# Data Retention
DATA_RETENTION_DAYS=90          # Days to keep data before TTL deletion
EXPORT_DAYS=7                   # Days to export in Parquet backups
LOG_RETENTION_DAYS=30           # Days before archiving raw logs
```

### Service Credentials

```bash
# Grafana
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=admin123   # CHANGE THIS!

# Jupyter
JUPYTER_TOKEN=your_secure_token_here  # CHANGE THIS!
# Generate with: python3 -c "import secrets; print(secrets.token_urlsafe(32))"

# Email Alerts (optional)
ALERT_EMAIL=admin@example.com
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASSWORD=your_app_password
```

### Network Settings

```bash
# Honeypot Networks
HONEYPOT_NETWORK=172.20.0.0/24
MANAGEMENT_NETWORK=172.21.0.0/24

# IP Addresses
COWRIE_IP=172.20.0.10
DIONAEA_IP=172.20.0.11
CONPOT_IP=172.20.0.12
```

### Resource Limits

```bash
# Container Resource Limits
SURICATA_MEM_LIMIT=2g
ZEEK_MEM_LIMIT=2g
CLICKHOUSE_MEM_LIMIT=4g
LOGSTASH_MEM_LIMIT=2g
```

---

## Honeypot Configuration

### Cowrie (SSH/Telnet)

**Location**: `configs/cowrie/cowrie.cfg`

#### Key Settings

```ini
[honeypot]
hostname = server01                # Fake hostname
log_path = /data/cowrie            # Log directory
download_path = /data/cowrie/downloads  # Malware storage
filesystem_file = /honeyfs.pickle  # Fake filesystem

[ssh]
enabled = true
listen_endpoints = tcp:22:interface=0.0.0.0  # SSH port
version = SSH-2.0-OpenSSH_7.4      # Banner version

[telnet]
enabled = true
listen_endpoints = tcp:23:interface=0.0.0.0  # Telnet port

[output_jsonlog]
logfile = /data/cowrie/cowrie.json
```

#### Customizing User Database

Edit `configs/cowrie/userdb.txt` to add/modify credentials:

```
root:x:root
admin:x:admin
user:x:password123
```

Format: `username:x:password` or `username:*` (any password)

---

### Dionaea (Multi-Protocol)

**Location**: `configs/dionaea/dionaea.cfg`

#### Key Settings

```yaml
modules:
  python:
    http:
      enabled: true
      ports: [80, 443, 8080]

    ftp:
      enabled: true
      ports: [21]

    smb:
      enabled: true
      ports: [445]

    mysql:
      enabled: true
      ports: [3306]

logging:
  default:
    filename: /data/dionaea/dionaea.json
    levels: [info, warning, error]

downloads:
  dir: /data/dionaea/binaries/  # Malware storage
```

---

### Conpot (ICS/SCADA)

**Location**: `configs/conpot/conpot.cfg`

#### Key Settings

```ini
[device]
device_name = Siemens SIMATIC S7-300   # Emulated device

[modbus]
enabled = true
port = 502
slave_id = 1

[snmp]
enabled = true
port = 161
community = public

[s7comm]
enabled = true
port = 102

[logging]
log_file = /data/conpot/conpot.json
```

#### Customizing ICS Templates

Conpot supports multiple device templates:

```bash
# Available templates
ls configs/conpot/templates/
# - default (Generic ICS)
# - guardian_ast (Guardian AST)
# - ipmi (IPMI)
# - kamstrup_382 (Kamstrup smart meter)
```

Change template in docker-compose.yml:

```yaml
conpot:
  command: --template kamstrup_382
```

---

## IDS Configuration

### Suricata

**Location**: `configs/suricata/suricata.yaml`

#### Network Interface

```yaml
af-packet:
  - interface: eth0           # Change if different interface
    threads: auto
    cluster-type: cluster_flow
```

#### Rule Files

```yaml
rule-files:
  - /etc/suricata/rules/honeypot-custom.rules      # Custom rules
  - /etc/suricata/rules/iot-botnet.rules           # IoT-specific
  - /etc/suricata/rules/lateral_movement.rules     # Internal traffic
  - /etc/suricata/rules/emerging-threats.rules     # ET rules (optional)
```

#### Performance Tuning

```yaml
threading:
  set-cpu-affinity: no
  cpu-affinity: []
  detect-thread-ratio: 1.5

stream:
  memcap: 512mb               # Memory for TCP reassembly
  prealloc-sessions: 10000

defrag:
  memcap: 256mb               # Memory for IP defragmentation
```

#### Custom Rules

Edit `configs/suricata/rules/honeypot-custom.rules`:

```
# Example: Detect custom malware C2 beacon
alert tcp $HOME_NET any -> any any (
    msg:"HONEYPOT Custom C2 Beacon";
    content:"BEACON";
    content:"ID=";
    distance:0;
    classtype:trojan-activity;
    metadata:mitre_technique_id T1071.001, mitre_tactic_id command-and-control;
    sid:3000001;
    rev:1;
)
```

**Important**: After editing rules, restart Suricata:

```bash
docker-compose restart suricata
```

---

### Zeek

**Location**: `configs/zeek/local.zeek`

#### Enabled Scripts

```zeek
# Load default scripts
@load base/frameworks/software
@load base/protocols/conn
@load base/protocols/http
@load base/protocols/dns
@load base/protocols/ssl

# Custom ICS detection
@load protocols/modbus
@load protocols/s7comm

# Custom detection scripts
@load /usr/local/zeek/site/detect-iot-attacks.zeek
```

#### Custom Detection Script

Create `configs/zeek/detect-iot-attacks.zeek`:

```zeek
module IotDetect;

export {
    redef enum Notice::Type += {
        IoT_Scanner_Detected
    };
}

event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (is_orig && /Mirai|Gafgyt|Hajime/ in value) {
        NOTICE([$note=IoT_Scanner_Detected,
                $conn=c,
                $msg=fmt("IoT botnet scanner detected: %s", value)]);
    }
}
```

---

## Database Configuration

### ClickHouse

**Location**: `configs/clickhouse/config.xml`

#### Memory Settings

```xml
<clickhouse>
    <max_memory_usage>8GB</max_memory_usage>
    <max_server_memory_usage>12GB</max_server_memory_usage>

    <!-- Query limits -->
    <max_execution_time>300</max_execution_time>
    <max_rows_to_read>10000000000</max_rows_to_read>
</clickhouse>
```

#### User Configuration

**Location**: `configs/clickhouse/users.xml`

```xml
<users>
    <honeynet>
        <password_sha256_hex>YOUR_SHA256_HASH_HERE</password_sha256_hex>
        <networks>
            <ip>::/0</ip>  <!-- Allow all, restrict in production! -->
        </networks>
        <profile>default</profile>
        <quota>default</quota>
    </honeynet>
</users>
```

Generate password hash:

```bash
echo -n 'your_password' | sha256sum
```

---

### Logstash

**Location**: `configs/logstash/pipelines/*.conf`

#### Cowrie Pipeline

**File**: `configs/logstash/pipelines/cowrie.conf`

```ruby
input {
  file {
    path => "/data/cowrie/cowrie.json*"
    start_position => "beginning"
    sincedb_path => "/usr/share/logstash/data/sincedb/cowrie"
    codec => "json"
    tags => ["cowrie"]
  }
}

filter {
  if "cowrie" in [tags] {
    # GeoIP lookup BEFORE anonymization
    if [src_ip] {
      geoip {
        source => "src_ip"
        target => "geoip"
        fields => ["country_code2"]
        tag_on_failure => ["_geoip_lookup_failure"]
      }

      if [geoip][country_code2] {
        mutate {
          add_field => { "source_ip_country" => "%{[geoip][country_code2]}" }
        }
      }

      # IP Anonymization
      fingerprint {
        source => ["src_ip"]
        target => "source_ip_hash"
        method => "SHA256"
        key => "${ANON_SECRET_KEY}"
      }

      mutate {
        remove_field => ["src_ip", "geoip"]  # Remove original IP
      }
    }

    # Additional field mappings...
  }
}

output {
  if "cowrie" in [tags] {
    clickhouse {
      host => "clickhouse"
      port => 8123
      user => "${CLICKHOUSE_USER}"
      password => "${CLICKHOUSE_PASSWORD}"
      table => "honeynet.honeypot_events"
      request_tolerance => 1
      flush_size => 1000
      idle_flush_time => 10
    }
  }
}
```

#### Tuning Logstash Performance

**File**: `configs/logstash/logstash.yml`

```yaml
pipeline.workers: 4              # Number of pipeline workers
pipeline.batch.size: 1000        # Events per batch
pipeline.batch.delay: 50         # Milliseconds to wait for batch

queue.type: persisted            # Persistent queue
queue.max_bytes: 1gb             # Queue size
```

---

## Network Configuration

### Docker Networks

**File**: `docker-compose.yml`

```yaml
networks:
  honeypot_net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24
    driver_opts:
      com.docker.network.bridge.enable_icc: "true"  # Enable inter-container

  management_net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.21.0.0/24
```

### Host Firewall

#### iptables Rules

```bash
# Allow inbound to honeypot ports
iptables -A INPUT -p tcp --dport 22 -j ACCEPT     # SSH
iptables -A INPUT -p tcp --dport 23 -j ACCEPT     # Telnet
iptables -A INPUT -p tcp --dport 80 -j ACCEPT     # HTTP
iptables -A INPUT -p tcp --dport 445 -j ACCEPT    # SMB
iptables -A INPUT -p tcp --dport 502 -j ACCEPT    # Modbus
iptables -A INPUT -p udp --dport 161 -j ACCEPT    # SNMP

# Block egress from DMZ network (CRITICAL for isolation)
iptables -A FORWARD -s 172.20.0.0/24 -j DROP

# Allow management network
iptables -A FORWARD -s 172.21.0.0/24 -j ACCEPT
```

Save rules:

```bash
iptables-save > /etc/iptables/rules.v4
```

---

## Security Settings

### IP Anonymization

**Critical**: Change `ANON_SECRET_KEY` in `.env` to unique value:

```bash
# Generate strong secret
openssl rand -hex 32

# Add to .env
ANON_SECRET_KEY=your_generated_key_here
```

**Warning**: Changing this key after deployment will change all IP hashes (breaks historical correlation).

---

### SSL/TLS for Services

#### Grafana HTTPS

```yaml
# docker-compose.yml
grafana:
  environment:
    - GF_SERVER_PROTOCOL=https
    - GF_SERVER_CERT_FILE=/etc/grafana/cert.pem
    - GF_SERVER_CERT_KEY=/etc/grafana/key.pem
  volumes:
    - ./certs/grafana-cert.pem:/etc/grafana/cert.pem
    - ./certs/grafana-key.pem:/etc/grafana/key.pem
```

Generate self-signed cert:

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout certs/grafana-key.pem \
  -out certs/grafana-cert.pem
```

---

### Access Control

#### Restrict Grafana Access

**File**: `configs/grafana/grafana.ini`

```ini
[auth.anonymous]
enabled = false                 # Disable anonymous access

[auth]
disable_login_form = false
disable_signout_menu = false

[users]
allow_sign_up = false           # Prevent self-registration
```

#### ClickHouse Network Restrictions

**File**: `configs/clickhouse/users.xml`

```xml
<honeynet>
    <networks>
        <ip>172.21.0.0/24</ip>  <!-- Only management network -->
        <ip>127.0.0.1</ip>      <!-- Localhost -->
    </networks>
</honeynet>
```

---

## Monitoring Configuration

### Health Check Script

**File**: `scripts/monitoring/health_check.sh`

Configure thresholds:

```bash
# Thresholds
MAX_CPU_PERCENT=80
MAX_MEM_PERCENT=90
MAX_DISK_PERCENT=85

# Alert email
ALERT_EMAIL="admin@example.com"
```

### Daily Report

**File**: `scripts/monitoring/daily_report.sh`

Configure report settings:

```bash
# Report period
REPORT_DAYS=1

# Email settings
REPORT_EMAIL="team@example.com"
```

Add to crontab:

```bash
0 8 * * * /opt/HoneyNetV2/scripts/monitoring/daily_report.sh
```

---

## Backup Configuration

### Ansible Backup Playbook

**File**: `ansible/playbooks/99-backup.yml`

Configure backup settings:

```yaml
vars:
  export_days: "{{ lookup('env', 'EXPORT_DAYS') | default('7', true) }}"
  backup_dir: "/opt/honeynet_backups"
  backup_retention_days: 30

  # Remote backup (optional)
  remote_backup: false
  remote_host: "backup.example.com"
  remote_path: "/backups/honeynet/"
```

---

## Performance Tuning

### High Traffic Scenarios

For deployments expecting >10,000 events/minute:

#### Increase Logstash Workers

```yaml
# configs/logstash/logstash.yml
pipeline.workers: 8
pipeline.batch.size: 2000
```

#### Increase ClickHouse Buffer

```xml
<!-- configs/clickhouse/config.xml -->
<max_insert_block_size>1048576</max_insert_block_size>
<min_insert_block_size_rows>10000</min_insert_block_size_rows>
```

#### Add Kafka Buffer (Advanced)

For very high throughput, add Kafka between Logstash and ClickHouse:

```
Logstash → Kafka → ClickHouse
```

---

## Troubleshooting

### Configuration Validation

```bash
# Validate Suricata config
docker exec honeynet-suricata suricata -T -c /etc/suricata/suricata.yaml

# Validate Logstash pipelines
docker exec honeynet-logstash bin/logstash -t -f /usr/share/logstash/pipeline/

# Test ClickHouse connection
docker exec honeynet-clickhouse clickhouse-client --query "SELECT 1"
```

### Common Issues

**Issue**: Logs not appearing in ClickHouse

**Checks**:
1. Logstash reading files: `docker logs honeynet-logstash | grep "Completed"`
2. ClickHouse accepting connections: `curl http://localhost:8123/ping`
3. Credentials correct in Logstash pipeline

---

## References

- [Docker Compose Reference](https://docs.docker.com/compose/compose-file/)
- [Suricata Configuration](https://suricata.readthedocs.io/en/latest/configuration/)
- [ClickHouse Settings](https://clickhouse.com/docs/en/operations/settings/)
- [Logstash Configuration](https://www.elastic.co/guide/en/logstash/current/configuration.html)

---

**Document Version**: 1.0
**Author**: Agent #6b - Testing & Documentation
