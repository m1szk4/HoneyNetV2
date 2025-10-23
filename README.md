# HoneyNetV2

A comprehensive honeypot infrastructure for cybersecurity threat intelligence and research. HoneyNetV2 deploys multiple honeypots, network intrusion detection systems, and analytics tools in an isolated DMZ environment to capture and analyze real-world cyber attacks.

## Features

- **Multiple Honeypots**:
  - **Cowrie**: SSH/Telnet honeypot for capturing brute force attacks and malware
  - **Dionaea**: Multi-protocol honeypot (SMB, HTTP, FTP, MSSQL, MySQL)
  - **Conpot**: ICS/SCADA honeypot for industrial control system attacks

- **Network Intrusion Detection**:
  - **Suricata**: High-performance IDS with custom rules
  - **Zeek**: Network security monitor with protocol analysis

- **Data Analytics**:
  - **ClickHouse**: High-performance OLAP database for attack data
  - **Logstash**: ETL pipeline with IP anonymization
  - **Grafana**: Interactive dashboards and visualizations
  - **Jupyter**: Data science notebooks for threat analysis

- **Security Features**:
  - DMZ network isolation (no outbound connections from honeypots)
  - IP address anonymization (GDPR-compliant)
  - System hardening with Ansible
  - Automated testing and monitoring

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Internet / Attackers                     │
└──────────────────────────┬──────────────────────────────────┘
                           │
                    ┌──────▼──────┐
                    │   Firewall   │
                    │  (DMZ Rules) │
                    └──────┬──────┘
                           │
        ┌──────────────────┼──────────────────┐
        │      Honeypot Network (DMZ)         │
        │      172.20.0.0/24                  │
        │  ┌─────────┬─────────┬─────────┐   │
        │  │ Cowrie  │ Dionaea │ Conpot  │   │
        │  │ SSH/Tel │ Multi-P │   ICS   │   │
        │  └─────────┴─────────┴─────────┘   │
        └─────────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │           IDS/Monitoring            │
        │  ┌─────────┐      ┌─────────┐      │
        │  │Suricata │      │  Zeek   │      │
        │  └─────────┘      └─────────┘      │
        └─────────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │    Management Network               │
        │    172.21.0.0/24                    │
        │  ┌──────────┬──────────┬─────────┐ │
        │  │ClickHouse│ Logstash │ Grafana │ │
        │  └──────────┴──────────┴─────────┘ │
        │       ┌─────────┐                   │
        │       │ Jupyter │                   │
        │       └─────────┘                   │
        └─────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Ubuntu 20.04+ or Debian 11+ (recommended)
- Docker 20.10+
- Docker Compose 2.0+
- 4GB RAM minimum (8GB recommended)
- 50GB free disk space

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/m1szk4/HoneyNetV2.git
   cd HoneyNetV2
   ```

2. **Configure environment**:
   ```bash
   cp .env.example .env
   nano .env  # Edit configuration (CHANGE ALL PASSWORDS!)
   ```

3. **Deploy with script**:
   ```bash
   ./scripts/deployment/deploy.sh
   ```

   Or manually:
   ```bash
   # Create data directories
   mkdir -p data/{cowrie,dionaea,conpot,suricata,zeek,clickhouse,grafana,logstash}

   # Start services
   docker-compose up -d

   # Check status
   docker-compose ps
   ```

4. **Verify deployment**:
   ```bash
   # Run tests
   python3 tests/test_ports.py
   python3 tests/test_isolation.py
   ```

### Access Services

- **Grafana**: http://localhost:3000 (default: admin/admin)
- **Jupyter**: http://localhost:8888 (token in .env)
- **ClickHouse**: http://localhost:8123

## Configuration

### Environment Variables

Key variables in `.env`:

- `TZ`: Timezone (default: UTC)
- `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD`: Database credentials
- `ANON_SECRET_KEY`: Secret for IP anonymization (must be changed!)
- `GRAFANA_ADMIN_PASSWORD`: Grafana admin password
- `JUPYTER_TOKEN`: Jupyter notebook access token

### Network Configuration

- **Honeypot DMZ**: 172.20.0.0/24 (isolated, no outbound)
- **Management**: 172.21.0.0/24 (full access)

### Exposed Ports

Honeypot services:
- 22, 23, 2323: SSH/Telnet (Cowrie)
- 21, 80, 443, 445, 1433, 3306, 8080: Various protocols (Dionaea)
- 102, 502, 161/udp, 47808/udp, 623/udp: ICS protocols (Conpot)

## Usage

### Monitoring

Check system health:
```bash
./scripts/monitoring/health_check.sh
```

Generate daily report:
```bash
./scripts/monitoring/daily_report.sh
```

View logs:
```bash
docker-compose logs -f cowrie dionaea conpot
docker-compose logs -f suricata zeek
```

### Data Analysis

Access Grafana dashboards or Jupyter notebooks for data analysis.

Example ClickHouse queries:
```sql
-- Top attacked ports
SELECT dest_port, count() as attacks
FROM honeypot_events
WHERE timestamp > now() - INTERVAL 24 HOUR
GROUP BY dest_port
ORDER BY attacks DESC
LIMIT 10;

-- Most common credentials
SELECT username, password, count() as attempts
FROM credentials
WHERE timestamp > now() - INTERVAL 7 DAY
GROUP BY username, password
ORDER BY attempts DESC
LIMIT 20;
```

## Testing

Run all tests:
```bash
# Port accessibility
python3 tests/test_ports.py

# DMZ isolation
python3 tests/test_isolation.py

# End-to-end
python3 tests/test_e2e.py
```

## Ansible Automation

For production deployment with hardening:

```bash
# Configure hosts
nano ansible/inventory/hosts.ini

# Run playbooks
ansible-playbook -i ansible/inventory/hosts.ini ansible/playbooks/00-hardening.yml
ansible-playbook -i ansible/inventory/hosts.ini ansible/playbooks/01-docker-install.yml
ansible-playbook -i ansible/inventory/hosts.ini ansible/playbooks/02-deploy-honeypots.yml
```

## Security Considerations

### DMZ Isolation

Honeypots are isolated in a DMZ network with:
- No outbound internet access (masquerade disabled)
- Firewall rules blocking egress traffic
- Network monitoring on all traffic

This prevents compromised honeypots from being used in attacks.

### Data Privacy

- All source IP addresses are anonymized using SHA-256 hashing
- Change `ANON_SECRET_KEY` in `.env` for your deployment
- Data retention: 90 days (configurable in ClickHouse schema)

### Operational Security

- Change all default passwords in `.env`
- Restrict access to management interfaces (Grafana, Jupyter)
- Use strong firewall rules on the host
- Monitor for unusual activity
- Keep Docker images updated

## Maintenance

### Backup

```bash
# Backup ClickHouse data
docker exec honeynet-clickhouse clickhouse-client --query "BACKUP DATABASE honeynet TO Disk('backups', 'backup.zip')"

# Backup Grafana dashboards
tar -czf grafana-backup.tar.gz data/grafana/
```

### Updates

```bash
# Pull latest images
docker-compose pull

# Restart services
docker-compose up -d
```

### Cleanup

```bash
# Remove old containers
docker-compose down

# Remove volumes (WARNING: deletes all data!)
docker-compose down -v

# Clean up disk space
docker system prune -a
```

## Troubleshooting

### Containers not starting

```bash
# Check logs
docker-compose logs <service>

# Check resource usage
docker stats

# Verify .env configuration
cat .env
```

### No attacks being captured

- Verify ports are open: `python3 tests/test_ports.py`
- Check firewall rules: `sudo ufw status`
- Review honeypot logs: `docker-compose logs cowrie`

### ClickHouse connection errors

```bash
# Test connectivity
curl http://localhost:8123/ping

# Check credentials in .env
docker-compose logs clickhouse
```

## Project Structure

```
HoneyNetV2/
├── ansible/              # Ansible playbooks for deployment
├── configs/              # Service configuration files
├── data/                 # Runtime data (not in git)
├── notebooks/            # Jupyter analysis notebooks
├── scripts/              # Helper scripts
│   ├── deployment/       # Deployment automation
│   └── monitoring/       # Health checks and reports
├── tests/                # Automated tests
├── docker-compose.yml    # Service orchestration
└── .env.example          # Environment configuration template
```

## Contributing

This project is for cybersecurity research and education. Contributions welcome!

## License

MIT License - See LICENSE file

## Credits

Built with:
- [Cowrie](https://github.com/cowrie/cowrie)
- [Dionaea](https://github.com/DinoTools/dionaea)
- [Conpot](https://github.com/mushorg/conpot)
- [Suricata](https://suricata.io/)
- [Zeek](https://zeek.org/)
- [ClickHouse](https://clickhouse.com/)
- [Grafana](https://grafana.com/)

## Disclaimer

This honeypot infrastructure is for research and educational purposes only. Operators are responsible for compliance with local laws and regulations. Never use honeypots to attack or harm others.

## Support

For issues and questions:
- GitHub Issues: https://github.com/m1szk4/HoneyNetV2/issues
- Documentation: See `docs/` directory (to be created)

---

**Agent 1 Complete**: Infrastructure and deployment foundation established!