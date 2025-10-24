# PCAP Capture Scripts

Scripts for managing PCAP network traffic capture in HoneyNetV2.

## Scripts

### capture_traffic.sh

Main PCAP capture script that runs inside the Docker container.

**Usage**:
```bash
./capture_traffic.sh [interface]
```

**Features**:
- Captures all network traffic on specified interface
- Automatic hourly rotation (configurable)
- Date-based directory structure (`YYYY-MM-DD/`)
- Graceful shutdown on SIGTERM/SIGINT
- Configurable via environment variables

**Environment Variables**:
- `PCAP_INTERFACE`: Network interface to monitor (default: eth0)
- `PCAP_DIR`: Base directory for PCAP files (default: /data/pcap)
- `PCAP_ROTATION_SECONDS`: Rotation interval in seconds (default: 3600)
- `PCAP_MAX_SIZE`: Max file size in MB before rotation (default: 1000)
- `PCAP_SNAPLEN`: Packet snapshot length in bytes (default: 65535)
- `PCAP_BUFFER_SIZE`: Buffer size in KB (default: 8192)

**Example**:
```bash
# Capture on eth0 with default settings
./capture_traffic.sh

# Capture on specific interface
./capture_traffic.sh ens160

# Custom configuration
PCAP_ROTATION_SECONDS=1800 \
PCAP_MAX_SIZE=500 \
./capture_traffic.sh eth0
```

---

### cleanup_old_pcaps.sh

Retention policy enforcement - removes PCAP files older than specified days.

**Usage**:
```bash
./cleanup_old_pcaps.sh [retention_days]
```

**Features**:
- Removes files older than retention period
- Dry-run mode for safe testing
- Detailed logging and statistics
- Removes empty directories
- Reports disk space freed

**Environment Variables**:
- `PCAP_DIR`: Base directory for PCAP files (default: /data/pcap)
- `PCAP_RETENTION_DAYS`: Retention period in days (default: 60)
- `PCAP_DRY_RUN`: Enable dry-run mode (default: false)

**Examples**:
```bash
# Remove files older than 60 days
./cleanup_old_pcaps.sh 60

# Dry run (no files deleted)
PCAP_DRY_RUN=true ./cleanup_old_pcaps.sh 60

# Remove files older than 30 days
./cleanup_old_pcaps.sh 30

# Custom PCAP directory
PCAP_DIR=/mnt/pcap ./cleanup_old_pcaps.sh 45
```

---

### install_systemd.sh

Installs systemd service and timer for automatic PCAP cleanup.

**Usage**:
```bash
sudo ./install_systemd.sh
```

**Features**:
- Installs systemd service and timer units
- Configures daily cleanup at 03:00 AM
- Updates paths to match installation directory
- Enables and starts timer automatically

**Requirements**:
- Must be run as root (sudo)
- systemd-based Linux distribution

**Example**:
```bash
# Install systemd timer
sudo ./install_systemd.sh

# Check timer status
systemctl status honeynet-pcap-cleanup.timer

# View next scheduled run
systemctl list-timers honeynet-pcap-cleanup.timer

# Run cleanup manually
sudo systemctl start honeynet-pcap-cleanup.service

# View logs
journalctl -u honeynet-pcap-cleanup.service
```

## Integration with HoneyNetV2

### Docker Compose

The PCAP capture service is defined in `docker-compose.yml`:

```yaml
pcap:
  image: kalilinux/kali-rolling:latest
  container_name: honeynet-pcap
  restart: unless-stopped
  network_mode: host
  volumes:
    - ./scripts/pcap/capture_traffic.sh:/opt/capture_traffic.sh:ro
    - ./data/pcap:/data/pcap:rw
  environment:
    - PCAP_INTERFACE=${PCAP_INTERFACE:-eth0}
    - PCAP_DIR=/data/pcap
    - PCAP_RETENTION_DAYS=${PCAP_RETENTION_DAYS:-60}
  cap_add:
    - NET_ADMIN
    - NET_RAW
```

### Systemd Timer

The cleanup timer is configured to run daily:

- **Service**: `/etc/systemd/system/honeynet-pcap-cleanup.service`
- **Timer**: `/etc/systemd/system/honeynet-pcap-cleanup.timer`
- **Schedule**: Daily at 03:00 AM
- **Persistent**: Yes (runs on boot if missed)

## Directory Structure

```
data/pcap/
├── 2025-10-24/
│   ├── capture_20251024_000000.pcap  # 00:00 - 01:00
│   ├── capture_20251024_010000.pcap  # 01:00 - 02:00
│   ├── capture_20251024_020000.pcap  # 02:00 - 03:00
│   └── ...
├── 2025-10-25/
│   └── ...
└── ...
```

## Monitoring

### Check PCAP Capture Status

```bash
# Container status
docker-compose ps pcap

# View logs
docker-compose logs -f pcap

# Check files being created
ls -lh data/pcap/$(date +%Y-%m-%d)/
```

### Check Disk Usage

```bash
# Total PCAP disk usage
du -sh data/pcap/

# Usage by day
du -h data/pcap/ | tail -20

# Count files
find data/pcap/ -name "*.pcap" | wc -l
```

### Manual Operations

```bash
# Restart capture
docker-compose restart pcap

# Stop capture
docker-compose stop pcap

# Run cleanup manually
./cleanup_old_pcaps.sh 60

# Test cleanup (dry-run)
PCAP_DRY_RUN=true ./cleanup_old_pcaps.sh 60
```

## Troubleshooting

### Container not starting

```bash
# Check logs for errors
docker-compose logs pcap

# Verify interface exists
ip -br link show

# Test manually
docker exec honeynet-pcap tcpdump -i eth0 -c 10
```

### No files being created

```bash
# Check directory permissions
ls -ld data/pcap/

# Check disk space
df -h

# Verify tcpdump is running inside container
docker exec honeynet-pcap ps aux | grep tcpdump
```

### Cleanup not running

```bash
# Check timer status
systemctl status honeynet-pcap-cleanup.timer

# Check timer schedule
systemctl list-timers honeynet-pcap-cleanup.timer

# View cleanup logs
journalctl -u honeynet-pcap-cleanup.service -f

# Run cleanup manually
sudo systemctl start honeynet-pcap-cleanup.service
```

## Performance Considerations

### Disk I/O

- **Recommendation**: Use dedicated disk for `/data/pcap/`
- **SSD preferred**: Better write performance for high-traffic networks
- **Mount options**: Consider `noatime,nodiratime` to reduce writes

### CPU Usage

- Default CPU limit: 0.5 cores
- Increase if packet drops occur: `PCAP_CPUS=1.0`
- Monitor: `docker stats honeynet-pcap`

### Memory

- Default memory limit: 512 MB
- Buffer size: 8 MB (default)
- Increase for high-traffic: `PCAP_BUFFER_SIZE=32768` (32 MB)

### Packet Drops

Check for dropped packets:

```bash
docker-compose logs pcap | grep "packets dropped"
```

If drops occur:
1. Increase buffer size (`PCAP_BUFFER_SIZE`)
2. Increase memory limit (`PCAP_MEM_LIMIT`)
3. Use faster disk (SSD)
4. Reduce snapshot length (`PCAP_SNAPLEN=96` for headers only)

## Security

### File Permissions

PCAP files contain sensitive data. Restrict access:

```bash
# Restrict directory
chmod 700 data/pcap/

# Restrict files
chmod 600 data/pcap/**/*.pcap

# Set ownership
chown -R honeynet:honeynet data/pcap/
```

### Encryption

Encrypt PCAP storage:

```bash
# LUKS encrypted volume (example)
cryptsetup luksFormat /dev/sdb1
cryptsetup luksOpen /dev/sdb1 pcap_encrypted
mkfs.ext4 /dev/mapper/pcap_encrypted
mount /dev/mapper/pcap_encrypted /opt/honeynet/data/pcap
```

### Data Retention Compliance

Ensure compliance with data retention regulations:

- **GDPR**: Consider anonymization for EU data
- **Log retention**: Follow organizational policies
- **Legal hold**: Preserve relevant data for investigations

## See Also

- [PCAP Capture Documentation](../../docs/pcap_capture.md)
- [Testing Guide](../../docs/testing_guide.md)
- [Maintenance Documentation](../../docs/maintenance.md)
