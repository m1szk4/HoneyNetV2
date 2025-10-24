# PCAP Network Traffic Capture

## Overview

The PCAP capture system provides full packet capture capabilities for HoneyNetV2, recording all network traffic to/from honeypots in PCAP format. This enables:

- **Post-incident analysis**: Forensic investigation of attacks
- **Traffic replay**: Reproduce attack scenarios for testing
- **Deep packet inspection**: Manual analysis with tools like Wireshark
- **Compliance**: Meet regulatory requirements for network monitoring
- **Threat intelligence**: Share attack samples with security community

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                   Network Traffic                     │
│                   (eth0 interface)                    │
└────────────────────┬─────────────────────────────────┘
                     │
         ┌───────────┼───────────┐
         │           │           │
    ┌────▼────┐ ┌───▼────┐ ┌───▼────┐
    │Suricata │ │  Zeek  │ │  PCAP  │
    │  (IDS)  │ │ (NSM)  │ │Capture │
    └─────────┘ └────────┘ └────┬───┘
                                 │
                    ┌────────────▼────────────┐
                    │   PCAP Storage          │
                    │   /data/pcap/YYYY-MM-DD/│
                    │   - Hourly rotation     │
                    │   - 60 days retention   │
                    └─────────────────────────┘
```

## Configuration

### Environment Variables

Configure in `.env` file:

```bash
# Network interface to monitor (default: eth0)
PCAP_INTERFACE=eth0

# Rotation interval in seconds (default: 3600 = 1 hour)
PCAP_ROTATION_SECONDS=3600

# Maximum file size in MB before rotation (default: 1000 MB)
PCAP_MAX_SIZE=1000

# Packet snapshot length in bytes (default: 65535 = full packet)
PCAP_SNAPLEN=65535

# Buffer size in KB (default: 8192 = 8MB)
PCAP_BUFFER_SIZE=8192

# Container resource limits
PCAP_MEM_LIMIT=512m
PCAP_CPUS=0.5

# Retention period in days (default: 60)
PCAP_RETENTION_DAYS=60
```

### Directory Structure

PCAP files are organized by date:

```
data/pcap/
├── 2025-10-24/
│   ├── capture_20251024_000000.pcap  # 00:00 - 01:00
│   ├── capture_20251024_010000.pcap  # 01:00 - 02:00
│   ├── capture_20251024_020000.pcap  # 02:00 - 03:00
│   └── ...
├── 2025-10-25/
│   ├── capture_20251025_000000.pcap
│   └── ...
└── ...
```

**File naming convention**: `capture_YYYYMMDD_HH0000.pcap`
- `YYYYMMDD`: Date (year, month, day)
- `HH0000`: Hour of capture start (00:00, 01:00, etc.)

## Deployment

### 1. Start PCAP Capture

The PCAP capture container starts automatically with HoneyNetV2:

```bash
# Deploy entire honeypot infrastructure (includes PCAP)
./scripts/deployment/deploy.sh

# Or start PCAP service separately
docker-compose up -d pcap
```

### 2. Verify PCAP Capture

Check if container is running:

```bash
docker-compose ps pcap
docker-compose logs -f pcap
```

Expected output:
```
[2025-10-24 12:00:00] Starting PCAP capture on interface: eth0
[2025-10-24 12:00:00] Base directory: /data/pcap
[2025-10-24 12:00:00] Rotation interval: 3600 seconds (1 hour(s))
[2025-10-24 12:00:01] tcpdump started with PID: 123
```

Check PCAP files are being created:

```bash
ls -lh data/pcap/$(date +%Y-%m-%d)/
```

### 3. Install Automatic Cleanup (Retention Policy)

Install systemd timer for automatic cleanup:

```bash
sudo ./scripts/pcap/install_systemd.sh
```

Or configure cron manually:

```bash
# Add to crontab
0 3 * * * /opt/honeynet/scripts/pcap/cleanup_old_pcaps.sh 60
```

### 4. Run Tests

Validate PCAP capture functionality:

```bash
python3 tests/test_pcap.py
```

## Operation

### Monitoring PCAP Capture

**View container logs**:
```bash
docker-compose logs -f pcap
```

**Check disk usage**:
```bash
du -sh data/pcap/
du -h data/pcap/ | tail -20
```

**List PCAP files**:
```bash
# List today's files
ls -lh data/pcap/$(date +%Y-%m-%d)/

# List all files
find data/pcap/ -name "*.pcap" -exec ls -lh {} \;

# Count total files
find data/pcap/ -name "*.pcap" | wc -l
```

**Check oldest/newest files**:
```bash
# Oldest
find data/pcap/ -name "*.pcap" -printf '%T+ %p\n' | sort | head -1

# Newest
find data/pcap/ -name "*.pcap" -printf '%T+ %p\n' | sort | tail -1
```

### Manual File Rotation

PCAP files rotate automatically every hour (3600 seconds). To change rotation interval:

1. Edit `.env`:
   ```bash
   PCAP_ROTATION_SECONDS=1800  # 30 minutes
   ```

2. Restart container:
   ```bash
   docker-compose restart pcap
   ```

### Retention Management

**Run cleanup manually**:
```bash
# Dry run (no files deleted)
PCAP_DRY_RUN=true ./scripts/pcap/cleanup_old_pcaps.sh 60

# Actual cleanup (remove files older than 60 days)
./scripts/pcap/cleanup_old_pcaps.sh 60
```

**Check retention timer status**:
```bash
systemctl status honeynet-pcap-cleanup.timer
systemctl list-timers honeynet-pcap-cleanup.timer
```

**View cleanup logs**:
```bash
journalctl -u honeynet-pcap-cleanup.service -f
```

### Storage Estimation

**Estimated storage requirements**:

| Network Activity | MB/hour | GB/day | GB/45 days | GB/60 days |
|-----------------|---------|---------|------------|------------|
| Low (10 Mbps avg) | 4,500 | 108 | 4,860 | 6,480 |
| Medium (50 Mbps avg) | 22,500 | 540 | 24,300 | 32,400 |
| High (100 Mbps avg) | 45,000 | 1,080 | 48,600 | 64,800 |

**Note**: Actual storage depends on:
- Attack frequency and volume
- Honeypot exposure (public IP, open ports)
- Network noise and scanning activity
- Packet size distribution

**Recommended**: Provision **500-700 GB** for 60 days retention with medium activity.

### Changing Network Interface

By default, PCAP captures on `eth0`. To monitor a different interface:

**Option 1: Environment variable** (recommended)
```bash
# Edit .env
PCAP_INTERFACE=br-1234567890ab  # Docker bridge interface
```

**Option 2: Runtime override**
```bash
docker-compose up -d pcap -e PCAP_INTERFACE=ens160
```

**Find available interfaces**:
```bash
# On host
ip -br link show

# Inside container
docker exec honeynet-pcap ip -br link show
```

**For Docker bridge network** (honeypot_net):
```bash
# Find bridge interface name
docker network inspect honeynet_honeypot_net | grep com.docker.network.bridge.name
```

## Analysis

### Using tcpdump

**Read PCAP file**:
```bash
tcpdump -r data/pcap/2025-10-24/capture_20251024_120000.pcap
```

**Filter by protocol**:
```bash
# SSH traffic
tcpdump -r file.pcap port 22

# HTTP traffic
tcpdump -r file.pcap port 80

# Specific IP
tcpdump -r file.pcap host 203.0.113.45
```

**Extract specific packets**:
```bash
# First 100 packets
tcpdump -r file.pcap -c 100

# Packets with payload
tcpdump -r file.pcap -A

# Hex dump
tcpdump -r file.pcap -X
```

### Using Wireshark

**Local analysis**:
```bash
# Copy file from server
scp server:/opt/honeynet/data/pcap/2025-10-24/capture_*.pcap .

# Open in Wireshark
wireshark capture_20251024_120000.pcap
```

**Useful Wireshark filters**:
```
tcp.port == 22                    # SSH traffic
http                              # HTTP traffic
ip.src == 172.20.0.10            # Traffic from Cowrie
tcp.flags.syn == 1 && tcp.flags.ack == 0  # SYN scans
```

### Using tshark (CLI)

**Statistics**:
```bash
# Protocol hierarchy
tshark -r file.pcap -q -z io,phs

# Conversation statistics
tshark -r file.pcap -q -z conv,tcp

# HTTP statistics
tshark -r file.pcap -q -z http,tree
```

**Extract data**:
```bash
# Export HTTP objects
tshark -r file.pcap --export-objects http,/tmp/http_objects/

# Extract credentials
tshark -r file.pcap -Y "ssh" -T fields -e tcp.payload
```

### Merging PCAP Files

**Merge multiple files**:
```bash
mergecap -w merged.pcap file1.pcap file2.pcap file3.pcap

# Merge all files from a day
mergecap -w 2025-10-24_full.pcap data/pcap/2025-10-24/*.pcap
```

### Integration with Suricata/Zeek

PCAP capture runs **independently** from Suricata and Zeek:

- **Suricata**: Real-time IDS alerts (fast pattern matching)
- **Zeek**: Real-time protocol analysis and logging
- **PCAP**: Full packet capture for forensics

All three services capture from the **same interface** (`eth0`) simultaneously without interference.

## Troubleshooting

### Container not starting

**Check logs**:
```bash
docker-compose logs pcap
```

**Common issues**:

1. **Interface not found**:
   ```
   ERROR: Interface eth0 does not exist!
   ```
   Solution: Set correct interface in `.env` (PCAP_INTERFACE)

2. **Permission denied**:
   ```
   tcpdump: permission denied
   ```
   Solution: Container needs NET_ADMIN and NET_RAW capabilities (already configured)

3. **Disk full**:
   ```
   tcpdump: /data/pcap/...: No space left on device
   ```
   Solution: Free up space or enable retention cleanup

### No files being created

**Check container is running**:
```bash
docker-compose ps pcap
```

**Check logs for errors**:
```bash
docker-compose logs pcap | grep -i error
```

**Check directory permissions**:
```bash
ls -ld data/pcap/
# Should be writable by container user
```

**Test manually**:
```bash
docker exec honeynet-pcap tcpdump -i eth0 -c 10
```

### Files too large

If PCAP files grow too large:

1. **Reduce rotation interval**:
   ```bash
   PCAP_ROTATION_SECONDS=1800  # 30 minutes instead of 1 hour
   ```

2. **Reduce snapshot length**:
   ```bash
   PCAP_SNAPLEN=96  # Capture only headers (not full payload)
   ```

3. **Add BPF filter** (capture only specific traffic):
   Edit `scripts/pcap/capture_traffic.sh` and add filter to tcpdump command:
   ```bash
   tcpdump -i eth0 \
       -w ... \
       'port 22 or port 80 or port 443'  # Only SSH, HTTP, HTTPS
   ```

### High CPU usage

If PCAP capture uses too much CPU:

1. **Reduce buffer size**:
   ```bash
   PCAP_BUFFER_SIZE=2048  # Smaller buffer
   ```

2. **Limit CPU**:
   ```bash
   PCAP_CPUS=0.25  # Use only 25% of one CPU core
   ```

3. **Use hardware acceleration** (if available):
   Enable offloading on network interface (host):
   ```bash
   ethtool -K eth0 rx-checksumming on
   ethtool -K eth0 tx-checksumming on
   ```

## Security Considerations

### Data Sensitivity

PCAP files contain **unencrypted packet payloads**, including:
- Passwords (if sent in clear text)
- Attack payloads and exploits
- Malware samples
- Personally identifiable information (PII)

**Recommendations**:
1. **Encrypt storage**: Use encrypted disk/volume for `/data/pcap/`
2. **Access control**: Restrict file permissions to authorized users only
3. **Secure transfer**: Use encrypted channels (SCP, SFTP) when copying files
4. **Retention compliance**: Follow legal requirements for data retention

### File Permissions

Ensure PCAP files are readable only by authorized users:

```bash
# Set restrictive permissions
chmod 700 data/pcap/
chmod 600 data/pcap/**/*.pcap

# Set ownership
chown -R honeynet:honeynet data/pcap/
```

### Anonymization

Unlike honeypot logs (which anonymize IPs), PCAP files contain **raw packet data**.

To anonymize PCAP files:

```bash
# Install tcprewrite
sudo apt install tcpreplay

# Anonymize source IPs
tcprewrite --infile=capture.pcap \
           --outfile=capture_anon.pcap \
           --srcipmap=0.0.0.0/0:192.0.2.0/24

# Randomize MAC addresses
tcprewrite --infile=capture.pcap \
           --outfile=capture_anon.pcap \
           --enet-dmac=00:00:00:00:00:01 \
           --enet-smac=00:00:00:00:00:02
```

## Performance Tuning

### Buffer Size Optimization

For high-traffic networks:

```bash
# Increase buffer to 32MB
PCAP_BUFFER_SIZE=32768
```

Monitor for packet drops:
```bash
docker-compose logs pcap | grep "packets dropped"
```

### Disk I/O Optimization

1. **Use dedicated disk** for PCAP storage
2. **Enable write caching** (if safe):
   ```bash
   mount -o remount,noatime,nodiratime /data/pcap
   ```
3. **Use SSD** for better write performance

### Compression

Compress old PCAP files to save space:

```bash
# Compress files older than 7 days
find data/pcap/ -name "*.pcap" -mtime +7 -exec gzip {} \;

# Read compressed files
tcpdump -r file.pcap.gz
```

## Integration Examples

### Alert-triggered PCAP extraction

Extract PCAP for specific Suricata alert:

```bash
#!/bin/bash
# Extract PCAP around alert time

ALERT_TIME="2025-10-24 14:32:15"
ALERT_IP="203.0.113.45"

# Find PCAP file for that hour
PCAP_FILE="data/pcap/2025-10-24/capture_20251024_140000.pcap"

# Extract relevant packets (±5 minutes around alert)
tcpdump -r "$PCAP_FILE" \
    -w "alert_$ALERT_IP.pcap" \
    "host $ALERT_IP and \
     (tcp[tcpflags] & tcp-syn != 0 or \
      tcp[tcpflags] & tcp-ack != 0)"
```

### Automated PCAP analysis

```bash
#!/bin/bash
# Nightly PCAP analysis

for pcap in data/pcap/$(date -d yesterday +%Y-%m-%d)/*.pcap; do
    # Extract statistics
    tshark -r "$pcap" -q -z io,phs > "analysis/$(basename $pcap .pcap).stats"

    # Extract malware samples
    tshark -r "$pcap" --export-objects http,"malware/$(date -d yesterday +%Y-%m-%d)/"
done
```

## References

- [tcpdump manual](https://www.tcpdump.org/manpages/tcpdump.1.html)
- [Wireshark documentation](https://www.wireshark.org/docs/)
- [PCAP format specification](https://wiki.wireshark.org/Development/LibpcapFileFormat)
- [BPF filter syntax](https://www.tcpdump.org/manpages/pcap-filter.7.html)

## See Also

- [Architecture Documentation](architecture.md)
- [Configuration Guide](configuration.md)
- [Testing Guide](testing_guide.md)
- [Maintenance Documentation](maintenance.md)
