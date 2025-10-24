# RTSP Honeypot

## Overview

RTSP (Real Time Streaming Protocol) honeypot designed to simulate vulnerable IP cameras and DVR/NVR systems. This honeypot emulates the RTSP service on TCP port 554 and simulates CVE-2014-8361 buffer overflow vulnerability.

## Features

### Protocol Emulation
- **RTSP/1.0 Protocol Support**
  - OPTIONS - Returns available methods
  - DESCRIBE - Returns SDP session description
  - SETUP - Session establishment (with authentication challenge)
  - PLAY/PAUSE - Playback control
  - TEARDOWN - Session termination

### Device Simulation
- Emulates generic IP Camera/DVR device
- Provides minimal SDP (Session Description Protocol) response
- Simulates H.264 video stream capability (no actual streaming)
- Returns device information in Server headers

### Vulnerability Simulation

#### CVE-2014-8361: RTSP Buffer Overflow
The honeypot simulates this critical vulnerability found in many IP cameras:

**Vulnerability Details:**
- Affects DESCRIBE command with abnormally long Authorization headers
- Buffer overflow occurs when Authorization header exceeds 1024 bytes
- Real vulnerable devices crash or allow remote code execution

**Honeypot Behavior:**
- Accepts long Authorization headers (>1024 bytes) without crashing
- **Does NOT close connection** on overflow attempt (critical for IDS detection)
- Logs attack details for analysis
- Allows Suricata rule SID 2000015 to detect the attack pattern

**Attack Detection:**
```
DESCRIBE rtsp://target:554/stream RTSP/1.0
CSeq: 2
Authorization: Basic [>1024 bytes of data]
```

### Attack Detection Capabilities

1. **Buffer Overflow Attempts** (CVE-2014-8361)
   - Long Authorization headers (>1024 bytes)
   - Long URI paths (>2048 bytes)

2. **Brute Force Detection**
   - Multiple authentication attempts (>5 in 60 seconds)
   - Tracks failed login patterns

3. **Reconnaissance Detection**
   - Port scanning attempts
   - Service fingerprinting

## Logging

### JSON Format (Logstash Integration)

All events are logged to `/var/log/rtsp/rtsp.json` in JSON format:

```json
{
  "timestamp": "2025-10-24T12:34:56.789Z",
  "honeypot_type": "rtsp",
  "event_type": "attack_detected",
  "session_id": "a1b2c3d4e5f6g7h8",
  "src_ip": "192.168.1.100",
  "src_port": 54321,
  "dest_ip": "172.20.0.13",
  "dest_port": 554,
  "protocol": "rtsp",
  "method": "DESCRIBE",
  "attack_detected": true,
  "attack_type": "CVE-2014-8361 buffer overflow",
  "attack_info": {
    "type": "buffer_overflow",
    "cve": "CVE-2014-8361",
    "description": "RTSP buffer overflow attempt via long Authorization header",
    "header_length": 2048,
    "threshold": 1024
  }
}
```

### Event Types

- `session_start` - New connection established
- `session_end` - Connection closed
- `options` - OPTIONS request
- `describe` - DESCRIBE request (most common for attacks)
- `setup` - SETUP request
- `setup_unauthorized` - SETUP without authentication
- `play` - PLAY/PAUSE request
- `teardown` - TEARDOWN request
- `attack_detected` - Malicious activity detected
- `unknown_method` - Unsupported RTSP method
- `error` - Error occurred

## Integration with Security Stack

### Suricata Detection

The honeypot works with Suricata rule **SID 2000015**:

```
alert tcp any any -> $HOME_NET 554 (
  msg:"IoT RTSP exploit - CVE-2014-8361 buffer overflow attempt";
  content:"DESCRIBE rtsp://"; depth:20; nocase;
  byte_test:2,>,1024,15,relative;
  flow:to_server,established;
  classtype:attempted-admin;
  reference:cve,2014-8361;
  reference:url,attack.mitre.org/techniques/T1190;
  metadata: mitre_technique_id T1190, mitre_tactic_id TA0001;
  sid:2000015; rev:1;
)
```

**MITRE ATT&CK Mapping:**
- Technique: T1190 (Exploit Public-Facing Application)
- Tactic: TA0001 (Initial Access)

### Zeek Detection

Zeek monitors port 554 connections via `detect-iot-attacks.zeek`:

```zeek
event connection_established(c: connection) {
    if (c$id$resp_p == 554/tcp) {
        NOTICE([$note=IoT_Exploit_Attempt,
                $msg=fmt("RTSP connection attempt from %s", c$id$orig_h),
                $conn=c]);
    }
}
```

### Logstash Pipeline

Events are processed through dedicated RTSP pipeline:
- Parses JSON logs
- Performs GeoIP lookup on source IP
- Anonymizes IP addresses (SHA256 hash)
- Stores in ClickHouse database

### ClickHouse Storage

Events stored in `honeypot_events` table with:
- Monthly partitioning
- 90-day TTL
- Indexed by timestamp, source IP hash, event type

## Docker Deployment

### Standalone

```bash
cd /home/user/HoneyNetV2/honeypots/rtsp
docker build -t rtsp-honeypot .
docker run -d -p 554:554 -v rtsp-logs:/var/log/rtsp rtsp-honeypot
```

### Docker Compose (Recommended)

Integrated with HoneyNetV2 infrastructure:

```yaml
rtsp:
  build: ./honeypots/rtsp
  container_name: honeynet-rtsp
  hostname: rtsp-honeypot
  networks:
    honeypot_dmz:
      ipv4_address: 172.20.0.13
  ports:
    - "554:554/tcp"
  volumes:
    - ./logs/rtsp:/var/log/rtsp
    - ./configs/rtsp:/config:ro
  cap_drop:
    - ALL
  cap_add:
    - NET_BIND_SERVICE
  mem_limit: 256m
  cpus: 0.25
  restart: unless-stopped
  logging:
    driver: json-file
    options:
      max-size: "10m"
      max-file: "3"
```

## Testing

### Basic Connectivity Test

```bash
# Test OPTIONS request
echo -e "OPTIONS rtsp://localhost:554 RTSP/1.0\r\nCSeq: 1\r\n\r\n" | nc localhost 554
```

Expected response:
```
RTSP/1.0 200 OK
CSeq: 1
Server: RTSP/1.0 DVR-Camera-NVR
Public: OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN
```

### Test DESCRIBE Request

```bash
# Test DESCRIBE (returns SDP)
echo -e "DESCRIBE rtsp://localhost:554/stream RTSP/1.0\r\nCSeq: 2\r\n\r\n" | nc localhost 554
```

### Test CVE-2014-8361 Buffer Overflow

```bash
# Generate long Authorization header
python3 -c "
import socket
s = socket.socket()
s.connect(('localhost', 554))
overflow = 'A' * 2048
request = f'DESCRIBE rtsp://localhost:554/stream RTSP/1.0\r\nCSeq: 2\r\nAuthorization: Basic {overflow}\r\n\r\n'
s.send(request.encode())
response = s.recv(4096)
print(response.decode())
s.close()
"
```

Expected:
- Honeypot logs attack with `attack_detected: true`
- Suricata triggers alert SID 2000015
- Connection remains open (does not crash)

### Test with ffmpeg

```bash
# Test with real RTSP client
ffmpeg -rtsp_transport tcp -i rtsp://localhost:554/stream -t 5 -f null -
```

Expected:
- Honeypot responds to OPTIONS and DESCRIBE
- Returns SDP with H.264 video track
- SETUP request triggers authentication challenge

### Test Brute Force Detection

```bash
# Send multiple authentication attempts
for i in {1..10}; do
  echo -e "DESCRIBE rtsp://localhost:554/stream RTSP/1.0\r\nCSeq: $i\r\nAuthorization: Basic dGVzdDp0ZXN0\r\n\r\n" | nc localhost 554
  sleep 1
done
```

Expected:
- After 5 attempts, brute force attack logged

## Performance

- **Memory Usage**: ~20-50 MB
- **CPU Usage**: <5% (idle), <20% (under load)
- **Max Connections**: 100 concurrent sessions
- **Session Timeout**: 300 seconds (5 minutes)

## Security Considerations

### Honeypot Isolation

- Runs as non-root user (UID 1000)
- Minimal Linux capabilities (NET_BIND_SERVICE only)
- No outbound network access (Docker network isolation)
- Read-only configuration mount

### No Real Video Streaming

**Important**: This honeypot does NOT provide actual video streams:
- Only protocol-level emulation
- SDP describes non-existent H.264 stream
- PLAY command returns success but no RTP packets sent
- Sufficient for attack detection and threat intelligence

**Rationale**:
- Reduces resource consumption (CPU, memory, bandwidth)
- Simplifies implementation
- Attack detection occurs at protocol level (DESCRIBE, not streaming)
- Real attackers expect authentication failures, not working streams

## Troubleshooting

### Honeypot not binding to port 554

```bash
# Check if port is already in use
sudo netstat -tulpn | grep :554

# Check container logs
docker logs honeynet-rtsp
```

### No logs being generated

```bash
# Check log file permissions
ls -la /home/user/HoneyNetV2/logs/rtsp/

# Verify log directory is mounted
docker inspect honeynet-rtsp | grep Mounts -A 10
```

### Suricata not detecting attacks

```bash
# Verify Suricata is monitoring honeypot network
docker logs honeynet-suricata | grep 554

# Check if rule is loaded
docker exec honeynet-suricata suricata-update list-enabled-rules | grep 2000015
```

## References

- **CVE-2014-8361**: RTSP DESCRIBE buffer overflow in multiple IP camera vendors
- **RFC 2326**: Real Time Streaming Protocol (RTSP)
- **RFC 4566**: Session Description Protocol (SDP)
- **MITRE ATT&CK**: T1190 - Exploit Public-Facing Application
- **Suricata Rule**: SID 2000015 - IoT RTSP exploit detection

## Future Enhancements

- [ ] Add support for RTSP/2.0
- [ ] Implement RTP packet generation (fake stream)
- [ ] Add more camera vendor fingerprints
- [ ] Support ONVIF protocol emulation
- [ ] Credential harvesting with common defaults
- [ ] Integration with VirusTotal for payload analysis
