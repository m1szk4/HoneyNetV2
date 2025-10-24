# AgentUPnP - UPnP Honeypot

## Overview

AgentUPnP is a honeypot that simulates a vulnerable Universal Plug and Play (UPnP) service commonly found in routers and IoT devices. It implements both SSDP (Simple Service Discovery Protocol) for device discovery and SOAP/HTTP for control operations, specifically targeting abuse scenarios like unauthorized port forwarding.

## Architecture

### Components

1. **SSDP Server (UDP/1900)**
   - Listens for M-SEARCH multicast discovery requests
   - Responds with device information (InternetGatewayDevice)
   - Provides location URL for device description XML

2. **HTTP/SOAP Server (TCP/5000)**
   - Serves UPnP device description XML
   - Serves service description XML (WANIPConnection, WANPPPConnection)
   - Accepts and logs SOAP control requests
   - Simulates successful responses to port mapping attempts

### Simulated Device

**Device Type**: `InternetGatewayDevice:1` (IGD)

**Device Profile**:
- **Manufacturer**: Generic IoT Corp
- **Model**: Smart Router IGD-1000
- **Model Number**: IGD-1000-v2
- **Device Type**: urn:schemas-upnp-org:device:InternetGatewayDevice:1

**Services**:
- `WANIPConnection:1` - WAN IP connection service (port mapping)
- `WANPPPConnection:1` - WAN PPP connection service

**SOAP Actions Supported**:
- `AddPortMapping` - Adds port forwarding rules (logged as attack)
- `DeletePortMapping` - Removes port forwarding rules (logged as attack)
- `GetExternalIPAddress` - Returns external IP address

## Attack Scenarios

### 1. UPnP Device Discovery (MITRE T1046 - Network Service Discovery)

**Attack Vector**: Attackers scan for UPnP devices using SSDP M-SEARCH queries
```
M-SEARCH * HTTP/1.1
HOST: 239.255.255.250:1900
MAN: "ssdp:discover"
MX: 3
ST: ssdp:all
```

**Honeypot Response**: Returns device information with location URL

**Suricata Detection**: SID 2000016 (threshold: 20 M-SEARCH/60s from same source)

### 2. UPnP Port Mapping Abuse (MITRE T1557 - Adversary-in-the-Middle)

**Attack Vector**: Attackers send SOAP requests to manipulate router port forwarding
```xml
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewExternalPort>8080</NewExternalPort>
      <NewInternalPort>80</NewInternalPort>
      <NewInternalClient>192.168.1.100</NewInternalClient>
      <NewProtocol>TCP</NewProtocol>
    </u:AddPortMapping>
  </s:Body>
</s:Envelope>
```

**Honeypot Response**: Returns successful SOAP response (without actually creating port mapping)

**Suricata Detection**: SID 2000017 (detects "AddPortMapping" and "NewExternalPort" in traffic)

## Log Format

All events are logged in JSON format to `/var/log/upnp/upnp.json` for Logstash ingestion:

```json
{
  "timestamp": "2025-10-24T12:00:00.000000Z",
  "honeypot_type": "upnp",
  "event_type": "soap_request",
  "src_ip": "192.168.1.100",
  "src_port": 54321,
  "dest_ip": "172.20.0.14",
  "dest_port": 5000,
  "protocol": "tcp",
  "soap_action": "AddPortMapping",
  "action": "AddPortMapping",
  "params": {
    "NewExternalPort": "8080",
    "NewInternalPort": "80",
    "NewInternalClient": "192.168.1.100",
    "NewProtocol": "TCP"
  },
  "attack_detected": true,
  "attack_type": "AddPortMapping abuse"
}
```

## Testing

### 1. Test SSDP Discovery with nmap

```bash
# Scan for UPnP devices
nmap -sU -p 1900 --script=upnp-info <honeypot-ip>

# Expected output: Device information with model, manufacturer, services
```

### 2. Test SSDP Discovery with msearch

```bash
# Send M-SEARCH multicast
echo -ne "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 3\r\nST: ssdp:all\r\n\r\n" | \
  socat - UDP-DATAGRAM:239.255.255.250:1900,broadcast

# Expected: SSDP response with device location
```

### 3. Test Device Description

```bash
# Fetch device description XML
curl http://<honeypot-ip>:5000/description.xml

# Expected: XML with device info and service list
```

### 4. Test SOAP Port Mapping

```bash
# Send AddPortMapping SOAP request
curl -X POST http://<honeypot-ip>:5000/ctl/IPConn \
  -H "Content-Type: text/xml; charset=utf-8" \
  -H "SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"" \
  -d '<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewExternalPort>8080</NewExternalPort>
      <NewInternalPort>80</NewInternalPort>
      <NewInternalClient>192.168.1.100</NewInternalClient>
      <NewProtocol>TCP</NewProtocol>
    </u:AddPortMapping>
  </s:Body>
</s:Envelope>'

# Expected: Successful SOAP response + logged attack
```

### 5. Verify Suricata Detection

```bash
# Check Suricata alerts
tail -f /var/log/suricata/fast.log | grep -E "(2000016|2000017)"

# Expected alerts:
# - SID 2000016: UPnP SSDP scan - M-SEARCH discovery (after 20 requests)
# - SID 2000017: UPnP AddPortMapping abuse attempt
```

### 6. Verify UPnP Logs

```bash
# Check honeypot logs
tail -f data/upnp/upnp.json | jq .

# Expected events:
# - ssdp_msearch
# - ssdp_response_sent
# - http_get (device description)
# - soap_request (port mapping)
# - attack_detected
```

## Integration with HoneyNetV2

### Docker Compose

The UPnP honeypot is integrated into the docker-compose stack:

```yaml
upnp:
  build: ./honeypots/upnp
  image: honeynet/upnp:latest
  container_name: honeynet-upnp
  restart: unless-stopped
  networks:
    honeypot_net:
      ipv4_address: 172.20.0.14
  ports:
    - "1900:1900/udp"  # SSDP
    - "5000:5000"      # HTTP/SOAP
  environment:
    - CONTAINER_IP=172.20.0.14
```

### Logstash Pipeline

UPnP logs are processed through Logstash and stored in ClickHouse:

```ruby
input {
  file {
    path => "/input/upnp/upnp.json"
    codec => "json"
    type => "upnp"
  }
}

filter {
  # Timestamp parsing, anonymization, enrichment
}

output {
  http {
    url => "http://clickhouse:8123/"
    # Insert into upnp_events table
  }
}
```

## Security Considerations

1. **Isolation**: Runs in DMZ network (172.20.0.0/24) with no outbound access
2. **Non-root**: Runs as unprivileged user (uid 1000)
3. **Resource Limits**: Limited to 256MB RAM, 0.25 CPU
4. **Capabilities**: Only NET_BIND_SERVICE capability for binding to ports <1024

## Common UPnP Attack Tools

Attackers commonly use these tools to exploit UPnP:

- **upnpc** (MiniUPnP client) - CLI tool for port mapping
- **Miranda** - UPnP service interrogation tool
- **Evil SSDP** - SSDP spoofing and MITM tool
- **Nmap scripts** - upnp-info, broadcast-upnp-info
- **Metasploit modules** - upnp_ssdp_amplification, upnp_msearch

## References

- [UPnP Device Architecture v1.0](http://upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v1.0.pdf)
- [UPnP IGD v1.0 Specification](http://upnp.org/specs/gw/UPnP-gw-InternetGatewayDevice-v1-Device.pdf)
- [MITRE ATT&CK T1046 - Network Service Discovery](https://attack.mitre.org/techniques/T1046/)
- [MITRE ATT&CK T1557 - Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)
- [CWE-264: UPnP Control Point Vulnerabilities](https://cwe.mitre.org/data/definitions/264.html)

## Known Limitations

1. **Multicast SSDP**: Requires host network mode or proper multicast routing
2. **Limited SOAP Actions**: Only implements port mapping actions (most common attack vector)
3. **No Real NAT**: Does not actually perform port forwarding (honeypot behavior)
4. **Simplified XML**: Device/service descriptions are minimal but functional

## Future Enhancements

- [ ] Support for more SOAP actions (GetGenericPortMappingEntry, etc.)
- [ ] Emulation of firmware vulnerabilities (buffer overflows, auth bypass)
- [ ] SSDP amplification attack detection
- [ ] UPnP event subscription handling
- [ ] Integration with threat intelligence feeds for known attack patterns
