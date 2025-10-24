#!/usr/bin/env python3
"""
UPnP Honeypot - Router/IoT Gateway Emulation
Simulates vulnerable UPnP service for detecting abuse and reconnaissance
Ports: 1900/UDP (SSDP), 5000/TCP (SOAP/HTTP)
"""

import socket
import threading
import json
import logging
import sys
import struct
from datetime import datetime
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
import hashlib
import uuid
import re

# Configuration
SSDP_PORT = 1900
SSDP_MCAST_ADDR = "239.255.255.250"
HTTP_PORT = 5000
BIND_ADDRESS = "0.0.0.0"
LOG_FILE = "/var/log/upnp/upnp.json"
MAX_CONNECTIONS = 100
BUFFER_SIZE = 8192

# Get container IP for responses (fallback to hostname resolution)
try:
    import os
    CONTAINER_IP = os.environ.get('CONTAINER_IP', socket.gethostbyname(socket.gethostname()))
except:
    CONTAINER_IP = "172.20.0.14"  # Fallback to expected IP

# Simulated device information (realistic IoT Router)
DEVICE_INFO = {
    "device_type": "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "friendly_name": "Generic Smart Router IGD-1000",
    "manufacturer": "Generic IoT Corp",
    "manufacturer_url": "http://www.generic-iot.com",
    "model_description": "Internet Gateway Device with UPnP support",
    "model_name": "Smart Router IGD-1000",
    "model_number": "IGD-1000-v2",
    "model_url": "http://www.generic-iot.com/products/igd-1000",
    "serial_number": "SN-" + str(uuid.uuid4())[:8].upper(),
    "udn": "uuid:" + str(uuid.uuid4()),
    "presentation_url": f"http://{CONTAINER_IP}:{HTTP_PORT}/",
}


class UPnPLogger:
    """Centralized logging for UPnP honeypot"""

    def __init__(self):
        self.setup_logging()

    def setup_logging(self):
        """Configure JSON logging for Logstash integration"""
        log_dir = Path(LOG_FILE).parent
        log_dir.mkdir(parents=True, exist_ok=True)

        # Configure logger
        self.logger = logging.getLogger('upnp_honeypot')
        self.logger.setLevel(logging.INFO)

        # File handler for JSON logs
        handler = logging.FileHandler(LOG_FILE)
        handler.setLevel(logging.INFO)
        self.logger.addHandler(handler)

        # Console handler for debugging
        console = logging.StreamHandler(sys.stdout)
        console.setLevel(logging.INFO)
        console.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(console)

    def log_event(self, event_type, src_ip, src_port, dest_port, protocol, **kwargs):
        """Log event in JSON format for Logstash"""
        event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "honeypot_type": "upnp",
            "event_type": event_type,
            "src_ip": src_ip,
            "src_port": src_port,
            "dest_ip": CONTAINER_IP,
            "dest_port": dest_port,
            "protocol": protocol,
            **kwargs
        }

        self.logger.info(json.dumps(event))


# Global logger instance
upnp_logger = UPnPLogger()


class SSDPServer:
    """SSDP (Simple Service Discovery Protocol) server for UPnP discovery"""

    def __init__(self, port=SSDP_PORT):
        self.port = port
        self.running = False

    def create_ssdp_response(self, search_target):
        """Create SSDP response for M-SEARCH queries"""
        location = f"http://{CONTAINER_IP}:{HTTP_PORT}/description.xml"

        response = (
            "HTTP/1.1 200 OK\r\n"
            f"CACHE-CONTROL: max-age=1800\r\n"
            f"DATE: {datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')}\r\n"
            f"EXT:\r\n"
            f"LOCATION: {location}\r\n"
            f"SERVER: Linux/3.x UPnP/1.0 {DEVICE_INFO['model_name']}\r\n"
            f"ST: {search_target}\r\n"
            f"USN: {DEVICE_INFO['udn']}::{search_target}\r\n"
            "\r\n"
        )

        return response.encode('utf-8')

    def parse_msearch(self, data):
        """Parse M-SEARCH request"""
        try:
            lines = data.decode('utf-8', errors='ignore').split('\r\n')
            headers = {}

            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().upper()] = value.strip()

            return {
                'method': lines[0].split()[0] if lines else '',
                'headers': headers,
                'raw': data
            }
        except Exception as e:
            upnp_logger.logger.error(f"Error parsing M-SEARCH: {e}")
            return None

    def handle_msearch(self, data, addr):
        """Handle M-SEARCH discovery requests"""
        src_ip, src_port = addr

        request = self.parse_msearch(data)
        if not request:
            return None

        # Extract search target
        search_target = request['headers'].get('ST', 'ssdp:all')
        man_header = request['headers'].get('MAN', '')

        # Log the discovery attempt
        upnp_logger.log_event(
            'ssdp_msearch',
            src_ip=src_ip,
            src_port=src_port,
            dest_port=self.port,
            protocol='udp',
            search_target=search_target,
            man_header=man_header,
            mx=request['headers'].get('MX', 'unknown')
        )

        # Respond to relevant search targets
        valid_targets = [
            'ssdp:all',
            'upnp:rootdevice',
            'urn:schemas-upnp-org:device:InternetGatewayDevice:1',
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            'urn:schemas-upnp-org:service:WANPPPConnection:1',
            DEVICE_INFO['udn']
        ]

        # Check if search target matches (case-insensitive)
        should_respond = any(target.lower() in search_target.lower() for target in valid_targets)

        if should_respond:
            return self.create_ssdp_response(search_target), addr

        return None

    def start(self):
        """Start SSDP server (multicast and unicast)"""
        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            # Bind to SSDP port
            sock.bind(('', self.port))

            # Join multicast group
            mreq = struct.pack("4sl", socket.inet_aton(SSDP_MCAST_ADDR), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

            print(f"[*] SSDP server started on UDP/{self.port}")
            print(f"[*] Multicast group: {SSDP_MCAST_ADDR}")

            self.running = True

            while self.running:
                try:
                    data, addr = sock.recvfrom(BUFFER_SIZE)

                    # Check if it's an M-SEARCH request
                    if b'M-SEARCH' in data:
                        print(f"[+] M-SEARCH from {addr[0]}:{addr[1]}")

                        result = self.handle_msearch(data, addr)

                        if result:
                            response, dest_addr = result
                            # Send unicast response
                            sock.sendto(response, dest_addr)

                            upnp_logger.log_event(
                                'ssdp_response_sent',
                                src_ip=CONTAINER_IP,
                                src_port=self.port,
                                dest_port=dest_addr[1],
                                protocol='udp',
                                dest_ip=dest_addr[0]
                            )

                except Exception as e:
                    upnp_logger.logger.error(f"Error in SSDP handler: {e}")
                    continue

        except KeyboardInterrupt:
            print("\n[*] Stopping SSDP server...")
        except Exception as e:
            print(f"[!] SSDP Error: {e}")
        finally:
            sock.close()
            self.running = False


class UPnPHTTPRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for UPnP device description and SOAP requests"""

    def log_message(self, format, *args):
        """Override to use custom logger"""
        pass  # We use our own logging

    def get_device_description_xml(self):
        """Generate UPnP device description XML"""
        xml = f"""<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion>
    <major>1</major>
    <minor>0</minor>
  </specVersion>
  <device>
    <deviceType>{DEVICE_INFO['device_type']}</deviceType>
    <friendlyName>{DEVICE_INFO['friendly_name']}</friendlyName>
    <manufacturer>{DEVICE_INFO['manufacturer']}</manufacturer>
    <manufacturerURL>{DEVICE_INFO['manufacturer_url']}</manufacturerURL>
    <modelDescription>{DEVICE_INFO['model_description']}</modelDescription>
    <modelName>{DEVICE_INFO['model_name']}</modelName>
    <modelNumber>{DEVICE_INFO['model_number']}</modelNumber>
    <modelURL>{DEVICE_INFO['model_url']}</modelURL>
    <serialNumber>{DEVICE_INFO['serial_number']}</serialNumber>
    <UDN>{DEVICE_INFO['udn']}</UDN>
    <presentationURL>{DEVICE_INFO['presentation_url']}</presentationURL>
    <serviceList>
      <service>
        <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
        <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
        <controlURL>/ctl/IPConn</controlURL>
        <eventSubURL>/evt/IPConn</eventSubURL>
        <SCPDURL>/WANIPConnection.xml</SCPDURL>
      </service>
      <service>
        <serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType>
        <serviceId>urn:upnp-org:serviceId:WANPPPConn1</serviceId>
        <controlURL>/ctl/PPPConn</controlURL>
        <eventSubURL>/evt/PPPConn</eventSubURL>
        <SCPDURL>/WANPPPConnection.xml</SCPDURL>
      </service>
    </serviceList>
  </device>
</root>"""
        return xml

    def get_service_description_xml(self, service_type):
        """Generate service description XML (simplified)"""
        xml = f"""<?xml version="1.0"?>
<scpd xmlns="urn:schemas-upnp-org:service-1-0">
  <specVersion>
    <major>1</major>
    <minor>0</minor>
  </specVersion>
  <actionList>
    <action>
      <name>AddPortMapping</name>
      <argumentList>
        <argument>
          <name>NewExternalPort</name>
          <direction>in</direction>
        </argument>
        <argument>
          <name>NewInternalPort</name>
          <direction>in</direction>
        </argument>
        <argument>
          <name>NewInternalClient</name>
          <direction>in</direction>
        </argument>
        <argument>
          <name>NewProtocol</name>
          <direction>in</direction>
        </argument>
      </argumentList>
    </action>
    <action>
      <name>DeletePortMapping</name>
      <argumentList>
        <argument>
          <name>NewExternalPort</name>
          <direction>in</direction>
        </argument>
        <argument>
          <name>NewProtocol</name>
          <direction>in</direction>
        </argument>
      </argumentList>
    </action>
    <action>
      <name>GetExternalIPAddress</name>
      <argumentList>
        <argument>
          <name>NewExternalIPAddress</name>
          <direction>out</direction>
        </argument>
      </argumentList>
    </action>
  </actionList>
</scpd>"""
        return xml

    def parse_soap_request(self, body):
        """Parse SOAP request to extract action and parameters"""
        try:
            # Extract SOAP action
            action_match = re.search(r'<[mu]:[^>]*?(\w+)[^>]*?>', body)
            action = action_match.group(1) if action_match else 'unknown'

            # Extract parameters
            params = {}
            param_matches = re.findall(r'<(New\w+)>([^<]+)</\1>', body)
            for param_name, param_value in param_matches:
                params[param_name] = param_value

            return {
                'action': action,
                'params': params,
                'raw': body
            }
        except Exception as e:
            upnp_logger.logger.error(f"Error parsing SOAP: {e}")
            return {'action': 'unknown', 'params': {}, 'raw': body}

    def create_soap_response(self, action, params=None):
        """Create SOAP response"""
        params = params or {}

        # Default successful response
        if action == 'GetExternalIPAddress':
            params['NewExternalIPAddress'] = CONTAINER_IP

        param_xml = '\n'.join([f'      <{k}>{v}</{k}>' for k, v in params.items()])

        soap = f"""<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:{action}Response xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
{param_xml}
    </u:{action}Response>
  </s:Body>
</s:Envelope>"""
        return soap

    def do_GET(self):
        """Handle GET requests for device/service descriptions"""
        client_ip = self.client_address[0]

        upnp_logger.log_event(
            'http_get',
            src_ip=client_ip,
            src_port=self.client_address[1],
            dest_port=HTTP_PORT,
            protocol='tcp',
            path=self.path,
            user_agent=self.headers.get('User-Agent', 'unknown')
        )

        # Device description
        if self.path == '/description.xml' or self.path == '/rootDesc.xml':
            self.send_response(200)
            self.send_header('Content-Type', 'text/xml; charset="utf-8"')
            self.send_header('Server', f'Linux/3.x UPnP/1.0 {DEVICE_INFO["model_name"]}')
            self.end_headers()

            xml = self.get_device_description_xml()
            self.wfile.write(xml.encode('utf-8'))

            upnp_logger.log_event(
                'device_description_served',
                src_ip=client_ip,
                src_port=self.client_address[1],
                dest_port=HTTP_PORT,
                protocol='tcp',
                path=self.path
            )

        # Service descriptions
        elif self.path in ['/WANIPConnection.xml', '/WANPPPConnection.xml']:
            self.send_response(200)
            self.send_header('Content-Type', 'text/xml; charset="utf-8"')
            self.end_headers()

            xml = self.get_service_description_xml(self.path)
            self.wfile.write(xml.encode('utf-8'))

        # Presentation URL (web interface simulation)
        elif self.path == '/' or self.path == '/index.html':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()

            html = f"""<!DOCTYPE html>
<html>
<head><title>{DEVICE_INFO['friendly_name']}</title></head>
<body>
<h1>{DEVICE_INFO['friendly_name']}</h1>
<p>Manufacturer: {DEVICE_INFO['manufacturer']}</p>
<p>Model: {DEVICE_INFO['model_name']} ({DEVICE_INFO['model_number']})</p>
<p>Serial: {DEVICE_INFO['serial_number']}</p>
<p>Firmware: v2.4.0-beta</p>
</body>
</html>"""
            self.wfile.write(html.encode('utf-8'))

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        """Handle POST requests (SOAP control actions)"""
        client_ip = self.client_address[0]

        # Read request body
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8', errors='ignore')

        # Parse SOAP action
        soap_action = self.headers.get('SOAPAction', 'unknown').strip('"')
        parsed_soap = self.parse_soap_request(body)

        # Detect attack patterns
        attack_detected = False
        attack_type = None

        if 'AddPortMapping' in soap_action or 'AddPortMapping' in body:
            attack_detected = True
            attack_type = 'AddPortMapping abuse'

        if 'DeletePortMapping' in soap_action or 'DeletePortMapping' in body:
            attack_detected = True
            attack_type = 'DeletePortMapping abuse'

        # Log the SOAP request
        upnp_logger.log_event(
            'soap_request',
            src_ip=client_ip,
            src_port=self.client_address[1],
            dest_port=HTTP_PORT,
            protocol='tcp',
            path=self.path,
            soap_action=soap_action,
            action=parsed_soap['action'],
            params=parsed_soap['params'],
            body_preview=body[:500],
            attack_detected=attack_detected,
            attack_type=attack_type,
            user_agent=self.headers.get('User-Agent', 'unknown')
        )

        # Send successful SOAP response (honeypot behavior)
        self.send_response(200)
        self.send_header('Content-Type', 'text/xml; charset="utf-8"')
        self.send_header('Server', f'Linux/3.x UPnP/1.0 {DEVICE_INFO["model_name"]}')
        self.end_headers()

        response = self.create_soap_response(parsed_soap['action'])
        self.wfile.write(response.encode('utf-8'))

        if attack_detected:
            upnp_logger.log_event(
                'attack_detected',
                src_ip=client_ip,
                src_port=self.client_address[1],
                dest_port=HTTP_PORT,
                protocol='tcp',
                attack_type=attack_type,
                details=parsed_soap['params']
            )


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Threaded HTTP server for handling multiple connections"""
    daemon_threads = True
    allow_reuse_address = True


def start_http_server():
    """Start HTTP/SOAP server"""
    server = ThreadedHTTPServer((BIND_ADDRESS, HTTP_PORT), UPnPHTTPRequestHandler)
    print(f"[*] HTTP/SOAP server started on TCP/{HTTP_PORT}")
    print(f"[*] Device description: http://{CONTAINER_IP}:{HTTP_PORT}/description.xml")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping HTTP server...")
    finally:
        server.shutdown()


def main():
    """Main entry point"""
    print("=" * 70)
    print("UPnP Honeypot - Router/IoT Gateway Emulation")
    print("=" * 70)
    print(f"[*] Device Type: {DEVICE_INFO['device_type']}")
    print(f"[*] Model: {DEVICE_INFO['manufacturer']} {DEVICE_INFO['model_name']}")
    print(f"[*] Serial: {DEVICE_INFO['serial_number']}")
    print(f"[*] UDN: {DEVICE_INFO['udn']}")
    print(f"[*] Container IP: {CONTAINER_IP}")
    print(f"[*] Logging to: {LOG_FILE}")
    print("=" * 70)

    # Start SSDP server in separate thread
    ssdp_server = SSDPServer()
    ssdp_thread = threading.Thread(target=ssdp_server.start, daemon=True)
    ssdp_thread.start()

    # Start HTTP server in main thread
    start_http_server()


if __name__ == "__main__":
    main()
