#!/usr/bin/env python3
"""
RTSP Honeypot - IoT Camera/DVR Emulation
Simulates vulnerable RTSP service with CVE-2014-8361 buffer overflow detection
Port: 554/TCP (Real Time Streaming Protocol)
"""

import socket
import threading
import json
import logging
import sys
import re
from datetime import datetime
from pathlib import Path
import hashlib
import os

# Configuration
RTSP_PORT = 554
BIND_ADDRESS = "0.0.0.0"
LOG_FILE = "/var/log/rtsp/rtsp.json"
MAX_CONNECTIONS = 100
BUFFER_SIZE = 8192
SESSION_TIMEOUT = 300  # 5 minutes

# Simulated device information
DEVICE_INFO = {
    "server": "RTSP/1.0 DVR-Camera-NVR",
    "manufacturer": "Generic IoT Device",
    "model": "IP-Camera-001",
    "firmware": "v2.4.0-beta"
}


class RTSPSession:
    """Represents an RTSP session with a client"""

    def __init__(self, session_id, client_ip, client_port):
        self.session_id = session_id
        self.client_ip = client_ip
        self.client_port = client_port
        self.created_at = datetime.utcnow()
        self.cseq = 0
        self.authenticated = False
        self.username = None
        self.requests = []
        self.attack_detected = False
        self.attack_type = None


class RTSPHoneypot:
    """RTSP Honeypot server with CVE-2014-8361 vulnerability simulation"""

    def __init__(self, port=RTSP_PORT, bind_address=BIND_ADDRESS):
        self.port = port
        self.bind_address = bind_address
        self.sessions = {}
        self.session_counter = 0
        self.setup_logging()

    def setup_logging(self):
        """Configure JSON logging for Logstash integration"""
        log_dir = Path(LOG_FILE).parent
        log_dir.mkdir(parents=True, exist_ok=True)

        # Configure logger
        self.logger = logging.getLogger('rtsp_honeypot')
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

    def log_event(self, event_type, session, **kwargs):
        """Log event in JSON format for Logstash"""
        event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "honeypot_type": "rtsp",
            "event_type": event_type,
            "session_id": session.session_id,
            "src_ip": session.client_ip,
            "src_port": session.client_port,
            "dest_ip": self.bind_address,
            "dest_port": self.port,
            "protocol": "rtsp",
            **kwargs
        }

        # Add attack-specific fields
        if session.attack_detected:
            event["attack_detected"] = True
            event["attack_type"] = session.attack_type

        self.logger.info(json.dumps(event))

    def generate_session_id(self, client_ip, client_port):
        """Generate unique session ID"""
        self.session_counter += 1
        timestamp = datetime.utcnow().timestamp()
        data = f"{client_ip}:{client_port}:{timestamp}:{self.session_counter}"
        return hashlib.md5(data.encode()).hexdigest()[:16]

    def parse_rtsp_request(self, data):
        """Parse RTSP request"""
        try:
            lines = data.decode('utf-8', errors='ignore').split('\r\n')
            if not lines:
                return None

            # Parse request line (e.g., "OPTIONS rtsp://192.168.1.100:554 RTSP/1.0")
            request_line = lines[0].strip()
            parts = request_line.split()

            if len(parts) < 3:
                return None

            method = parts[0].upper()
            url = parts[1] if len(parts) > 1 else ""
            version = parts[2] if len(parts) > 2 else "RTSP/1.0"

            # Parse headers
            headers = {}
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()

            return {
                'method': method,
                'url': url,
                'version': version,
                'headers': headers,
                'raw': data
            }
        except Exception as e:
            self.logger.error(f"Error parsing RTSP request: {e}")
            return None

    def check_for_attacks(self, request, session):
        """Check for known attack patterns (CVE-2014-8361)"""
        attacks_detected = []

        # CVE-2014-8361: Buffer overflow in Authorization header
        if 'authorization' in request['headers']:
            auth_header = request['headers']['authorization']

            # Check for abnormally long Authorization header (>1024 bytes)
            if len(auth_header) > 1024:
                attacks_detected.append({
                    'type': 'buffer_overflow',
                    'cve': 'CVE-2014-8361',
                    'description': 'RTSP buffer overflow attempt via long Authorization header',
                    'header_length': len(auth_header),
                    'threshold': 1024
                })
                session.attack_detected = True
                session.attack_type = 'CVE-2014-8361 buffer overflow'

        # Check for brute force attempts
        if 'authorization' in request['headers']:
            session.requests.append({
                'timestamp': datetime.utcnow().isoformat(),
                'method': request['method'],
                'authorization': request['headers']['authorization'][:100]  # Log first 100 chars
            })

            # Detect multiple auth attempts
            recent_auth_attempts = [r for r in session.requests
                                   if (datetime.utcnow() - datetime.fromisoformat(r['timestamp'].replace('Z', ''))).seconds < 60]

            if len(recent_auth_attempts) > 5:
                attacks_detected.append({
                    'type': 'brute_force',
                    'description': 'Multiple authentication attempts detected',
                    'attempts': len(recent_auth_attempts)
                })

        # Check for abnormally long URI (potential overflow)
        if len(request['url']) > 2048:
            attacks_detected.append({
                'type': 'uri_overflow',
                'description': 'Abnormally long RTSP URI',
                'uri_length': len(request['url'])
            })

        return attacks_detected

    def handle_options(self, request, session):
        """Handle OPTIONS request - returns available methods"""
        cseq = request['headers'].get('cseq', '1')

        response = (
            f"RTSP/1.0 200 OK\r\n"
            f"CSeq: {cseq}\r\n"
            f"Server: {DEVICE_INFO['server']}\r\n"
            f"Public: OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN\r\n"
            f"\r\n"
        )

        self.log_event('options', session,
                      method='OPTIONS',
                      response_code=200)

        return response.encode()

    def handle_describe(self, request, session):
        """Handle DESCRIBE request - returns SDP session description"""
        cseq = request['headers'].get('cseq', '1')

        # Generate minimal SDP (Session Description Protocol) response
        # This simulates a camera with H.264 video stream
        sdp_body = (
            "v=0\r\n"
            f"o=- {session.session_id} 1 IN IP4 {self.bind_address}\r\n"
            "s=IP Camera Stream\r\n"
            f"c=IN IP4 {self.bind_address}\r\n"
            "t=0 0\r\n"
            "a=control:*\r\n"
            "a=range:npt=0-\r\n"
            "m=video 0 RTP/AVP 96\r\n"
            "a=rtpmap:96 H264/90000\r\n"
            "a=fmtp:96 packetization-mode=1;profile-level-id=42801F\r\n"
            "a=control:track1\r\n"
        )

        response = (
            f"RTSP/1.0 200 OK\r\n"
            f"CSeq: {cseq}\r\n"
            f"Server: {DEVICE_INFO['server']}\r\n"
            f"Content-Type: application/sdp\r\n"
            f"Content-Length: {len(sdp_body)}\r\n"
            f"\r\n"
            f"{sdp_body}"
        )

        self.log_event('describe', session,
                      method='DESCRIBE',
                      response_code=200,
                      url=request['url'],
                      sdp_provided=True)

        return response.encode()

    def handle_setup(self, request, session):
        """Handle SETUP request - typically requires authentication"""
        cseq = request['headers'].get('cseq', '1')

        # Check for authentication
        if 'authorization' not in request['headers']:
            response = (
                f"RTSP/1.0 401 Unauthorized\r\n"
                f"CSeq: {cseq}\r\n"
                f"Server: {DEVICE_INFO['server']}\r\n"
                f'WWW-Authenticate: Basic realm="IP Camera"\r\n'
                f"\r\n"
            )

            self.log_event('setup_unauthorized', session,
                          method='SETUP',
                          response_code=401,
                          url=request['url'])

            return response.encode()

        # Simulate successful setup (even with invalid credentials for honeypot purposes)
        response = (
            f"RTSP/1.0 200 OK\r\n"
            f"CSeq: {cseq}\r\n"
            f"Server: {DEVICE_INFO['server']}\r\n"
            f"Session: {session.session_id};timeout={SESSION_TIMEOUT}\r\n"
            f"Transport: RTP/AVP;unicast;client_port=8000-8001;server_port=9000-9001\r\n"
            f"\r\n"
        )

        self.log_event('setup', session,
                      method='SETUP',
                      response_code=200,
                      url=request['url'],
                      authenticated=True)

        return response.encode()

    def handle_play(self, request, session):
        """Handle PLAY request"""
        cseq = request['headers'].get('cseq', '1')

        response = (
            f"RTSP/1.0 200 OK\r\n"
            f"CSeq: {cseq}\r\n"
            f"Server: {DEVICE_INFO['server']}\r\n"
            f"Session: {session.session_id}\r\n"
            f"Range: npt=0.000-\r\n"
            f"RTP-Info: url=track1;seq=1;rtptime=0\r\n"
            f"\r\n"
        )

        self.log_event('play', session,
                      method='PLAY',
                      response_code=200,
                      url=request['url'])

        return response.encode()

    def handle_teardown(self, request, session):
        """Handle TEARDOWN request"""
        cseq = request['headers'].get('cseq', '1')

        response = (
            f"RTSP/1.0 200 OK\r\n"
            f"CSeq: {cseq}\r\n"
            f"Server: {DEVICE_INFO['server']}\r\n"
            f"Session: {session.session_id}\r\n"
            f"\r\n"
        )

        self.log_event('teardown', session,
                      method='TEARDOWN',
                      response_code=200)

        return response.encode()

    def handle_unknown(self, request, session):
        """Handle unknown/unsupported methods"""
        cseq = request['headers'].get('cseq', '1')

        response = (
            f"RTSP/1.0 501 Not Implemented\r\n"
            f"CSeq: {cseq}\r\n"
            f"Server: {DEVICE_INFO['server']}\r\n"
            f"\r\n"
        )

        self.log_event('unknown_method', session,
                      method=request['method'],
                      response_code=501)

        return response.encode()

    def handle_client(self, client_socket, client_address):
        """Handle individual client connection"""
        client_ip, client_port = client_address
        session_id = self.generate_session_id(client_ip, client_port)
        session = RTSPSession(session_id, client_ip, client_port)
        self.sessions[session_id] = session

        self.log_event('session_start', session)

        try:
            while True:
                # Receive data with larger buffer to capture overflow attempts
                data = client_socket.recv(BUFFER_SIZE)

                if not data:
                    break

                # Parse RTSP request
                request = self.parse_rtsp_request(data)

                if not request:
                    continue

                # Check for attack patterns
                attacks = self.check_for_attacks(request, session)

                if attacks:
                    for attack in attacks:
                        self.log_event('attack_detected', session,
                                     method=request['method'],
                                     attack_info=attack)

                    # CVE-2014-8361 simulation: DO NOT close connection on buffer overflow
                    # This allows IDS (Suricata) to detect the attack
                    # Real vulnerable devices would crash or misbehave but stay connected

                # Route request to appropriate handler
                method_handlers = {
                    'OPTIONS': self.handle_options,
                    'DESCRIBE': self.handle_describe,
                    'SETUP': self.handle_setup,
                    'PLAY': self.handle_play,
                    'PAUSE': self.handle_play,  # Same as PLAY for simplicity
                    'TEARDOWN': self.handle_teardown
                }

                handler = method_handlers.get(request['method'], self.handle_unknown)
                response = handler(request, session)

                # Send response
                client_socket.sendall(response)

                # Close connection after TEARDOWN
                if request['method'] == 'TEARDOWN':
                    break

        except Exception as e:
            self.logger.error(f"Error handling client {client_ip}:{client_port}: {e}")
            self.log_event('error', session, error=str(e))
        finally:
            client_socket.close()
            self.log_event('session_end', session,
                          duration=(datetime.utcnow() - session.created_at).total_seconds(),
                          requests_count=len(session.requests))

            # Clean up session
            if session_id in self.sessions:
                del self.sessions[session_id]

    def start(self):
        """Start the RTSP honeypot server"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server_socket.bind((self.bind_address, self.port))
            server_socket.listen(MAX_CONNECTIONS)

            print(f"[*] RTSP Honeypot started on {self.bind_address}:{self.port}")
            print(f"[*] Device: {DEVICE_INFO['manufacturer']} {DEVICE_INFO['model']}")
            print(f"[*] Firmware: {DEVICE_INFO['firmware']}")
            print(f"[*] Logging to: {LOG_FILE}")
            print(f"[*] Simulating CVE-2014-8361 vulnerability")
            print(f"[*] Waiting for connections...")

            while True:
                client_socket, client_address = server_socket.accept()
                print(f"[+] Connection from {client_address[0]}:{client_address[1]}")

                # Handle client in separate thread
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address),
                    daemon=True
                )
                client_thread.start()

        except KeyboardInterrupt:
            print("\n[*] Shutting down RTSP honeypot...")
        except Exception as e:
            print(f"[!] Error: {e}")
        finally:
            server_socket.close()


def main():
    """Main entry point"""
    honeypot = RTSPHoneypot()
    honeypot.start()


if __name__ == "__main__":
    main()
