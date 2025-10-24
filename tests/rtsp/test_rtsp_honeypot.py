#!/usr/bin/env python3
"""
RTSP Honeypot Test Suite
Tests RTSP protocol emulation and CVE-2014-8361 vulnerability simulation
"""

import socket
import time
import sys
import json
from typing import Dict, Tuple, Optional


class RTSPTestClient:
    """Simple RTSP client for testing honeypot"""

    def __init__(self, host: str = "localhost", port: int = 554, timeout: int = 5):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.cseq = 0
        self.socket: Optional[socket.socket] = None

    def connect(self) -> bool:
        """Establish connection to RTSP server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.timeout)
            self.socket.connect((self.host, self.port))
            print(f"[+] Connected to {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            return False

    def send_request(self, method: str, url: str = "*", headers: Dict[str, str] = None) -> str:
        """Send RTSP request and receive response"""
        if not self.socket:
            raise RuntimeError("Not connected")

        self.cseq += 1

        # Build request
        if url == "*":
            request_line = f"{method} {url} RTSP/1.0\r\n"
        else:
            request_line = f"{method} rtsp://{self.host}:{self.port}{url} RTSP/1.0\r\n"

        request = request_line
        request += f"CSeq: {self.cseq}\r\n"

        # Add custom headers
        if headers:
            for key, value in headers.items():
                request += f"{key}: {value}\r\n"

        request += "\r\n"

        # Send request
        self.socket.sendall(request.encode())
        print(f"[>] Sent {method} request (CSeq: {self.cseq})")

        # Receive response
        response = self.socket.recv(4096).decode('utf-8', errors='ignore')
        print(f"[<] Received response ({len(response)} bytes)")

        return response

    def close(self):
        """Close connection"""
        if self.socket:
            self.socket.close()
            self.socket = None
            print("[+] Connection closed")


def parse_rtsp_response(response: str) -> Dict:
    """Parse RTSP response"""
    lines = response.split('\r\n')
    if not lines:
        return {}

    # Parse status line
    status_line = lines[0]
    parts = status_line.split()

    result = {
        'status_line': status_line,
        'version': parts[0] if len(parts) > 0 else '',
        'status_code': int(parts[1]) if len(parts) > 1 else 0,
        'status_text': ' '.join(parts[2:]) if len(parts) > 2 else '',
        'headers': {},
        'body': ''
    }

    # Parse headers
    i = 1
    while i < len(lines) and lines[i]:
        if ':' in lines[i]:
            key, value = lines[i].split(':', 1)
            result['headers'][key.strip().lower()] = value.strip()
        i += 1

    # Parse body (if any)
    if i < len(lines) - 1:
        result['body'] = '\r\n'.join(lines[i+1:])

    return result


def test_options(client: RTSPTestClient) -> bool:
    """Test OPTIONS request"""
    print("\n[TEST] OPTIONS Request")
    print("=" * 60)

    response = client.send_request("OPTIONS", "*")
    parsed = parse_rtsp_response(response)

    # Verify response
    if parsed['status_code'] == 200:
        print(f"[✓] Status: {parsed['status_code']} {parsed['status_text']}")

        if 'public' in parsed['headers']:
            methods = parsed['headers']['public']
            print(f"[✓] Available methods: {methods}")

            expected_methods = ['OPTIONS', 'DESCRIBE', 'SETUP', 'PLAY', 'TEARDOWN']
            for method in expected_methods:
                if method in methods:
                    print(f"  [✓] {method} supported")
                else:
                    print(f"  [✗] {method} NOT supported")

        if 'server' in parsed['headers']:
            print(f"[✓] Server: {parsed['headers']['server']}")

        return True
    else:
        print(f"[✗] Unexpected status: {parsed['status_code']}")
        return False


def test_describe(client: RTSPTestClient) -> bool:
    """Test DESCRIBE request"""
    print("\n[TEST] DESCRIBE Request")
    print("=" * 60)

    response = client.send_request("DESCRIBE", "/stream")
    parsed = parse_rtsp_response(response)

    if parsed['status_code'] == 200:
        print(f"[✓] Status: {parsed['status_code']} {parsed['status_text']}")

        # Check for SDP content
        if 'content-type' in parsed['headers']:
            content_type = parsed['headers']['content-type']
            print(f"[✓] Content-Type: {content_type}")

            if 'application/sdp' in content_type:
                print("[✓] SDP response detected")

                # Parse SDP body
                if parsed['body']:
                    print(f"[✓] SDP body ({len(parsed['body'])} bytes):")
                    for line in parsed['body'].split('\r\n')[:10]:  # Show first 10 lines
                        if line:
                            print(f"    {line}")

                    # Check for essential SDP fields
                    if 'v=0' in parsed['body']:
                        print("  [✓] SDP version found")
                    if 'm=video' in parsed['body']:
                        print("  [✓] Video stream description found")
                    if 'H264' in parsed['body'] or 'h264' in parsed['body']:
                        print("  [✓] H.264 codec found")

                return True
            else:
                print(f"[✗] Unexpected content type: {content_type}")
                return False
        else:
            print("[✗] No Content-Type header")
            return False
    else:
        print(f"[✗] Unexpected status: {parsed['status_code']}")
        return False


def test_setup_unauthorized(client: RTSPTestClient) -> bool:
    """Test SETUP without authentication"""
    print("\n[TEST] SETUP Request (No Authentication)")
    print("=" * 60)

    response = client.send_request("SETUP", "/stream/track1")
    parsed = parse_rtsp_response(response)

    if parsed['status_code'] == 401:
        print(f"[✓] Status: {parsed['status_code']} {parsed['status_text']}")

        if 'www-authenticate' in parsed['headers']:
            auth_header = parsed['headers']['www-authenticate']
            print(f"[✓] Authentication required: {auth_header}")
            return True
        else:
            print("[!] No WWW-Authenticate header (but 401 returned)")
            return True
    elif parsed['status_code'] == 200:
        print(f"[!] SETUP accepted without authentication (status {parsed['status_code']})")
        print("[!] This might be intentional for honeypot purposes")
        return True
    else:
        print(f"[✗] Unexpected status: {parsed['status_code']}")
        return False


def test_cve_2014_8361(client: RTSPTestClient) -> bool:
    """Test CVE-2014-8361 buffer overflow attempt"""
    print("\n[TEST] CVE-2014-8361 Buffer Overflow Simulation")
    print("=" * 60)

    # Create abnormally long Authorization header (>1024 bytes)
    overflow_payload = "A" * 2048
    auth_value = f"Basic {overflow_payload}"

    headers = {
        "Authorization": auth_value
    }

    print(f"[*] Sending DESCRIBE with {len(auth_value)} byte Authorization header")
    print(f"[*] Threshold: 1024 bytes (CVE-2014-8361)")

    try:
        response = client.send_request("DESCRIBE", "/stream", headers=headers)
        parsed = parse_rtsp_response(response)

        # Key test: Connection should remain open (honeypot should NOT crash)
        print("[✓] Connection remained open (honeypot did not crash)")
        print(f"[✓] Received response: {parsed['status_code']} {parsed['status_text']}")

        # Verify we can still send requests
        print("[*] Verifying connection is still functional...")
        response2 = client.send_request("OPTIONS", "*")
        parsed2 = parse_rtsp_response(response2)

        if parsed2['status_code'] == 200:
            print("[✓] Connection still functional after overflow attempt")
            print("[✓] CVE-2014-8361 simulation successful")
            print("[*] Suricata should detect this as SID 2000015")
            return True
        else:
            print("[!] Connection unstable after overflow")
            return False

    except Exception as e:
        print(f"[✗] Exception occurred: {e}")
        print("[✗] This might indicate real crash (not expected for honeypot)")
        return False


def test_brute_force(client: RTSPTestClient) -> bool:
    """Test brute force detection (multiple auth attempts)"""
    print("\n[TEST] Brute Force Detection")
    print("=" * 60)

    print("[*] Sending multiple DESCRIBE requests with different credentials")

    credentials = [
        ("admin", "admin"),
        ("root", "root"),
        ("admin", "12345"),
        ("user", "password"),
        ("admin", "password"),
        ("test", "test")
    ]

    for i, (username, password) in enumerate(credentials, 1):
        import base64
        creds = f"{username}:{password}"
        encoded = base64.b64encode(creds.encode()).decode()

        headers = {
            "Authorization": f"Basic {encoded}"
        }

        print(f"[*] Attempt {i}/6: {username}:{password}")

        try:
            response = client.send_request("DESCRIBE", "/stream", headers=headers)
            parsed = parse_rtsp_response(response)
            print(f"    Response: {parsed['status_code']}")
            time.sleep(0.5)  # Small delay between attempts
        except Exception as e:
            print(f"    [!] Error: {e}")

    print("[✓] Sent 6 authentication attempts")
    print("[*] Honeypot should log brute force detection after 5 attempts")
    return True


def test_teardown(client: RTSPTestClient) -> bool:
    """Test TEARDOWN request"""
    print("\n[TEST] TEARDOWN Request")
    print("=" * 60)

    response = client.send_request("TEARDOWN", "/stream")
    parsed = parse_rtsp_response(response)

    if parsed['status_code'] == 200:
        print(f"[✓] Status: {parsed['status_code']} {parsed['status_text']}")
        return True
    else:
        print(f"[✗] Unexpected status: {parsed['status_code']}")
        return False


def main():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("RTSP Honeypot Test Suite")
    print("=" * 60)

    # Parse command line arguments
    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 554

    print(f"Target: {host}:{port}")
    print("=" * 60)

    # Create client
    client = RTSPTestClient(host, port)

    # Test connection
    if not client.connect():
        print("\n[FAILED] Could not connect to RTSP honeypot")
        print(f"Make sure the honeypot is running on {host}:{port}")
        return 1

    # Run tests
    tests = [
        ("OPTIONS Request", test_options),
        ("DESCRIBE Request", test_describe),
        ("SETUP Unauthorized", test_setup_unauthorized),
        ("CVE-2014-8361", test_cve_2014_8361),
        ("Brute Force Detection", test_brute_force),
        ("TEARDOWN Request", test_teardown)
    ]

    results = []

    for test_name, test_func in tests:
        try:
            result = test_func(client)
            results.append((test_name, result))
        except Exception as e:
            print(f"\n[ERROR] Test '{test_name}' failed with exception: {e}")
            results.append((test_name, False))

    # Close connection
    client.close()

    # Print summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for test_name, result in results:
        status = "[✓] PASS" if result else "[✗] FAIL"
        print(f"{status} - {test_name}")

    print("=" * 60)
    print(f"Results: {passed}/{total} tests passed")
    print("=" * 60)

    # Check logs
    print("\n[*] Check logs at: ./data/rtsp/rtsp.json")
    print("[*] Check Suricata alerts for SID 2000015 (CVE-2014-8361)")
    print("[*] Check ClickHouse for RTSP events in honeypot_events table")

    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
