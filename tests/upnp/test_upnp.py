#!/usr/bin/env python3
"""
UPnP Honeypot Test Suite (Python)
Comprehensive testing for SSDP and SOAP functionality
"""

import socket
import struct
import requests
import time
import sys
from typing import Dict, Tuple, Optional

# Configuration
HONEYPOT_IP = "172.20.0.14"
SSDP_PORT = 1900
HTTP_PORT = 5000
SSDP_MCAST = "239.255.255.250"
TIMEOUT = 5

# Test results
tests_passed = 0
tests_failed = 0


def test_result(success: bool, test_name: str, details: str = ""):
    """Record and print test result"""
    global tests_passed, tests_failed

    if success:
        print(f"[PASS] {test_name}")
        tests_passed += 1
    else:
        print(f"[FAIL] {test_name}")
        tests_failed += 1

    if details:
        print(f"       {details}")


def send_ssdp_msearch(target_ip: str = HONEYPOT_IP, target_port: int = SSDP_PORT) -> Optional[str]:
    """Send SSDP M-SEARCH request and receive response"""
    msearch = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {SSDP_MCAST}:{SSDP_PORT}\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 3\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    )

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(TIMEOUT)
        sock.sendto(msearch.encode(), (target_ip, target_port))

        response, _ = sock.recvfrom(8192)
        sock.close()

        return response.decode('utf-8', errors='ignore')
    except socket.timeout:
        return None
    except Exception as e:
        print(f"       Error: {e}")
        return None


def test_ssdp_discovery():
    """Test 1: SSDP M-SEARCH Discovery"""
    print("\nTest 1: SSDP M-SEARCH Discovery")
    print(f"Sending M-SEARCH to {HONEYPOT_IP}:{SSDP_PORT}...")

    response = send_ssdp_msearch()

    if response and "LOCATION:" in response:
        # Extract location
        for line in response.split('\r\n'):
            if line.startswith('LOCATION:'):
                location = line.split(':', 1)[1].strip()
                test_result(True, "SSDP Discovery", f"Location: {location}")
                return location
        test_result(True, "SSDP Discovery", "Response received but no location")
        return None
    else:
        test_result(False, "SSDP Discovery", "No response or invalid response")
        return None


def test_device_description():
    """Test 2: Device Description XML"""
    print("\nTest 2: Device Description XML")

    try:
        response = requests.get(
            f"http://{HONEYPOT_IP}:{HTTP_PORT}/description.xml",
            timeout=TIMEOUT
        )

        if response.status_code == 200 and "InternetGatewayDevice" in response.text:
            # Extract device info
            friendly_name = ""
            manufacturer = ""
            model_name = ""

            for line in response.text.split('\n'):
                if '<friendlyName>' in line:
                    friendly_name = line.split('>')[1].split('<')[0]
                elif '<manufacturer>' in line:
                    manufacturer = line.split('>')[1].split('<')[0]
                elif '<modelName>' in line:
                    model_name = line.split('>')[1].split('<')[0]

            test_result(
                True,
                "Device Description XML",
                f"{manufacturer} {model_name} ({friendly_name})"
            )
            return True
        else:
            test_result(False, "Device Description XML", f"Status: {response.status_code}")
            return False
    except Exception as e:
        test_result(False, "Device Description XML", f"Error: {e}")
        return False


def test_service_description():
    """Test 3: Service Description XML"""
    print("\nTest 3: Service Description XML")

    try:
        response = requests.get(
            f"http://{HONEYPOT_IP}:{HTTP_PORT}/WANIPConnection.xml",
            timeout=TIMEOUT
        )

        if response.status_code == 200 and "AddPortMapping" in response.text:
            test_result(True, "Service Description XML", "AddPortMapping action available")
            return True
        else:
            test_result(False, "Service Description XML", f"Status: {response.status_code}")
            return False
    except Exception as e:
        test_result(False, "Service Description XML", f"Error: {e}")
        return False


def test_soap_add_port_mapping():
    """Test 4: SOAP AddPortMapping Attack"""
    print("\nTest 4: SOAP AddPortMapping Attack")

    soap_request = '''<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewExternalPort>8080</NewExternalPort>
      <NewInternalPort>80</NewInternalPort>
      <NewInternalClient>192.168.1.100</NewInternalClient>
      <NewProtocol>TCP</NewProtocol>
      <NewPortMappingDescription>Python Test</NewPortMappingDescription>
      <NewLeaseDuration>0</NewLeaseDuration>
    </u:AddPortMapping>
  </s:Body>
</s:Envelope>'''

    headers = {
        'Content-Type': 'text/xml; charset=utf-8',
        'SOAPAction': '"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"'
    }

    try:
        response = requests.post(
            f"http://{HONEYPOT_IP}:{HTTP_PORT}/ctl/IPConn",
            data=soap_request,
            headers=headers,
            timeout=TIMEOUT
        )

        if response.status_code == 200 and "AddPortMappingResponse" in response.text:
            test_result(True, "SOAP AddPortMapping", "Request accepted (logged as attack)")
            return True
        else:
            test_result(False, "SOAP AddPortMapping", f"Status: {response.status_code}")
            return False
    except Exception as e:
        test_result(False, "SOAP AddPortMapping", f"Error: {e}")
        return False


def test_soap_delete_port_mapping():
    """Test 5: SOAP DeletePortMapping Attack"""
    print("\nTest 5: SOAP DeletePortMapping Attack")

    soap_request = '''<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:DeletePortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewExternalPort>8080</NewExternalPort>
      <NewProtocol>TCP</NewProtocol>
    </u:DeletePortMapping>
  </s:Body>
</s:Envelope>'''

    headers = {
        'Content-Type': 'text/xml; charset=utf-8',
        'SOAPAction': '"urn:schemas-upnp-org:service:WANIPConnection:1#DeletePortMapping"'
    }

    try:
        response = requests.post(
            f"http://{HONEYPOT_IP}:{HTTP_PORT}/ctl/IPConn",
            data=soap_request,
            headers=headers,
            timeout=TIMEOUT
        )

        if response.status_code == 200 and "DeletePortMappingResponse" in response.text:
            test_result(True, "SOAP DeletePortMapping", "Request accepted (logged as attack)")
            return True
        else:
            test_result(False, "SOAP DeletePortMapping", f"Status: {response.status_code}")
            return False
    except Exception as e:
        test_result(False, "SOAP DeletePortMapping", f"Error: {e}")
        return False


def test_soap_get_external_ip():
    """Test 6: SOAP GetExternalIPAddress"""
    print("\nTest 6: SOAP GetExternalIPAddress")

    soap_request = '''<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:GetExternalIPAddress xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
    </u:GetExternalIPAddress>
  </s:Body>
</s:Envelope>'''

    headers = {
        'Content-Type': 'text/xml; charset=utf-8',
        'SOAPAction': '"urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress"'
    }

    try:
        response = requests.post(
            f"http://{HONEYPOT_IP}:{HTTP_PORT}/ctl/IPConn",
            data=soap_request,
            headers=headers,
            timeout=TIMEOUT
        )

        if response.status_code == 200 and "GetExternalIPAddressResponse" in response.text:
            # Extract IP
            for line in response.text.split('\n'):
                if '<NewExternalIPAddress>' in line:
                    external_ip = line.split('>')[1].split('<')[0]
                    test_result(True, "SOAP GetExternalIPAddress", f"External IP: {external_ip}")
                    return True
            test_result(True, "SOAP GetExternalIPAddress", "Response received")
            return True
        else:
            test_result(False, "SOAP GetExternalIPAddress", f"Status: {response.status_code}")
            return False
    except Exception as e:
        test_result(False, "SOAP GetExternalIPAddress", f"Error: {e}")
        return False


def test_presentation_url():
    """Test 7: Presentation URL (Web Interface)"""
    print("\nTest 7: Presentation URL (Web Interface)")

    try:
        response = requests.get(
            f"http://{HONEYPOT_IP}:{HTTP_PORT}/",
            timeout=TIMEOUT
        )

        if response.status_code == 200 and "Smart Router" in response.text:
            test_result(True, "Presentation URL", "Web interface accessible")
            return True
        else:
            test_result(False, "Presentation URL", f"Status: {response.status_code}")
            return False
    except Exception as e:
        test_result(False, "Presentation URL", f"Error: {e}")
        return False


def test_ssdp_scan_threshold():
    """Test 8: SSDP Scan Threshold (Suricata Detection)"""
    print("\nTest 8: SSDP Scan Threshold (25 requests)")
    print("Sending 25 M-SEARCH requests to trigger Suricata SID 2000016...")

    success_count = 0
    for i in range(25):
        response = send_ssdp_msearch()
        if response:
            success_count += 1
        time.sleep(0.1)  # Small delay between requests

    test_result(
        success_count >= 20,
        "SSDP Scan Threshold",
        f"{success_count}/25 requests succeeded (should trigger Suricata alert)"
    )


def main():
    """Run all tests"""
    print("=" * 60)
    print("UPnP Honeypot Test Suite (Python)")
    print("=" * 60)
    print(f"Target: {HONEYPOT_IP}")
    print(f"SSDP Port: {SSDP_PORT}")
    print(f"HTTP Port: {HTTP_PORT}")
    print("=" * 60)

    # Run tests
    test_ssdp_discovery()
    test_device_description()
    test_service_description()
    test_soap_add_port_mapping()
    test_soap_delete_port_mapping()
    test_soap_get_external_ip()
    test_presentation_url()
    test_ssdp_scan_threshold()

    # Summary
    print("\n" + "=" * 60)
    print(f"Tests Passed: {tests_passed}")
    print(f"Tests Failed: {tests_failed}")
    print("=" * 60)

    if tests_failed == 0:
        print("All tests passed!")
        return 0
    else:
        print("Some tests failed.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
