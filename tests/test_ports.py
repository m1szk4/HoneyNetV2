#!/usr/bin/env python3
"""
HoneyNetV2 Port Accessibility Test
Tests that all honeypot ports are accessible and listening
"""

import socket
import sys
from typing import List, Tuple

# Define honeypot services and their ports
HONEYPOT_PORTS = {
    'Cowrie SSH': {'port': 22, 'protocol': 'tcp'},
    'Cowrie Telnet': {'port': 23, 'protocol': 'tcp'},
    'Cowrie Telnet Alt': {'port': 2323, 'protocol': 'tcp'},
    'Dionaea FTP': {'port': 21, 'protocol': 'tcp'},
    'Dionaea HTTP': {'port': 80, 'protocol': 'tcp'},
    'Dionaea HTTPS': {'port': 443, 'protocol': 'tcp'},
    'Dionaea SMB': {'port': 445, 'protocol': 'tcp'},
    'Dionaea MySQL': {'port': 3306, 'protocol': 'tcp'},
    'Dionaea MSSQL': {'port': 1433, 'protocol': 'tcp'},
    'Dionaea HTTP Alt': {'port': 8080, 'protocol': 'tcp'},
    'Conpot S7comm': {'port': 102, 'protocol': 'tcp'},
    'Conpot Modbus': {'port': 502, 'protocol': 'tcp'},
    'RTSP Camera': {'port': 554, 'protocol': 'tcp'},
}

UDP_PORTS = {
    'Conpot SNMP': {'port': 161, 'protocol': 'udp'},
    'Conpot BACnet': {'port': 47808, 'protocol': 'udp'},
    'Conpot IPMI': {'port': 623, 'protocol': 'udp'},
}

MANAGEMENT_PORTS = {
    'Grafana': {'port': 3000, 'protocol': 'tcp'},
    'Jupyter': {'port': 8888, 'protocol': 'tcp'},
    'ClickHouse HTTP': {'port': 8123, 'protocol': 'tcp'},
    'ClickHouse Native': {'port': 9000, 'protocol': 'tcp'},
}


def test_tcp_port(host: str, port: int, timeout: int = 2) -> bool:
    """
    Test if a TCP port is open and accepting connections

    Args:
        host: Hostname or IP address
        port: Port number
        timeout: Connection timeout in seconds

    Returns:
        True if port is open, False otherwise
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def test_udp_port(host: str, port: int, timeout: int = 2) -> bool:
    """
    Test if a UDP port is reachable (basic check)

    Args:
        host: Hostname or IP address
        port: Port number
        timeout: Connection timeout in seconds

    Returns:
        True if port appears open (no ICMP port unreachable), False otherwise
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # Send a dummy packet
        sock.sendto(b'\x00', (host, port))

        try:
            # Try to receive (will timeout if port is open but no response)
            sock.recvfrom(1024)
            sock.close()
            return True
        except socket.timeout:
            # Timeout is actually good - means port didn't refuse
            sock.close()
            return True

    except Exception:
        return False


def test_ports(host: str, ports: dict, protocol: str = 'tcp') -> Tuple[List[str], List[str]]:
    """
    Test a dictionary of ports

    Args:
        host: Hostname or IP address to test
        ports: Dictionary of port definitions
        protocol: Default protocol if not specified in port definition

    Returns:
        Tuple of (passed_tests, failed_tests)
    """
    passed = []
    failed = []

    for service_name, config in ports.items():
        port = config['port']
        proto = config.get('protocol', protocol)

        print(f"  Testing {service_name} ({proto}/{port})...", end=' ')

        if proto == 'tcp':
            is_open = test_tcp_port(host, port)
        elif proto == 'udp':
            is_open = test_udp_port(host, port)
        else:
            print("UNKNOWN PROTOCOL")
            failed.append(f"{service_name} - unknown protocol {proto}")
            continue

        if is_open:
            print("✓ OPEN")
            passed.append(service_name)
        else:
            print("✗ CLOSED")
            failed.append(f"{service_name} ({proto}/{port})")

    return passed, failed


def main():
    """Main test execution"""
    print("="*70)
    print("HoneyNetV2 Port Accessibility Test")
    print("="*70)

    # Test host
    host = 'localhost'

    all_passed = []
    all_failed = []

    # Test honeypot TCP ports
    print("\n[*] Testing Honeypot TCP Ports...")
    passed, failed = test_ports(host, HONEYPOT_PORTS, 'tcp')
    all_passed.extend(passed)
    all_failed.extend(failed)

    # Test honeypot UDP ports
    print("\n[*] Testing Honeypot UDP Ports...")
    passed, failed = test_ports(host, UDP_PORTS, 'udp')
    all_passed.extend(passed)
    all_failed.extend(failed)

    # Test management ports
    print("\n[*] Testing Management Ports...")
    passed, failed = test_ports(host, MANAGEMENT_PORTS, 'tcp')
    all_passed.extend(passed)
    all_failed.extend(failed)

    # Print summary
    print("\n" + "="*70)
    print("Test Summary")
    print("="*70)

    print(f"\nTotal Ports Tested: {len(all_passed) + len(all_failed)}")
    print(f"Passed: {len(all_passed)}")
    print(f"Failed: {len(all_failed)}")

    if all_failed:
        print("\n✗ FAILED TESTS:")
        for test in all_failed:
            print(f"  - {test}")
        print("\nSome ports are not accessible. Check:")
        print("  1. Docker containers are running: docker-compose ps")
        print("  2. Port mappings in docker-compose.yml")
        print("  3. Host firewall rules (ufw/iptables)")
        print("  4. Container logs: docker-compose logs <service>")
        return 1
    else:
        print("\n✓ ALL PORTS ACCESSIBLE")
        print("  All honeypot and management services are reachable!")
        return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nUnexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
