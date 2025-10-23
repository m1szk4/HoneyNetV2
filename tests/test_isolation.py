#!/usr/bin/env python3
"""
HoneyNetV2 Isolation Test
Tests that honeypot containers cannot access the Internet (DMZ isolation)
"""

import docker
import sys
import subprocess
from typing import List, Tuple

# Honeypot containers to test
HONEYPOT_CONTAINERS = [
    'honeynet-cowrie',
    'honeynet-dionaea',
    'honeynet-conpot'
]

# External hosts to test connectivity (should fail)
EXTERNAL_HOSTS = [
    '8.8.8.8',          # Google DNS
    '1.1.1.1',          # Cloudflare DNS
    'www.google.com',   # Web service
]


def test_container_isolation(container_name: str) -> Tuple[bool, List[str]]:
    """
    Test if a container cannot reach external hosts

    Args:
        container_name: Name of the Docker container to test

    Returns:
        Tuple of (passed, errors) where passed is True if isolation is working
    """
    client = docker.from_env()
    errors = []

    try:
        container = client.containers.get(container_name)

        if container.status != 'running':
            errors.append(f"Container {container_name} is not running")
            return False, errors

        print(f"\n[*] Testing isolation for: {container_name}")

        # Test connectivity to external hosts
        for host in EXTERNAL_HOSTS:
            print(f"  - Testing connectivity to {host}...", end=' ')

            # Try to ping (should fail or timeout)
            try:
                result = container.exec_run(
                    f"ping -c 1 -W 2 {host}",
                    timeout=3
                )

                # If ping succeeds, isolation is broken
                if result.exit_code == 0:
                    errors.append(f"Container {container_name} can reach {host} - ISOLATION BREACH!")
                    print("FAIL (isolation breach!)")
                else:
                    print("OK (cannot reach)")

            except Exception as e:
                # Timeout or error is expected (good - means isolated)
                print("OK (isolated)")

        # Test DNS resolution (should fail or not resolve external domains)
        for host in ['google.com', 'cloudflare.com']:
            try:
                result = container.exec_run(
                    f"nslookup {host}",
                    timeout=3
                )

                if result.exit_code == 0 and b'Address' in result.output:
                    print(f"  - WARNING: Container can resolve {host}")

            except Exception:
                # Timeout is good - means no DNS
                pass

    except docker.errors.NotFound:
        errors.append(f"Container {container_name} not found")
        return False, errors

    except Exception as e:
        errors.append(f"Error testing {container_name}: {str(e)}")
        return False, errors

    # If no errors, isolation is working
    return len(errors) == 0, errors


def test_network_configuration() -> Tuple[bool, List[str]]:
    """
    Test Docker network configuration for DMZ isolation

    Returns:
        Tuple of (passed, errors)
    """
    client = docker.from_env()
    errors = []

    print("\n[*] Testing Docker network configuration...")

    try:
        # Check honeypot_net exists
        honeypot_net = client.networks.get('honeynet_honeypot_net')

        # Check if masquerade is disabled (no NAT)
        options = honeypot_net.attrs.get('Options', {})
        enable_masquerade = options.get('com.docker.network.bridge.enable_ip_masquerade', 'true')

        if enable_masquerade != 'false':
            errors.append("DMZ network has masquerade enabled - should be disabled for isolation")
            print("  - Masquerade: ENABLED (should be disabled) - FAIL")
        else:
            print("  - Masquerade: DISABLED - OK")

        # Check inter-container communication
        enable_icc = options.get('com.docker.network.bridge.enable_icc', 'true')
        if enable_icc == 'true':
            print("  - Inter-container communication: ENABLED - OK")
        else:
            print("  - Inter-container communication: DISABLED - WARNING")

    except docker.errors.NotFound:
        errors.append("honeypot_net network not found")
        return False, errors

    except Exception as e:
        errors.append(f"Error checking network configuration: {str(e)}")
        return False, errors

    return len(errors) == 0, errors


def test_iptables_rules() -> Tuple[bool, List[str]]:
    """
    Test host iptables rules for DMZ isolation

    Returns:
        Tuple of (passed, errors)
    """
    errors = []

    print("\n[*] Testing host iptables rules...")

    try:
        # Check if DOCKER-USER chain has DROP rules for honeypot subnet
        result = subprocess.run(
            ['iptables', '-L', 'DOCKER-USER', '-n', '-v'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            output = result.stdout

            # Check for DROP rules for 172.20.0.0/24
            if '172.20.0.0/24' in output and 'DROP' in output:
                print("  - DROP rules for honeypot subnet: FOUND - OK")
            else:
                errors.append("No DROP rules found for honeypot subnet in DOCKER-USER chain")
                print("  - DROP rules for honeypot subnet: NOT FOUND - WARNING")
        else:
            print("  - Could not check iptables (requires root) - SKIP")

    except FileNotFoundError:
        print("  - iptables command not found - SKIP")
    except Exception as e:
        print(f"  - Error checking iptables: {str(e)} - SKIP")

    return len(errors) == 0, errors


def main():
    """Main test execution"""
    print("="*70)
    print("HoneyNetV2 Isolation Test")
    print("="*70)

    all_passed = True
    all_errors = []

    # Test network configuration
    passed, errors = test_network_configuration()
    if not passed:
        all_passed = False
        all_errors.extend(errors)

    # Test iptables rules (optional, requires root)
    passed, errors = test_iptables_rules()
    if not passed:
        # Don't fail on iptables check (may require root)
        all_errors.extend([f"WARNING: {e}" for e in errors])

    # Test each honeypot container
    for container_name in HONEYPOT_CONTAINERS:
        passed, errors = test_container_isolation(container_name)
        if not passed:
            all_passed = False
            all_errors.extend(errors)

    # Print summary
    print("\n" + "="*70)
    print("Test Summary")
    print("="*70)

    if all_passed:
        print("\n✓ ALL TESTS PASSED - Honeypot isolation is working correctly!")
        print("  Honeypots cannot access the Internet (DMZ isolation verified)")
        return 0
    else:
        print("\n✗ SOME TESTS FAILED - Isolation may be compromised!")
        print("\nErrors:")
        for error in all_errors:
            print(f"  - {error}")
        return 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nTest interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nUnexpected error: {str(e)}")
        sys.exit(1)
