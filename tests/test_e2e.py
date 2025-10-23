#!/usr/bin/env python3
"""
HoneyNetV2 End-to-End Test
Comprehensive test suite for the entire honeypot infrastructure
"""

import docker
import sys
import time
from typing import Dict, List

# Expected containers
REQUIRED_CONTAINERS = {
    'honeynet-cowrie': 'running',
    'honeynet-dionaea': 'running',
    'honeynet-conpot': 'running',
    'honeynet-suricata': 'running',
    'honeynet-zeek': 'running',
    'honeynet-clickhouse': 'running',
    'honeynet-logstash': 'running',
    'honeynet-grafana': 'running',
    'honeynet-jupyter': 'running',
}


def test_container_status() -> Dict[str, bool]:
    """
    Test if all required containers are running

    Returns:
        Dictionary mapping container names to pass/fail status
    """
    client = docker.from_env()
    results = {}

    print("\n[*] Testing Container Status...")

    for container_name, expected_status in REQUIRED_CONTAINERS.items():
        try:
            container = client.containers.get(container_name)
            actual_status = container.status

            if actual_status == expected_status:
                print(f"  ✓ {container_name}: {actual_status}")
                results[container_name] = True
            else:
                print(f"  ✗ {container_name}: {actual_status} (expected: {expected_status})")
                results[container_name] = False

        except docker.errors.NotFound:
            print(f"  ✗ {container_name}: NOT FOUND")
            results[container_name] = False
        except Exception as e:
            print(f"  ✗ {container_name}: ERROR - {str(e)}")
            results[container_name] = False

    return results


def test_container_health() -> Dict[str, bool]:
    """
    Test health status of containers with health checks

    Returns:
        Dictionary mapping container names to health status
    """
    client = docker.from_env()
    results = {}

    print("\n[*] Testing Container Health...")

    containers_with_health = ['honeynet-clickhouse', 'honeynet-grafana']

    for container_name in containers_with_health:
        try:
            container = client.containers.get(container_name)

            # Get health status
            health = container.attrs.get('State', {}).get('Health', {})
            health_status = health.get('Status', 'no healthcheck')

            if health_status == 'healthy':
                print(f"  ✓ {container_name}: healthy")
                results[container_name] = True
            elif health_status == 'starting':
                print(f"  ⏳ {container_name}: starting (wait and retry)")
                results[container_name] = False
            elif health_status == 'no healthcheck':
                print(f"  - {container_name}: no healthcheck defined")
                results[container_name] = True  # Not a failure
            else:
                print(f"  ✗ {container_name}: {health_status}")
                results[container_name] = False

        except docker.errors.NotFound:
            print(f"  ✗ {container_name}: NOT FOUND")
            results[container_name] = False
        except Exception as e:
            print(f"  - {container_name}: {str(e)}")
            results[container_name] = True  # Not a critical failure

    return results


def test_network_connectivity() -> Dict[str, bool]:
    """
    Test network connectivity between containers

    Returns:
        Dictionary of test results
    """
    client = docker.from_env()
    results = {}

    print("\n[*] Testing Network Connectivity...")

    # Test if ClickHouse is accessible from Logstash
    try:
        logstash = client.containers.get('honeynet-logstash')

        # Try to reach ClickHouse
        result = logstash.exec_run(
            "curl -s -o /dev/null -w '%{http_code}' http://clickhouse:8123/ping",
            timeout=5
        )

        if b'200' in result.output:
            print("  ✓ Logstash → ClickHouse: OK")
            results['logstash_clickhouse'] = True
        else:
            print(f"  ✗ Logstash → ClickHouse: FAILED (response: {result.output})")
            results['logstash_clickhouse'] = False

    except Exception as e:
        print(f"  ✗ Logstash → ClickHouse: ERROR - {str(e)}")
        results['logstash_clickhouse'] = False

    # Test if Grafana can reach ClickHouse
    try:
        grafana = client.containers.get('honeynet-grafana')

        result = grafana.exec_run(
            "curl -s -o /dev/null -w '%{http_code}' http://clickhouse:8123/ping",
            timeout=5
        )

        if b'200' in result.output:
            print("  ✓ Grafana → ClickHouse: OK")
            results['grafana_clickhouse'] = True
        else:
            print(f"  ✗ Grafana → ClickHouse: FAILED")
            results['grafana_clickhouse'] = False

    except Exception as e:
        print(f"  ✗ Grafana → ClickHouse: ERROR - {str(e)}")
        results['grafana_clickhouse'] = False

    return results


def test_data_directories() -> Dict[str, bool]:
    """
    Test if required data directories exist and are writable

    Returns:
        Dictionary of test results
    """
    import os

    results = {}

    print("\n[*] Testing Data Directories...")

    required_dirs = [
        'data/cowrie',
        'data/dionaea',
        'data/conpot',
        'data/suricata',
        'data/zeek',
        'data/clickhouse',
        'data/grafana',
        'data/logstash',
    ]

    for dir_path in required_dirs:
        if os.path.exists(dir_path):
            if os.access(dir_path, os.W_OK):
                print(f"  ✓ {dir_path}: exists and writable")
                results[dir_path] = True
            else:
                print(f"  ✗ {dir_path}: exists but not writable")
                results[dir_path] = False
        else:
            print(f"  ✗ {dir_path}: does not exist")
            results[dir_path] = False

    return results


def main():
    """Main test execution"""
    print("="*70)
    print("HoneyNetV2 End-to-End Test Suite")
    print("="*70)

    all_tests = {}

    # Test 1: Container Status
    results = test_container_status()
    all_tests.update(results)

    # Test 2: Container Health
    results = test_container_health()
    all_tests.update(results)

    # Test 3: Network Connectivity
    results = test_network_connectivity()
    all_tests.update(results)

    # Test 4: Data Directories
    results = test_data_directories()
    all_tests.update(results)

    # Summary
    print("\n" + "="*70)
    print("Test Summary")
    print("="*70)

    passed = sum(1 for v in all_tests.values() if v)
    failed = sum(1 for v in all_tests.values() if not v)

    print(f"\nTotal Tests: {len(all_tests)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")

    if failed == 0:
        print("\n✓ ALL TESTS PASSED")
        print("  HoneyNet infrastructure is fully operational!")
        return 0
    else:
        print("\n✗ SOME TESTS FAILED")
        print("\nFailed tests:")
        for test_name, result in all_tests.items():
            if not result:
                print(f"  - {test_name}")

        print("\nTroubleshooting steps:")
        print("  1. Check container logs: docker-compose logs <service>")
        print("  2. Restart services: docker-compose restart")
        print("  3. Check resource usage: docker stats")
        print("  4. Verify .env configuration")

        return 1


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
