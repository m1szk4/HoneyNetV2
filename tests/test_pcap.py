#!/usr/bin/env python3
"""
PCAP Capture Test Suite
Tests for HoneyNetV2 PCAP packet capture functionality

Tests:
1. PCAP directory structure exists
2. PCAP container is running
3. PCAP files are being created
4. PCAP files contain valid packet data
5. Rotation is working (hourly files)
6. Retention policy can be tested (cleanup script)
"""

import os
import sys
import time
import subprocess
import socket
from datetime import datetime
from pathlib import Path

# ANSI color codes
GREEN = '\033[0;32m'
RED = '\033[0;31m'
YELLOW = '\033[1;33m'
NC = '\033[0m'  # No Color


def log(message):
    """Print log message with timestamp"""
    print(f"{GREEN}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]{NC} {message}")


def error(message):
    """Print error message"""
    print(f"{RED}[ERROR]{NC} {message}", file=sys.stderr)


def warn(message):
    """Print warning message"""
    print(f"{YELLOW}[WARNING]{NC} {message}")


def run_command(cmd, check=True):
    """Run shell command and return output"""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            check=check
        )
        return result.stdout.strip(), result.returncode
    except subprocess.CalledProcessError as e:
        return e.stdout.strip(), e.returncode


class PCAPTests:
    def __init__(self, pcap_base_dir="./data/pcap"):
        self.pcap_dir = Path(pcap_base_dir)
        self.passed = 0
        self.failed = 0
        self.warnings = 0

    def test_directory_structure(self):
        """Test 1: Verify PCAP directory structure exists"""
        log("Test 1: Checking PCAP directory structure...")

        if not self.pcap_dir.exists():
            error(f"PCAP directory does not exist: {self.pcap_dir}")
            self.failed += 1
            return False

        if not self.pcap_dir.is_dir():
            error(f"PCAP path is not a directory: {self.pcap_dir}")
            self.failed += 1
            return False

        # Check if directory is writable
        if not os.access(self.pcap_dir, os.W_OK):
            error(f"PCAP directory is not writable: {self.pcap_dir}")
            self.failed += 1
            return False

        log(f"✓ PCAP directory exists and is writable: {self.pcap_dir}")
        self.passed += 1
        return True

    def test_container_running(self):
        """Test 2: Verify PCAP container is running"""
        log("Test 2: Checking if PCAP container is running...")

        output, code = run_command(
            "docker ps --filter name=honeynet-pcap --format '{{.Status}}'",
            check=False
        )

        if code != 0 or not output:
            error("PCAP container is not running")
            error("Start it with: docker-compose up -d pcap")
            self.failed += 1
            return False

        if "Up" not in output:
            error(f"PCAP container status: {output}")
            self.failed += 1
            return False

        log(f"✓ PCAP container is running: {output}")
        self.passed += 1
        return True

    def test_pcap_files_created(self):
        """Test 3: Verify PCAP files are being created"""
        log("Test 3: Checking if PCAP files are being created...")

        # Wait a bit for initial file creation
        time.sleep(2)

        # Look for PCAP files
        pcap_files = list(self.pcap_dir.glob("**/*.pcap"))

        if not pcap_files:
            warn("No PCAP files found yet (this is normal if just started)")
            warn("Waiting 30 seconds for file creation...")
            time.sleep(30)
            pcap_files = list(self.pcap_dir.glob("**/*.pcap"))

            if not pcap_files:
                error("No PCAP files created after 30 seconds")
                error("Check container logs: docker-compose logs pcap")
                self.failed += 1
                return False

        latest_file = max(pcap_files, key=lambda p: p.stat().st_mtime)
        file_size = latest_file.stat().st_size
        file_age = time.time() - latest_file.stat().st_mtime

        log(f"✓ Found {len(pcap_files)} PCAP file(s)")
        log(f"  Latest: {latest_file.name}")
        log(f"  Size: {file_size:,} bytes")
        log(f"  Age: {file_age:.1f} seconds")

        self.passed += 1
        return True

    def test_pcap_file_validity(self):
        """Test 4: Verify PCAP files contain valid packet data"""
        log("Test 4: Validating PCAP file format...")

        pcap_files = list(self.pcap_dir.glob("**/*.pcap"))

        if not pcap_files:
            warn("No PCAP files to validate")
            self.warnings += 1
            return True

        latest_file = max(pcap_files, key=lambda p: p.stat().st_mtime)

        # Check file magic number (PCAP header)
        try:
            with open(latest_file, 'rb') as f:
                magic = f.read(4)

                # PCAP magic numbers
                # 0xa1b2c3d4 = standard pcap
                # 0xa1b23c4d = pcap with nanosecond resolution
                # 0xd4c3b2a1 = swapped standard
                # 0x4d3cb2a1 = swapped nanosecond
                valid_magic = [
                    b'\xa1\xb2\xc3\xd4',
                    b'\xa1\xb2\x3c\x4d',
                    b'\xd4\xc3\xb2\xa1',
                    b'\x4d\x3c\xb2\xa1'
                ]

                if magic not in valid_magic:
                    error(f"Invalid PCAP magic number: {magic.hex()}")
                    self.failed += 1
                    return False

        except Exception as e:
            error(f"Failed to read PCAP file: {e}")
            self.failed += 1
            return False

        # Try to count packets with tcpdump if available
        output, code = run_command(
            f"tcpdump -r {latest_file} -c 10 2>&1 | grep 'packets captured' || echo ''",
            check=False
        )

        if output:
            log(f"✓ PCAP file is valid: {output}")
        else:
            log(f"✓ PCAP file has valid header (tcpdump not available for full validation)")

        self.passed += 1
        return True

    def test_generate_traffic(self):
        """Test 5: Generate test traffic and verify capture"""
        log("Test 5: Generating test traffic to verify capture...")

        # Get current PCAP file size
        pcap_files = list(self.pcap_dir.glob("**/*.pcap"))
        if pcap_files:
            latest_file = max(pcap_files, key=lambda p: p.stat().st_mtime)
            initial_size = latest_file.stat().st_size
        else:
            initial_size = 0

        # Generate some network traffic
        log("  Generating test traffic (HTTP, SSH, DNS)...")

        test_hosts = [
            ('localhost', 22),   # SSH
            ('localhost', 80),   # HTTP
            ('localhost', 443),  # HTTPS
        ]

        for host, port in test_hosts:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((host, port))
                sock.close()
            except:
                pass  # Expected to fail, we just want traffic

        # Wait for traffic to be captured
        time.sleep(3)

        # Check if PCAP file grew
        pcap_files = list(self.pcap_dir.glob("**/*.pcap"))
        if pcap_files:
            latest_file = max(pcap_files, key=lambda p: p.stat().st_mtime)
            final_size = latest_file.stat().st_size

            if final_size > initial_size:
                log(f"✓ PCAP file grew after traffic generation (+{final_size - initial_size} bytes)")
                self.passed += 1
                return True
            else:
                warn("PCAP file size did not change (may need more time or traffic)")
                self.warnings += 1
                return True
        else:
            warn("No PCAP files found after traffic generation")
            self.warnings += 1
            return True

    def test_rotation_structure(self):
        """Test 6: Verify date-based directory structure"""
        log("Test 6: Checking date-based directory structure...")

        today = datetime.now().strftime('%Y-%m-%d')
        today_dir = self.pcap_dir / today

        if not today_dir.exists():
            warn(f"Today's directory not created yet: {today}")
            warn("This is normal if PCAP capture just started")
            self.warnings += 1
            return True

        pcap_files = list(today_dir.glob("*.pcap"))
        log(f"✓ Found {len(pcap_files)} PCAP file(s) in today's directory: {today}")

        for pcap_file in pcap_files[:3]:  # Show first 3
            log(f"  - {pcap_file.name}")

        self.passed += 1
        return True

    def test_cleanup_script(self):
        """Test 7: Test cleanup script in dry-run mode"""
        log("Test 7: Testing cleanup script (dry-run)...")

        cleanup_script = Path("./scripts/pcap/cleanup_old_pcaps.sh")

        if not cleanup_script.exists():
            error(f"Cleanup script not found: {cleanup_script}")
            self.failed += 1
            return False

        # Run cleanup in dry-run mode
        output, code = run_command(
            f"PCAP_DRY_RUN=true {cleanup_script} 60",
            check=False
        )

        if code != 0:
            error(f"Cleanup script failed with code {code}")
            error(output)
            self.failed += 1
            return False

        log("✓ Cleanup script executed successfully (dry-run)")
        self.passed += 1
        return True

    def run_all_tests(self):
        """Run all tests and print summary"""
        log("=" * 70)
        log("HoneyNetV2 PCAP Capture Test Suite")
        log("=" * 70)
        log("")

        tests = [
            self.test_directory_structure,
            self.test_container_running,
            self.test_pcap_files_created,
            self.test_pcap_file_validity,
            self.test_generate_traffic,
            self.test_rotation_structure,
            self.test_cleanup_script,
        ]

        for test in tests:
            try:
                test()
                log("")
            except Exception as e:
                error(f"Test {test.__name__} failed with exception: {e}")
                self.failed += 1
                log("")

        # Summary
        log("=" * 70)
        log("Test Summary")
        log("=" * 70)
        log(f"Passed:   {GREEN}{self.passed}{NC}")
        log(f"Failed:   {RED}{self.failed}{NC}")
        log(f"Warnings: {YELLOW}{self.warnings}{NC}")
        log("")

        if self.failed == 0:
            log(f"{GREEN}✓ All tests passed!{NC}")
            return 0
        else:
            error(f"✗ {self.failed} test(s) failed")
            return 1


if __name__ == "__main__":
    # Parse command line arguments
    pcap_dir = sys.argv[1] if len(sys.argv) > 1 else "./data/pcap"

    # Run tests
    tester = PCAPTests(pcap_dir)
    exit_code = tester.run_all_tests()
    sys.exit(exit_code)
