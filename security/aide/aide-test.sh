#!/bin/bash
##############################################################################
# AIDE Testing Script for HoneyNetV2
#
# This script performs controlled security tests to validate AIDE's ability
# to detect unauthorized changes to the system.
#
# Usage: sudo ./aide-test.sh
##############################################################################

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_test() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root (use sudo)"
    exit 1
fi

echo "========================================================================"
log_info "AIDE Security Testing Suite for HoneyNetV2"
echo "========================================================================"
echo ""

# Verify AIDE is installed and configured
if ! command -v aide &> /dev/null; then
    log_error "AIDE is not installed. Please run aide-init.sh first."
    exit 1
fi

if [ ! -f /var/lib/aide/aide.db ]; then
    log_error "AIDE database not found. Please run aide-init.sh first."
    exit 1
fi

log_info "AIDE is properly configured. Starting security tests..."
echo ""

# Test directory
TEST_DIR="/tmp/aide-test-$$"
TEST_FILE="/tmp/aide-test-file-$$.txt"
TEST_RESULTS="/tmp/aide-test-results-$$.log"

# Cleanup function
cleanup() {
    log_info "Cleaning up test files..."
    rm -f "$TEST_FILE"
    rm -rf "$TEST_DIR"
    rm -f "$TEST_RESULTS"
}

trap cleanup EXIT

##############################################################################
# Test 1: File Creation Detection
##############################################################################
log_test "Test 1: Testing file creation detection in /etc"
echo ""

TEST_ETC_FILE="/etc/aide-test-$(date +%s).conf"

log_info "Creating test file: $TEST_ETC_FILE"
echo "# AIDE test file - safe to delete" > "$TEST_ETC_FILE"

log_info "Running AIDE check..."
aide --check > "$TEST_RESULTS" 2>&1 || true

if grep -q "added" "$TEST_RESULTS" || grep -q "$TEST_ETC_FILE" "$TEST_RESULTS"; then
    log_success "Test 1 PASSED: AIDE detected the new file"
else
    log_error "Test 1 FAILED: AIDE did not detect the new file"
    log_info "Check $TEST_RESULTS for details"
fi

log_info "Removing test file..."
rm -f "$TEST_ETC_FILE"

echo ""
read -p "Press Enter to continue to next test..."
echo ""

##############################################################################
# Test 2: File Modification Detection
##############################################################################
log_test "Test 2: Testing file modification detection"
echo ""

# Create a test file in /etc
TEST_CONFIG="/etc/aide-test-config-$(date +%s).conf"
log_info "Creating test configuration file: $TEST_CONFIG"
echo "original content" > "$TEST_CONFIG"

log_info "Updating AIDE database with the new file..."
aide --update > /dev/null 2>&1 || true
if [ -f /var/lib/aide/aide.db.new ]; then
    cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
fi

log_info "Modifying the test file..."
echo "modified content - unauthorized change" >> "$TEST_CONFIG"

log_info "Running AIDE check..."
aide --check > "$TEST_RESULTS" 2>&1 || true

if grep -q "changed" "$TEST_RESULTS" || grep -q "$TEST_CONFIG" "$TEST_RESULTS"; then
    log_success "Test 2 PASSED: AIDE detected the file modification"
else
    log_error "Test 2 FAILED: AIDE did not detect the modification"
    log_info "Check $TEST_RESULTS for details"
fi

log_info "Removing test file..."
rm -f "$TEST_CONFIG"

echo ""
read -p "Press Enter to continue to next test..."
echo ""

##############################################################################
# Test 3: Permission Change Detection
##############################################################################
log_test "Test 3: Testing permission change detection"
echo ""

TEST_PERM_FILE="/etc/aide-test-perm-$(date +%s).conf"
log_info "Creating test file with standard permissions: $TEST_PERM_FILE"
echo "test content" > "$TEST_PERM_FILE"
chmod 644 "$TEST_PERM_FILE"

log_info "Updating AIDE database..."
aide --update > /dev/null 2>&1 || true
if [ -f /var/lib/aide/aide.db.new ]; then
    cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
fi

log_info "Changing file permissions to 777..."
chmod 777 "$TEST_PERM_FILE"

log_info "Running AIDE check..."
aide --check > "$TEST_RESULTS" 2>&1 || true

if grep -q "changed" "$TEST_RESULTS" || grep -q "perm" "$TEST_RESULTS"; then
    log_success "Test 3 PASSED: AIDE detected the permission change"
else
    log_error "Test 3 FAILED: AIDE did not detect the permission change"
    log_info "Check $TEST_RESULTS for details"
fi

log_info "Removing test file..."
rm -f "$TEST_PERM_FILE"

echo ""
read -p "Press Enter to continue to next test..."
echo ""

##############################################################################
# Test 4: File Deletion Detection
##############################################################################
log_test "Test 4: Testing file deletion detection"
echo ""

TEST_DEL_FILE="/etc/aide-test-delete-$(date +%s).conf"
log_info "Creating test file: $TEST_DEL_FILE"
echo "test content for deletion" > "$TEST_DEL_FILE"

log_info "Updating AIDE database..."
aide --update > /dev/null 2>&1 || true
if [ -f /var/lib/aide/aide.db.new ]; then
    cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
fi

log_info "Deleting the test file..."
rm -f "$TEST_DEL_FILE"

log_info "Running AIDE check..."
aide --check > "$TEST_RESULTS" 2>&1 || true

if grep -q "removed" "$TEST_RESULTS" || grep -q "$TEST_DEL_FILE" "$TEST_RESULTS"; then
    log_success "Test 4 PASSED: AIDE detected the file deletion"
else
    log_error "Test 4 FAILED: AIDE did not detect the file deletion"
    log_info "Check $TEST_RESULTS for details"
fi

echo ""
read -p "Press Enter to continue to next test..."
echo ""

##############################################################################
# Test 5: HoneyNetV2 Script Modification Detection
##############################################################################
log_test "Test 5: Testing HoneyNetV2 script modification detection"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HONEYNET_PATH="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Check if a honeypot script exists
HONEYPOT_SCRIPT=""
if [ -f "$HONEYNET_PATH/honeypots/rtsp/rtsp_honeypot.py" ]; then
    HONEYPOT_SCRIPT="$HONEYNET_PATH/honeypots/rtsp/rtsp_honeypot.py"
elif [ -f "$HONEYNET_PATH/honeypots/upnp/upnp_honeypot.py" ]; then
    HONEYPOT_SCRIPT="$HONEYNET_PATH/honeypots/upnp/upnp_honeypot.py"
fi

if [ -n "$HONEYPOT_SCRIPT" ]; then
    log_info "Testing detection on HoneyNetV2 script: $HONEYPOT_SCRIPT"

    # Backup the original
    BACKUP_FILE="$HONEYPOT_SCRIPT.backup-test"
    cp "$HONEYPOT_SCRIPT" "$BACKUP_FILE"

    # Add a comment to the file
    echo "# AIDE test comment - $(date)" >> "$HONEYPOT_SCRIPT"

    log_info "Running AIDE check..."
    aide --check > "$TEST_RESULTS" 2>&1 || true

    if grep -q "changed" "$TEST_RESULTS" || grep -q "$(basename $HONEYPOT_SCRIPT)" "$TEST_RESULTS"; then
        log_success "Test 5 PASSED: AIDE detected HoneyNetV2 script modification"
    else
        log_error "Test 5 FAILED: AIDE did not detect HoneyNetV2 script modification"
        log_info "Check $TEST_RESULTS for details"
    fi

    # Restore the original file
    mv "$BACKUP_FILE" "$HONEYPOT_SCRIPT"
    log_info "Original file restored"
else
    log_warn "Test 5 SKIPPED: No HoneyNetV2 honeypot scripts found"
    log_info "This is expected if running before deploying to production"
fi

echo ""
echo "========================================================================"
log_info "AIDE Security Testing Complete"
echo "========================================================================"
echo ""

##############################################################################
# Summary
##############################################################################
log_info "Test Summary:"
echo ""
echo "All tests completed. Review the results above to ensure AIDE is"
echo "properly detecting changes to monitored files."
echo ""
echo "Recommendations:"
echo "  1. Review AIDE logs regularly: /var/log/aide/"
echo "  2. Investigate any unexpected changes immediately"
echo "  3. Update AIDE database after authorized changes: sudo aide --update"
echo "  4. Store AIDE database backups in secure, read-only location"
echo "  5. Monitor notification delivery (email/Discord)"
echo ""
log_warn "IMPORTANT: The test modifications have been reverted, but you should"
log_warn "update the AIDE database to reflect the current clean state:"
echo ""
echo "  sudo aide --update"
echo "  sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db"
echo ""
