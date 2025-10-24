#!/bin/bash
##############################################################################
# AIDE Initialization Script for HoneyNetV2
#
# This script installs and initializes AIDE (Advanced Intrusion Detection
# Environment) for monitoring file integrity on the host system.
#
# Usage: sudo ./aide-init.sh
##############################################################################

set -e  # Exit on any error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root (use sudo)"
    exit 1
fi

log_info "Starting AIDE installation and configuration for HoneyNetV2"
echo "========================================================================"

# Determine the actual HoneyNetV2 installation path
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HONEYNET_PATH="$(cd "$SCRIPT_DIR/../.." && pwd)"

log_info "Detected HoneyNetV2 path: $HONEYNET_PATH"

# Step 1: Install AIDE
log_info "Step 1/6: Installing AIDE..."
if command -v aide &> /dev/null; then
    log_info "AIDE is already installed"
    aide --version
else
    log_info "Installing AIDE package..."
    if command -v apt-get &> /dev/null; then
        apt-get update
        apt-get install -y aide aide-common
    elif command -v yum &> /dev/null; then
        yum install -y aide
    else
        log_error "Unsupported package manager. Please install AIDE manually."
        exit 1
    fi
    log_info "AIDE installed successfully"
fi

# Step 2: Create necessary directories
log_info "Step 2/6: Creating AIDE directories..."
mkdir -p /var/lib/aide
mkdir -p /var/log/aide
mkdir -p /etc/aide

log_info "Setting permissions for AIDE directories..."
chmod 700 /var/lib/aide
chmod 755 /var/log/aide
chmod 755 /etc/aide

# Step 3: Backup existing configuration if present
if [ -f /etc/aide/aide.conf ]; then
    log_warn "Existing AIDE configuration found"
    BACKUP_FILE="/etc/aide/aide.conf.backup.$(date +%Y%m%d_%H%M%S)"
    log_info "Creating backup: $BACKUP_FILE"
    cp /etc/aide/aide.conf "$BACKUP_FILE"
fi

# Step 4: Copy and customize configuration
log_info "Step 3/6: Installing AIDE configuration..."
cp "$SCRIPT_DIR/aide.conf" /etc/aide/aide.conf

# Update the HONEYNET_PATH in the configuration
log_info "Customizing configuration with HoneyNetV2 path: $HONEYNET_PATH"
sed -i "s|@@define HONEYNET_PATH /opt/HoneyNetV2|@@define HONEYNET_PATH $HONEYNET_PATH|g" /etc/aide/aide.conf

log_info "AIDE configuration installed to /etc/aide/aide.conf"

# Step 5: Initialize AIDE database
log_info "Step 4/6: Initializing AIDE database..."
log_warn "This process may take several minutes depending on system size..."

if [ -f /var/lib/aide/aide.db ]; then
    log_warn "Existing AIDE database found"
    read -p "Do you want to reinitialize the database? This will overwrite the existing one. (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Skipping database initialization"
    else
        log_info "Reinitializing AIDE database..."
        aide --init
        log_info "Moving new database to active location..."
        mv -f /var/lib/aide/aide.db.new /var/lib/aide/aide.db
        log_info "Database reinitialized successfully"
    fi
else
    log_info "Initializing AIDE database for the first time..."
    aide --init

    if [ -f /var/lib/aide/aide.db.new ]; then
        log_info "Moving new database to active location..."
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
        log_info "Database initialized successfully"
    else
        log_error "Failed to initialize AIDE database"
        exit 1
    fi
fi

# Step 6: Set proper permissions
log_info "Step 5/6: Setting database permissions..."
chmod 600 /var/lib/aide/aide.db
chown root:root /var/lib/aide/aide.db

# Step 7: Verify installation
log_info "Step 6/6: Verifying AIDE installation..."
if aide --version &> /dev/null && [ -f /var/lib/aide/aide.db ]; then
    log_info "AIDE is properly configured and database is initialized"
else
    log_error "AIDE installation verification failed"
    exit 1
fi

# Display summary
echo ""
echo "========================================================================"
log_info "AIDE initialization completed successfully!"
echo "========================================================================"
echo ""
echo "Next steps:"
echo "  1. Review configuration: /etc/aide/aide.conf"
echo "  2. Run manual check: sudo aide --check"
echo "  3. Set up cron job for automated scans (see aide-cron-setup.sh)"
echo "  4. Test integrity detection (see aide-test.sh)"
echo ""
echo "Important files:"
echo "  - Configuration: /etc/aide/aide.conf"
echo "  - Database: /var/lib/aide/aide.db"
echo "  - Logs: /var/log/aide/"
echo ""
log_warn "IMPORTANT: Store a copy of /var/lib/aide/aide.db in a secure, read-only location"
log_warn "to prevent attackers from modifying the baseline database."
echo ""
