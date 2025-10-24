#!/bin/bash
# Install HoneyNet PCAP Cleanup Systemd Timer
# This script installs the systemd service and timer for automatic PCAP cleanup

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" >&2
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    error "This script must be run as root (use sudo)"
    exit 1
fi

log "====================================================================="
log "HoneyNet PCAP Cleanup - Systemd Timer Installation"
log "====================================================================="
log ""

# Detect project directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

log "Project directory: $PROJECT_DIR"
log ""

# Check if systemd is available
if ! command -v systemctl &> /dev/null; then
    error "systemd is not available on this system"
    exit 1
fi

log "Installing systemd service and timer..."
log ""

# Copy service file
log "Installing service file..."
cp "$PROJECT_DIR/configs/systemd/honeynet-pcap-cleanup.service" /etc/systemd/system/
chmod 644 /etc/systemd/system/honeynet-pcap-cleanup.service

# Copy timer file
log "Installing timer file..."
cp "$PROJECT_DIR/configs/systemd/honeynet-pcap-cleanup.timer" /etc/systemd/system/
chmod 644 /etc/systemd/system/honeynet-pcap-cleanup.timer

# Update paths in service file to match actual installation
log "Updating paths in service file..."
sed -i "s|/opt/honeynet|$PROJECT_DIR|g" /etc/systemd/system/honeynet-pcap-cleanup.service

# Reload systemd
log "Reloading systemd daemon..."
systemctl daemon-reload

# Enable timer (but don't start service - timer will handle that)
log "Enabling timer..."
systemctl enable honeynet-pcap-cleanup.timer

# Start timer
log "Starting timer..."
systemctl start honeynet-pcap-cleanup.timer

log ""
log "====================================================================="
log "Installation Complete!"
log "====================================================================="
log ""

# Show status
log "Timer status:"
systemctl status honeynet-pcap-cleanup.timer --no-pager -l

log ""
log "Next scheduled run:"
systemctl list-timers honeynet-pcap-cleanup.timer --no-pager

log ""
log "Useful commands:"
log "  systemctl status honeynet-pcap-cleanup.timer   # Check timer status"
log "  systemctl start honeynet-pcap-cleanup.service  # Run cleanup now (manual)"
log "  journalctl -u honeynet-pcap-cleanup.service    # View cleanup logs"
log "  systemctl disable honeynet-pcap-cleanup.timer  # Disable automatic cleanup"
log ""

exit 0
