#!/bin/bash
# PCAP Traffic Capture Script
# Captures network traffic with hourly rotation for HoneyNetV2
#
# Usage: ./capture_traffic.sh [interface]

set -e

# Configuration
INTERFACE="${1:-${PCAP_INTERFACE:-eth0}}"
PCAP_BASE_DIR="${PCAP_DIR:-/data/pcap}"
ROTATION_SECONDS="${PCAP_ROTATION_SECONDS:-3600}"  # 1 hour
MAX_FILE_SIZE="${PCAP_MAX_SIZE:-1000}"  # MB
SNAPLEN="${PCAP_SNAPLEN:-65535}"  # Full packet capture
BUFFER_SIZE="${PCAP_BUFFER_SIZE:-8192}"  # 8MB buffer

# Colors for logging
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

# Verify interface exists
if ! ip link show "$INTERFACE" &> /dev/null; then
    error "Interface $INTERFACE does not exist!"
    error "Available interfaces:"
    ip -br link show
    exit 1
fi

log "Starting PCAP capture on interface: $INTERFACE"
log "Base directory: $PCAP_BASE_DIR"
log "Rotation interval: $ROTATION_SECONDS seconds ($(($ROTATION_SECONDS / 3600)) hour(s))"

# Create base directory
mkdir -p "$PCAP_BASE_DIR"

# Generate filename with date-based directory structure
# Format: /data/pcap/YYYY-MM-DD/capture_YYYYMMDD_HH0000.pcap
generate_filename() {
    local date_dir=$(date +'%Y-%m-%d')
    local timestamp=$(date +'%Y%m%d_%H0000')
    local dir="$PCAP_BASE_DIR/$date_dir"

    mkdir -p "$dir"
    echo "$dir/capture_${timestamp}.pcap"
}

# Cleanup handler
cleanup() {
    log "Received termination signal, stopping capture..."
    if [ -n "$TCPDUMP_PID" ]; then
        kill -TERM "$TCPDUMP_PID" 2>/dev/null || true
        wait "$TCPDUMP_PID" 2>/dev/null || true
    fi
    log "PCAP capture stopped"
    exit 0
}

trap cleanup SIGTERM SIGINT SIGQUIT

# Check if tcpdump is available
if ! command -v tcpdump &> /dev/null; then
    error "tcpdump is not installed!"
    exit 1
fi

log "Starting tcpdump..."

# Start tcpdump with automatic rotation
# -i: interface
# -w: write to file with strftime pattern
# -G: rotate file every N seconds
# -C: max file size in MB (backup to -G rotation)
# -s: snaplen (packet capture size)
# -B: buffer size in KB
# -n: don't resolve hostnames
# -Z: run as user (if started as root)
# -v: verbose

# Using strftime patterns for automatic rotation
tcpdump -i "$INTERFACE" \
    -w "$PCAP_BASE_DIR/%Y-%m-%d/capture_%Y%m%d_%H0000.pcap" \
    -G "$ROTATION_SECONDS" \
    -C "$MAX_FILE_SIZE" \
    -s "$SNAPLEN" \
    -B "$BUFFER_SIZE" \
    -n \
    -v \
    2>&1 | while IFS= read -r line; do
        log "tcpdump: $line"
    done &

TCPDUMP_PID=$!

log "tcpdump started with PID: $TCPDUMP_PID"
log "Capturing traffic - press Ctrl+C to stop"

# Monitor tcpdump process
wait "$TCPDUMP_PID"
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    error "tcpdump exited with code $EXIT_CODE"
    exit $EXIT_CODE
fi

log "PCAP capture completed successfully"
