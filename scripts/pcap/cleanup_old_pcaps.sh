#!/bin/bash
# PCAP Cleanup Script - Retention Policy Enforcement
# Removes PCAP files older than specified retention period
#
# Usage: ./cleanup_old_pcaps.sh [retention_days]

set -e

# Configuration
PCAP_BASE_DIR="${PCAP_DIR:-/data/pcap}"
RETENTION_DAYS="${1:-${PCAP_RETENTION_DAYS:-60}}"  # Default: 60 days
DRY_RUN="${PCAP_DRY_RUN:-false}"

# Colors for logging
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO:${NC} $1"
}

log "====================================================================="
log "PCAP Cleanup - Retention Policy Enforcement"
log "====================================================================="
log "Base directory: $PCAP_BASE_DIR"
log "Retention period: $RETENTION_DAYS days"
log "Dry run: $DRY_RUN"
log ""

# Check if base directory exists
if [ ! -d "$PCAP_BASE_DIR" ]; then
    warn "PCAP directory does not exist: $PCAP_BASE_DIR"
    log "Nothing to clean up"
    exit 0
fi

# Calculate disk usage before cleanup
DISK_USAGE_BEFORE=$(du -sh "$PCAP_BASE_DIR" 2>/dev/null | cut -f1 || echo "0")
log "Current disk usage: $DISK_USAGE_BEFORE"
log ""

# Find files older than retention period
log "Searching for files older than $RETENTION_DAYS days..."

# Count files to be removed
OLD_FILES_COUNT=$(find "$PCAP_BASE_DIR" -type f -name "*.pcap" -mtime +$RETENTION_DAYS 2>/dev/null | wc -l)

if [ "$OLD_FILES_COUNT" -eq 0 ]; then
    log "No files found older than $RETENTION_DAYS days"
    exit 0
fi

log "Found $OLD_FILES_COUNT file(s) to remove"
log ""

# Calculate total size of files to be removed
TOTAL_SIZE=$(find "$PCAP_BASE_DIR" -type f -name "*.pcap" -mtime +$RETENTION_DAYS -exec du -ch {} + 2>/dev/null | grep total$ | cut -f1 || echo "0")
log "Total size to be freed: $TOTAL_SIZE"
log ""

# List files to be removed (first 10)
if [ "$OLD_FILES_COUNT" -gt 0 ]; then
    info "Sample of files to be removed (showing first 10):"
    find "$PCAP_BASE_DIR" -type f -name "*.pcap" -mtime +$RETENTION_DAYS -printf "  %TY-%Tm-%Td %TH:%TM  %10s  %p\n" 2>/dev/null | sort | head -10

    if [ "$OLD_FILES_COUNT" -gt 10 ]; then
        info "  ... and $(($OLD_FILES_COUNT - 10)) more file(s)"
    fi
    log ""
fi

# Perform cleanup
if [ "$DRY_RUN" = "true" ]; then
    warn "DRY RUN MODE - No files will be deleted"
    log "Set PCAP_DRY_RUN=false to perform actual cleanup"
else
    log "Removing old PCAP files..."

    # Remove files
    REMOVED_COUNT=0
    while IFS= read -r -d '' file; do
        if rm "$file" 2>/dev/null; then
            REMOVED_COUNT=$((REMOVED_COUNT + 1))
            # Log every 100th file to avoid spam
            if [ $((REMOVED_COUNT % 100)) -eq 0 ]; then
                info "Removed $REMOVED_COUNT files so far..."
            fi
        else
            error "Failed to remove: $file"
        fi
    done < <(find "$PCAP_BASE_DIR" -type f -name "*.pcap" -mtime +$RETENTION_DAYS -print0 2>/dev/null)

    log "Successfully removed $REMOVED_COUNT file(s)"
    log ""

    # Remove empty directories
    log "Removing empty directories..."
    EMPTY_DIRS=$(find "$PCAP_BASE_DIR" -type d -empty 2>/dev/null | wc -l)
    if [ "$EMPTY_DIRS" -gt 0 ]; then
        find "$PCAP_BASE_DIR" -type d -empty -delete 2>/dev/null
        log "Removed $EMPTY_DIRS empty director(ies)"
    else
        log "No empty directories found"
    fi
fi

log ""

# Calculate disk usage after cleanup
if [ "$DRY_RUN" != "true" ]; then
    DISK_USAGE_AFTER=$(du -sh "$PCAP_BASE_DIR" 2>/dev/null | cut -f1 || echo "0")
    log "Disk usage after cleanup: $DISK_USAGE_AFTER"
    log "Space freed: $TOTAL_SIZE"
fi

log ""
log "Cleanup completed successfully"
log "====================================================================="

# Statistics
log ""
log "PCAP Storage Statistics:"
log "  Retention period: $RETENTION_DAYS days"
log "  Total files: $(find "$PCAP_BASE_DIR" -type f -name "*.pcap" 2>/dev/null | wc -l)"
log "  Total directories: $(find "$PCAP_BASE_DIR" -type d 2>/dev/null | wc -l)"
log "  Current disk usage: $(du -sh "$PCAP_BASE_DIR" 2>/dev/null | cut -f1 || echo "0")"
log "  Oldest file: $(find "$PCAP_BASE_DIR" -type f -name "*.pcap" -printf '%T+ %p\n' 2>/dev/null | sort | head -1 | cut -d' ' -f1 || echo "N/A")"
log "  Newest file: $(find "$PCAP_BASE_DIR" -type f -name "*.pcap" -printf '%T+ %p\n' 2>/dev/null | sort | tail -1 | cut -d' ' -f1 || echo "N/A")"
log ""

exit 0
