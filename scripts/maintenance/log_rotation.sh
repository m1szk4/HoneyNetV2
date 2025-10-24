#!/bin/bash
# ============================================================================
# HoneyNetV2 Log Rotation Script
# ============================================================================
# Purpose: Rotate and compress old log files from honeypots and IDS
# Usage: Run via cron (e.g., daily at 2 AM)
# Schedule: 0 2 * * * /opt/iot-honeynet/scripts/maintenance/log_rotation.sh
# ============================================================================

set -euo pipefail

# Configuration
PROJECT_ROOT="${PROJECT_ROOT:-/opt/iot-honeynet}"
DATA_DIR="${PROJECT_ROOT}/data"
LOG_RETENTION_DAYS="${LOG_RETENTION_DAYS:-30}"
ARCHIVE_DIR="${PROJECT_ROOT}/archives/logs"
DATE=$(date +%Y%m%d)

# Logging
LOG_FILE="${PROJECT_ROOT}/logs/log_rotation.log"
mkdir -p "$(dirname "$LOG_FILE")"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

# ============================================================================
# CREATE ARCHIVE DIRECTORY
# ============================================================================

mkdir -p "$ARCHIVE_DIR"

# ============================================================================
# ROTATE COWRIE LOGS
# ============================================================================

log "INFO: Starting Cowrie log rotation..."

COWRIE_LOG_DIR="${DATA_DIR}/cowrie/log"
if [ -d "$COWRIE_LOG_DIR" ]; then
    # Find log files older than 7 days
    find "$COWRIE_LOG_DIR" -name "cowrie.json.*" -mtime +7 -type f | while read -r logfile; do
        filename=$(basename "$logfile")
        log "INFO: Compressing Cowrie log: $filename"
        gzip -9 "$logfile" 2>/dev/null || log "WARN: Failed to compress $logfile"
    done

    # Archive compressed logs older than 30 days
    find "$COWRIE_LOG_DIR" -name "*.gz" -mtime +${LOG_RETENTION_DAYS} -type f | while read -r gzfile; do
        filename=$(basename "$gzfile")
        log "INFO: Archiving Cowrie log: $filename"
        mv "$gzfile" "${ARCHIVE_DIR}/" || log "WARN: Failed to archive $gzfile"
    done

    # Delete archived files older than 90 days
    find "$ARCHIVE_DIR" -name "cowrie*.gz" -mtime +90 -type f -delete

    log "INFO: Cowrie log rotation completed"
else
    log "WARN: Cowrie log directory not found: $COWRIE_LOG_DIR"
fi

# ============================================================================
# ROTATE DIONAEA LOGS
# ============================================================================

log "INFO: Starting Dionaea log rotation..."

DIONAEA_LOG_DIR="${DATA_DIR}/dionaea"
if [ -d "$DIONAEA_LOG_DIR" ]; then
    # Rotate dionaea.json if it exceeds 100MB
    DIONAEA_JSON="${DIONAEA_LOG_DIR}/dionaea.json"
    if [ -f "$DIONAEA_JSON" ]; then
        SIZE=$(stat -f%z "$DIONAEA_JSON" 2>/dev/null || stat -c%s "$DIONAEA_JSON" 2>/dev/null)
        if [ "$SIZE" -gt 104857600 ]; then  # 100MB
            log "INFO: Rotating large dionaea.json ($(numfmt --to=iec-i --suffix=B $SIZE))"
            mv "$DIONAEA_JSON" "${DIONAEA_JSON}.${DATE}"
            touch "$DIONAEA_JSON"
            chmod 644 "$DIONAEA_JSON"
            gzip -9 "${DIONAEA_JSON}.${DATE}" &
        fi
    fi

    # Compress old log files
    find "$DIONAEA_LOG_DIR" -name "dionaea.json.*" -mtime +7 -type f ! -name "*.gz" | while read -r logfile; do
        log "INFO: Compressing Dionaea log: $(basename "$logfile")"
        gzip -9 "$logfile" 2>/dev/null || log "WARN: Failed to compress $logfile"
    done

    # Archive compressed logs
    find "$DIONAEA_LOG_DIR" -name "*.gz" -mtime +${LOG_RETENTION_DAYS} -type f | while read -r gzfile; do
        filename=$(basename "$gzfile")
        log "INFO: Archiving Dionaea log: $filename"
        mv "$gzfile" "${ARCHIVE_DIR}/" || log "WARN: Failed to archive $gzfile"
    done

    # Clean up old binaries/downloads
    find "$DIONAEA_LOG_DIR/binaries" -type f -mtime +60 -delete 2>/dev/null || true

    log "INFO: Dionaea log rotation completed"
else
    log "WARN: Dionaea log directory not found: $DIONAEA_LOG_DIR"
fi

# ============================================================================
# ROTATE CONPOT LOGS
# ============================================================================

log "INFO: Starting Conpot log rotation..."

CONPOT_LOG_DIR="${DATA_DIR}/conpot"
if [ -d "$CONPOT_LOG_DIR" ]; then
    # Rotate conpot.json if it exceeds 100MB
    CONPOT_JSON="${CONPOT_LOG_DIR}/conpot.json"
    if [ -f "$CONPOT_JSON" ]; then
        SIZE=$(stat -f%z "$CONPOT_JSON" 2>/dev/null || stat -c%s "$CONPOT_JSON" 2>/dev/null)
        if [ "$SIZE" -gt 104857600 ]; then  # 100MB
            log "INFO: Rotating large conpot.json ($(numfmt --to=iec-i --suffix=B $SIZE))"
            mv "$CONPOT_JSON" "${CONPOT_JSON}.${DATE}"
            touch "$CONPOT_JSON"
            chmod 644 "$CONPOT_JSON"
            gzip -9 "${CONPOT_JSON}.${DATE}" &
        fi
    fi

    # Compress old logs
    find "$CONPOT_LOG_DIR" -name "conpot.json.*" -mtime +7 -type f ! -name "*.gz" | while read -r logfile; do
        log "INFO: Compressing Conpot log: $(basename "$logfile")"
        gzip -9 "$logfile" 2>/dev/null || log "WARN: Failed to compress $logfile"
    done

    # Archive compressed logs
    find "$CONPOT_LOG_DIR" -name "*.gz" -mtime +${LOG_RETENTION_DAYS} -type f | while read -r gzfile; do
        filename=$(basename "$gzfile")
        log "INFO: Archiving Conpot log: $filename"
        mv "$gzfile" "${ARCHIVE_DIR}/" || log "WARN: Failed to archive $gzfile"
    done

    log "INFO: Conpot log rotation completed"
else
    log "WARN: Conpot log directory not found: $CONPOT_LOG_DIR"
fi

# ============================================================================
# ROTATE SURICATA LOGS
# ============================================================================

log "INFO: Starting Suricata log rotation..."

SURICATA_LOG_DIR="${DATA_DIR}/suricata"
if [ -d "$SURICATA_LOG_DIR" ]; then
    # Rotate eve.json if it exceeds 500MB
    EVE_JSON="${SURICATA_LOG_DIR}/eve.json"
    if [ -f "$EVE_JSON" ]; then
        SIZE=$(stat -f%z "$EVE_JSON" 2>/dev/null || stat -c%s "$EVE_JSON" 2>/dev/null)
        if [ "$SIZE" -gt 524288000 ]; then  # 500MB
            log "INFO: Rotating large eve.json ($(numfmt --to=iec-i --suffix=B $SIZE))"
            # Signal Suricata to rotate logs
            docker exec honeynet-suricata killall -USR2 suricata 2>/dev/null || {
                mv "$EVE_JSON" "${EVE_JSON}.${DATE}"
                touch "$EVE_JSON"
                chmod 644 "$EVE_JSON"
            }
            # Compress rotated file
            [ -f "${EVE_JSON}.${DATE}" ] && gzip -9 "${EVE_JSON}.${DATE}" &
        fi
    fi

    # Compress old eve.json files
    find "$SURICATA_LOG_DIR" -name "eve.json.*" -mtime +3 -type f ! -name "*.gz" | while read -r logfile; do
        log "INFO: Compressing Suricata log: $(basename "$logfile")"
        gzip -9 "$logfile" 2>/dev/null || log "WARN: Failed to compress $logfile"
    done

    # Archive compressed logs
    find "$SURICATA_LOG_DIR" -name "*.gz" -mtime +${LOG_RETENTION_DAYS} -type f | while read -r gzfile; do
        filename=$(basename "$gzfile")
        log "INFO: Archiving Suricata log: $filename"
        mv "$gzfile" "${ARCHIVE_DIR}/" || log "WARN: Failed to archive $gzfile"
    done

    # Clean up old stats and fast logs
    find "$SURICATA_LOG_DIR" -name "stats.log.*" -mtime +7 -delete 2>/dev/null || true
    find "$SURICATA_LOG_DIR" -name "fast.log.*" -mtime +7 -delete 2>/dev/null || true

    log "INFO: Suricata log rotation completed"
else
    log "WARN: Suricata log directory not found: $SURICATA_LOG_DIR"
fi

# ============================================================================
# ROTATE ZEEK LOGS
# ============================================================================

log "INFO: Starting Zeek log rotation..."

ZEEK_LOG_DIR="${DATA_DIR}/zeek"
if [ -d "$ZEEK_LOG_DIR" ]; then
    # Zeek rotates logs automatically, we just need to compress old ones

    # Compress old Zeek logs (older than 1 day)
    find "$ZEEK_LOG_DIR" -name "*.log" -mtime +1 -type f ! -name "*.gz" | while read -r logfile; do
        log "INFO: Compressing Zeek log: $(basename "$logfile")"
        gzip -9 "$logfile" 2>/dev/null || log "WARN: Failed to compress $logfile"
    done

    # Archive compressed logs
    find "$ZEEK_LOG_DIR" -name "*.gz" -mtime +${LOG_RETENTION_DAYS} -type f | while read -r gzfile; do
        filename=$(basename "$gzfile")
        log "INFO: Archiving Zeek log: $filename"
        mv "$gzfile" "${ARCHIVE_DIR}/" || log "WARN: Failed to archive $gzfile"
    done

    log "INFO: Zeek log rotation completed"
else
    log "WARN: Zeek log directory not found: $ZEEK_LOG_DIR"
fi

# ============================================================================
# CLEANUP AND SUMMARY
# ============================================================================

# Remove empty directories
find "$DATA_DIR" -type d -empty -delete 2>/dev/null || true

# Calculate space saved
ARCHIVE_SIZE=$(du -sh "$ARCHIVE_DIR" 2>/dev/null | cut -f1)
DATA_SIZE=$(du -sh "$DATA_DIR" 2>/dev/null | cut -f1)

log "INFO: Log rotation completed"
log "INFO: Archive directory size: $ARCHIVE_SIZE"
log "INFO: Data directory size: $DATA_SIZE"

# Send summary email (if configured)
if [ -n "${ALERT_EMAIL:-}" ]; then
    {
        echo "HoneyNetV2 Log Rotation Summary"
        echo "================================"
        echo "Date: $(date)"
        echo "Archive Size: $ARCHIVE_SIZE"
        echo "Data Directory Size: $DATA_SIZE"
        echo ""
        echo "See full log: $LOG_FILE"
    } | mail -s "HoneyNetV2 Log Rotation - $(date +%Y-%m-%d)" "$ALERT_EMAIL" 2>/dev/null || true
fi

exit 0
