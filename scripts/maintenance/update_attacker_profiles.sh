#!/bin/bash
# ============================================================================
# HoneyNetV2 Attacker Profile Update Script
# ============================================================================
# Purpose: Update attacker_profiles table with latest data
# Usage: Run via cron (e.g., daily at 4 AM)
# Schedule: 0 4 * * * /opt/iot-honeynet/scripts/maintenance/update_attacker_profiles.sh
# ============================================================================

set -euo pipefail

# Configuration
PROJECT_ROOT="${PROJECT_ROOT:-/opt/iot-honeynet}"
CLICKHOUSE_CONTAINER="${CLICKHOUSE_CONTAINER:-honeynet-clickhouse}"
LOG_FILE="${PROJECT_ROOT}/logs/attacker_profiles.log"

# Create log directory
mkdir -p "$(dirname "$LOG_FILE")"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

# ============================================================================
# CHECK CLICKHOUSE AVAILABILITY
# ============================================================================

log "INFO: Checking ClickHouse availability..."

if ! docker ps -q -f name="$CLICKHOUSE_CONTAINER" | grep -q .; then
    log "ERROR: ClickHouse container not running"
    exit 1
fi

# Wait for ClickHouse to be ready
for i in {1..30}; do
    if docker exec "$CLICKHOUSE_CONTAINER" clickhouse-client --query="SELECT 1" &>/dev/null; then
        log "INFO: ClickHouse is ready"
        break
    fi
    log "WARN: Waiting for ClickHouse... (attempt $i/30)"
    sleep 2
done

# ============================================================================
# UPDATE ATTACKER PROFILES
# ============================================================================

log "INFO: Starting attacker profile update..."

# Get count of existing profiles
EXISTING_COUNT=$(docker exec "$CLICKHOUSE_CONTAINER" clickhouse-client --query="\
    SELECT count() FROM honeynet.attacker_profiles FORMAT TSV" 2>/dev/null || echo "0")

log "INFO: Existing attacker profiles: $EXISTING_COUNT"

# ============================================================================
# Step 1: Populate basic profiles from honeypot events (last 24 hours)
# ============================================================================

log "INFO: Step 1/3 - Updating profiles from honeypot events..."

docker exec "$CLICKHOUSE_CONTAINER" clickhouse-client --query="
INSERT INTO honeynet.attacker_profiles
SELECT
    source_ip_hash,
    min(timestamp) AS first_seen,
    max(timestamp) AS last_seen,
    count() AS total_events,
    groupUniqArray(dest_port) AS unique_ports_targeted,
    groupUniqArray(protocol) AS protocols_used,
    groupUniqArray(source_ip_country) AS countries,
    groupUniqArray(event_type) AS attack_types,
    0 AS credential_attempts,
    0 AS successful_logins,
    0 AS files_downloaded
FROM honeynet.honeypot_events
WHERE timestamp >= now() - INTERVAL 1 DAY
  AND source_ip_hash NOT IN (SELECT source_ip_hash FROM honeynet.attacker_profiles)
GROUP BY source_ip_hash
" 2>&1 | tee -a "$LOG_FILE"

PROFILES_ADDED=$?
if [ $PROFILES_ADDED -eq 0 ]; then
    log "INFO: Successfully added new attacker profiles"
else
    log "WARN: Failed to add new profiles (exit code: $PROFILES_ADDED)"
fi

# ============================================================================
# Step 2: Update credential statistics
# ============================================================================

log "INFO: Step 2/3 - Updating credential statistics..."

# Create temporary table with credential stats
docker exec "$CLICKHOUSE_CONTAINER" clickhouse-client --query="
CREATE TEMPORARY TABLE temp_cred_stats AS
SELECT
    source_ip_hash,
    count() AS total_attempts,
    countIf(success = true) AS successful_attempts
FROM honeynet.credentials
WHERE timestamp >= now() - INTERVAL 1 DAY
GROUP BY source_ip_hash
" 2>&1 | tee -a "$LOG_FILE"

# Update profiles with credential data
docker exec "$CLICKHOUSE_CONTAINER" clickhouse-client --query="
ALTER TABLE honeynet.attacker_profiles
UPDATE
    credential_attempts = credential_attempts + (
        SELECT total_attempts
        FROM temp_cred_stats
        WHERE temp_cred_stats.source_ip_hash = attacker_profiles.source_ip_hash
    ),
    successful_logins = successful_logins + (
        SELECT successful_attempts
        FROM temp_cred_stats
        WHERE temp_cred_stats.source_ip_hash = attacker_profiles.source_ip_hash
    )
WHERE source_ip_hash IN (SELECT source_ip_hash FROM temp_cred_stats)
" 2>&1 | tee -a "$LOG_FILE"

log "INFO: Credential statistics updated"

# ============================================================================
# Step 3: Update file download statistics
# ============================================================================

log "INFO: Step 3/3 - Updating file download statistics..."

# Create temporary table with download stats
docker exec "$CLICKHOUSE_CONTAINER" clickhouse-client --query="
CREATE TEMPORARY TABLE temp_download_stats AS
SELECT
    source_ip_hash,
    count() AS download_count
FROM honeynet.downloaded_files
WHERE timestamp >= now() - INTERVAL 1 DAY
GROUP BY source_ip_hash
" 2>&1 | tee -a "$LOG_FILE"

# Update profiles with download data
docker exec "$CLICKHOUSE_CONTAINER" clickhouse-client --query="
ALTER TABLE honeynet.attacker_profiles
UPDATE
    files_downloaded = files_downloaded + (
        SELECT download_count
        FROM temp_download_stats
        WHERE temp_download_stats.source_ip_hash = attacker_profiles.source_ip_hash
    )
WHERE source_ip_hash IN (SELECT source_ip_hash FROM temp_download_stats)
" 2>&1 | tee -a "$LOG_FILE"

log "INFO: File download statistics updated"

# ============================================================================
# STATISTICS AND SUMMARY
# ============================================================================

log "INFO: Generating statistics..."

# Get updated count
NEW_COUNT=$(docker exec "$CLICKHOUSE_CONTAINER" clickhouse-client --query="\
    SELECT count() FROM honeynet.attacker_profiles FORMAT TSV" 2>/dev/null || echo "0")

PROFILES_ADDED=$((NEW_COUNT - EXISTING_COUNT))

# Get top attackers
log "INFO: Top 10 most active attackers (last 24h):"
docker exec "$CLICKHOUSE_CONTAINER" clickhouse-client --query="
SELECT
    source_ip_hash,
    total_events,
    length(unique_ports_targeted) AS ports_count,
    length(protocols_used) AS protocols_count,
    credential_attempts,
    files_downloaded
FROM honeynet.attacker_profiles
WHERE last_seen >= now() - INTERVAL 1 DAY
ORDER BY total_events DESC
LIMIT 10
FORMAT PrettyCompact
" 2>&1 | tee -a "$LOG_FILE"

# Summary
log "========================================="
log "Attacker Profile Update Summary"
log "========================================="
log "Previous profiles: $EXISTING_COUNT"
log "New profiles added: $PROFILES_ADDED"
log "Total profiles: $NEW_COUNT"
log "========================================="

# Send email notification (if configured)
if [ -n "${ALERT_EMAIL:-}" ]; then
    {
        echo "HoneyNetV2 Attacker Profile Update"
        echo "==================================="
        echo "Date: $(date)"
        echo "Profiles Added: $PROFILES_ADDED"
        echo "Total Profiles: $NEW_COUNT"
        echo ""
        echo "See full log: $LOG_FILE"
    } | mail -s "HoneyNetV2 Attacker Profiles - $(date +%Y-%m-%d)" "$ALERT_EMAIL" 2>/dev/null || true
fi

log "INFO: Attacker profile update completed successfully"
exit 0
