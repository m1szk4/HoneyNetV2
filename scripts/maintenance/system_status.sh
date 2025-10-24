#!/bin/bash
# ============================================================================
# HoneyNetV2 System Status Check
# ============================================================================
# Purpose: Display system health, data statistics, and recent activity
# Usage: ./system_status.sh
# ============================================================================

set -euo pipefail

# Configuration
CLICKHOUSE_CONTAINER="${CLICKHOUSE_CONTAINER:-honeynet-clickhouse}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_ok() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# ============================================================================
# DOCKER CONTAINER STATUS
# ============================================================================

print_header "Docker Container Status"

CONTAINERS=(
    "honeynet-cowrie:Cowrie (SSH/Telnet)"
    "honeynet-dionaea:Dionaea (Multi-protocol)"
    "honeynet-conpot:Conpot (ICS/SCADA)"
    "honeynet-suricata:Suricata (IDS)"
    "honeynet-zeek:Zeek (Network Monitor)"
    "honeynet-logstash:Logstash (ETL)"
    "honeynet-clickhouse:ClickHouse (Database)"
    "honeynet-grafana:Grafana (Visualization)"
    "honeynet-jupyter:Jupyter (Analysis)"
)

for container_info in "${CONTAINERS[@]}"; do
    IFS=':' read -r container_name description <<< "$container_info"

    if docker ps -q -f name="$container_name" | grep -q .; then
        status=$(docker inspect -f '{{.State.Status}}' "$container_name")
        if [ "$status" = "running" ]; then
            print_ok "$description: Running"
        else
            print_warn "$description: $status"
        fi
    else
        print_error "$description: Not found"
    fi
done

echo ""

# ============================================================================
# CLICKHOUSE DATABASE STATISTICS
# ============================================================================

print_header "Database Statistics (Last 24 Hours)"

if docker ps -q -f name="$CLICKHOUSE_CONTAINER" | grep -q .; then
    # Test connection
    if docker exec "$CLICKHOUSE_CONTAINER" clickhouse-client --query="SELECT 1" &>/dev/null; then
        print_ok "ClickHouse connection: OK"
        echo ""

        # Event counts
        echo "Event Counts:"
        docker exec "$CLICKHOUSE_CONTAINER" clickhouse-client --query="
        SELECT
            'Honeypot Events' AS table_name,
            count() AS total_events,
            uniq(source_ip_hash) AS unique_attackers
        FROM honeynet.honeypot_events
        WHERE timestamp >= now() - INTERVAL 24 HOUR
        UNION ALL
        SELECT
            'IDS Alerts' AS table_name,
            count() AS total_events,
            uniq(source_ip_hash) AS unique_attackers
        FROM honeynet.ids_alerts
        WHERE timestamp >= now() - INTERVAL 24 HOUR
        UNION ALL
        SELECT
            'Network Connections' AS table_name,
            count() AS total_events,
            uniq(source_ip_hash) AS unique_sources
        FROM honeynet.network_connections
        WHERE timestamp >= now() - INTERVAL 24 HOUR
        FORMAT PrettyCompact
        "

        echo ""
        echo "Honeypot Breakdown:"
        docker exec "$CLICKHOUSE_CONTAINER" clickhouse-client --query="
        SELECT
            honeypot_type,
            count() AS events,
            uniq(source_ip_hash) AS unique_attackers,
            uniq(dest_port) AS unique_ports
        FROM honeynet.honeypot_events
        WHERE timestamp >= now() - INTERVAL 24 HOUR
        GROUP BY honeypot_type
        ORDER BY events DESC
        FORMAT PrettyCompact
        "

        echo ""
        echo "Geographic Distribution (Top 10):"
        docker exec "$CLICKHOUSE_CONTAINER" clickhouse-client --query="
        SELECT
            source_ip_country,
            count() AS attacks,
            round(attacks * 100.0 / sum(attacks) OVER (), 2) AS percentage
        FROM honeynet.honeypot_events
        WHERE timestamp >= now() - INTERVAL 24 HOUR
          AND source_ip_country != ''
        GROUP BY source_ip_country
        ORDER BY attacks DESC
        LIMIT 10
        FORMAT PrettyCompact
        "

        echo ""
        echo "MITRE ATT&CK Techniques (Last 24h):"
        docker exec "$CLICKHOUSE_CONTAINER" clickhouse-client --query="
        SELECT
            mitre_tactic,
            mitre_technique_id,
            count() AS detections
        FROM honeynet.ids_alerts
        WHERE timestamp >= now() - INTERVAL 24 HOUR
          AND mitre_technique_id != ''
        GROUP BY mitre_tactic, mitre_technique_id
        ORDER BY detections DESC
        LIMIT 10
        FORMAT PrettyCompact
        " || echo "  No MITRE ATT&CK data available"

    else
        print_error "ClickHouse connection: Failed"
    fi
else
    print_error "ClickHouse container not running"
fi

echo ""

# ============================================================================
# DATA QUALITY CHECKS
# ============================================================================

print_header "Data Quality Checks"

if docker ps -q -f name="$CLICKHOUSE_CONTAINER" | grep -q .; then
    # GeoIP coverage
    echo "GeoIP Coverage (Last 24h):"
    docker exec "$CLICKHOUSE_CONTAINER" clickhouse-client --query="
    SELECT
        'Honeypot Events' AS source,
        countIf(source_ip_country != '') AS with_country,
        count() AS total,
        round(with_country * 100.0 / total, 2) AS coverage_percent
    FROM honeynet.honeypot_events
    WHERE timestamp >= now() - INTERVAL 24 HOUR
    UNION ALL
    SELECT
        'IDS Alerts' AS source,
        countIf(source_ip_country != '') AS with_country,
        count() AS total,
        round(with_country * 100.0 / total, 2) AS coverage_percent
    FROM honeynet.ids_alerts
    WHERE timestamp >= now() - INTERVAL 24 HOUR
    FORMAT PrettyCompact
    "

    echo ""

    # MITRE coverage
    echo "MITRE ATT&CK Coverage (IDS Alerts, Last 24h):"
    docker exec "$CLICKHOUSE_CONTAINER" clickhouse-client --query="
    SELECT
        countIf(mitre_technique_id != '') AS with_mitre,
        count() AS total_alerts,
        round(with_mitre * 100.0 / total_alerts, 2) AS coverage_percent
    FROM honeynet.ids_alerts
    WHERE timestamp >= now() - INTERVAL 24 HOUR
    FORMAT PrettyCompact
    " || echo "  Unable to check MITRE coverage"
fi

echo ""

# ============================================================================
# LATERAL MOVEMENT DETECTION
# ============================================================================

print_header "Lateral Movement Detection (Last 7 Days)"

if docker ps -q -f name="$CLICKHOUSE_CONTAINER" | grep -q .; then
    LATERAL_EVENTS=$(docker exec "$CLICKHOUSE_CONTAINER" clickhouse-client --query="
    SELECT count()
    FROM honeynet.honeypot_events
    WHERE dest_ip LIKE '172.20.0.%'
      AND timestamp >= now() - INTERVAL 7 DAY
    FORMAT TSV
    " 2>/dev/null || echo "0")

    LATERAL_ALERTS=$(docker exec "$CLICKHOUSE_CONTAINER" clickhouse-client --query="
    SELECT count()
    FROM honeynet.ids_alerts
    WHERE signature_id = 2000035
      AND timestamp >= now() - INTERVAL 7 DAY
    FORMAT TSV
    " 2>/dev/null || echo "0")

    if [ "$LATERAL_EVENTS" -gt 0 ] || [ "$LATERAL_ALERTS" -gt 0 ]; then
        print_warn "Lateral movement detected!"
        echo "  Internal traffic events: $LATERAL_EVENTS"
        echo "  IDS alerts (SID 2000035): $LATERAL_ALERTS"

        if [ "$LATERAL_EVENTS" -gt 0 ]; then
            echo ""
            echo "Recent lateral movement events:"
            docker exec "$CLICKHOUSE_CONTAINER" clickhouse-client --query="
            SELECT
                timestamp,
                honeypot_type,
                source_ip_hash,
                dest_ip,
                dest_port
            FROM honeynet.honeypot_events
            WHERE dest_ip LIKE '172.20.0.%'
              AND timestamp >= now() - INTERVAL 7 DAY
            ORDER BY timestamp DESC
            LIMIT 5
            FORMAT PrettyCompact
            "
        fi
    else
        print_ok "No lateral movement detected"
    fi
fi

echo ""

# ============================================================================
# DISK SPACE USAGE
# ============================================================================

print_header "Disk Space Usage"

echo "Data Directory:"
du -sh /opt/iot-honeynet/data/* 2>/dev/null || echo "  Unable to check disk usage"

echo ""
echo "Docker Volumes:"
docker volume ls --filter name=honeynet | tail -n +2 | while read -r driver volume_name; do
    size=$(docker system df -v | grep "$volume_name" | awk '{print $3}' || echo "unknown")
    echo "  $volume_name: $size"
done

echo ""

# ============================================================================
# RECENT ERRORS
# ============================================================================

print_header "Recent Errors (Last 1 Hour)"

echo "Logstash Errors:"
docker logs honeynet-logstash --since 1h 2>&1 | grep -i "error" | tail -5 || echo "  No recent errors"

echo ""
echo "ClickHouse Errors:"
docker logs honeynet-clickhouse --since 1h 2>&1 | grep -i "error" | tail -5 || echo "  No recent errors"

echo ""

# ============================================================================
# TOP ATTACKERS
# ============================================================================

print_header "Top 10 Attackers (Last 24 Hours)"

if docker ps -q -f name="$CLICKHOUSE_CONTAINER" | grep -q .; then
    docker exec "$CLICKHOUSE_CONTAINER" clickhouse-client --query="
    SELECT
        source_ip_hash,
        source_ip_country,
        count() AS total_events,
        groupUniqArray(dest_port) AS ports_targeted,
        min(timestamp) AS first_seen,
        max(timestamp) AS last_seen
    FROM honeynet.honeypot_events
    WHERE timestamp >= now() - INTERVAL 24 HOUR
    GROUP BY source_ip_hash, source_ip_country
    ORDER BY total_events DESC
    LIMIT 10
    FORMAT PrettyCompact
    "
fi

echo ""

# ============================================================================
# SUMMARY
# ============================================================================

print_header "System Summary"

echo "$(date)"
echo ""
print_ok "HoneyNetV2 system status check completed"

exit 0
