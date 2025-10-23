#!/bin/bash
# HoneyNetV2 Daily Report Generator
# Generates a daily summary of honeypot activity

set -e

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

REPORT_DATE=$(date +%Y-%m-%d)
REPORT_FILE="reports/daily_report_${REPORT_DATE}.txt"

# Create reports directory
mkdir -p reports

echo "======================================================================"
echo "HoneyNetV2 Daily Report - $REPORT_DATE"
echo "======================================================================"
echo ""
echo "Generated: $(date)"
echo ""

# Redirect output to both console and file
{
    echo "======================================================================"
    echo "HoneyNetV2 Daily Report - $REPORT_DATE"
    echo "======================================================================"
    echo ""
    echo "Generated: $(date)"
    echo ""

    # System Health
    echo "System Health:"
    echo "----------------------------------------------------------------------"
    docker-compose ps 2>/dev/null || echo "Could not get container status"
    echo ""

    # Attack Statistics (from ClickHouse)
    echo "Attack Statistics:"
    echo "----------------------------------------------------------------------"

    if command -v clickhouse-client &> /dev/null || docker ps | grep -q honeynet-clickhouse; then
        # Query via HTTP API
        CLICKHOUSE_URL="http://localhost:8123"
        DB="${CLICKHOUSE_DB:-honeynet}"

        echo "Total Events Today:"
        curl -s "${CLICKHOUSE_URL}/?database=${DB}" --data "SELECT count() FROM honeypot_events WHERE toDate(timestamp) = today()" || echo "Query failed"
        echo ""

        echo "Events by Honeypot:"
        curl -s "${CLICKHOUSE_URL}/?database=${DB}" --data "SELECT honeypot_type, count() as count FROM honeypot_events WHERE toDate(timestamp) = today() GROUP BY honeypot_type ORDER BY count DESC" || echo "Query failed"
        echo ""

        echo "Top 10 Source IPs (anonymized):"
        curl -s "${CLICKHOUSE_URL}/?database=${DB}" --data "SELECT source_ip_hash, count() as count FROM honeypot_events WHERE toDate(timestamp) = today() GROUP BY source_ip_hash ORDER BY count DESC LIMIT 10" || echo "Query failed"
        echo ""

        echo "Top Attacked Ports:"
        curl -s "${CLICKHOUSE_URL}/?database=${DB}" --data "SELECT dest_port, count() as count FROM honeypot_events WHERE toDate(timestamp) = today() GROUP BY dest_port ORDER BY count DESC LIMIT 10" || echo "Query failed"
        echo ""

        echo "Most Common Credentials Tried:"
        curl -s "${CLICKHOUSE_URL}/?database=${DB}" --data "SELECT username, password, count() as count FROM credentials WHERE toDate(timestamp) = today() GROUP BY username, password ORDER BY count DESC LIMIT 10" || echo "Query failed"
        echo ""

        echo "IDS Alerts by Severity:"
        curl -s "${CLICKHOUSE_URL}/?database=${DB}" --data "SELECT alert_severity, count() as count FROM ids_alerts WHERE toDate(timestamp) = today() GROUP BY alert_severity ORDER BY alert_severity" || echo "Query failed"
        echo ""

        echo "Files Downloaded:"
        curl -s "${CLICKHOUSE_URL}/?database=${DB}" --data "SELECT count() as count, sum(file_size) as total_bytes FROM downloaded_files WHERE toDate(timestamp) = today()" || echo "Query failed"
        echo ""

    else
        echo "ClickHouse not available - cannot generate statistics"
        echo ""
    fi

    # Container Logs Summary
    echo "Recent Activity (last 24 hours):"
    echo "----------------------------------------------------------------------"

    echo ""
    echo "Cowrie Events:"
    docker logs --since 24h honeynet-cowrie 2>&1 | grep -i "login\|session\|command" | tail -20 || echo "No recent activity"

    echo ""
    echo "Dionaea Connections:"
    docker logs --since 24h honeynet-dionaea 2>&1 | grep -i "connection" | tail -20 || echo "No recent activity"

    echo ""
    echo "Suricata Alerts:"
    docker logs --since 24h honeynet-suricata 2>&1 | grep -i "alert" | tail -20 || echo "No recent alerts"

    echo ""
    echo "======================================================================"
    echo "Report End"
    echo "======================================================================"

} | tee "$REPORT_FILE"

echo ""
echo "Report saved to: $REPORT_FILE"

# Send email if configured
if [ -n "$ALERT_EMAIL" ] && command -v mail &> /dev/null; then
    echo "Sending report to: $ALERT_EMAIL"
    cat "$REPORT_FILE" | mail -s "HoneyNetV2 Daily Report - $REPORT_DATE" "$ALERT_EMAIL"
    echo "Email sent"
fi
