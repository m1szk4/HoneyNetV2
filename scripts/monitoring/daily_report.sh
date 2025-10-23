#!/bin/bash
#
# Daily Statistics Report for IoT Honeypot
# Purpose: Generate daily summary of attacks and honeypot activity
# Usage: ./daily_report.sh
# Cron: 0 1 * * * /opt/iot-honeynet/scripts/monitoring/daily_report.sh

set -euo pipefail

# Configuration
PROJECT_ROOT="${PROJECT_ROOT:-/opt/iot-honeynet}"
REPORT_DIR="${PROJECT_ROOT}/reports"
REPORT_FILE="${REPORT_DIR}/daily_report_$(date +'%Y%m%d').txt"
ALERT_EMAIL="${ALERT_EMAIL:-}"

# Create reports directory if it doesn't exist
mkdir -p "$REPORT_DIR"

# Colors for terminal output
BOLD='\033[1m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo "$*" | tee -a "$REPORT_FILE"
}

log_header() {
    echo -e "${BOLD}${CYAN}$*${NC}" | tee -a "$REPORT_FILE"
}

log_stat() {
    echo -e "  ${GREEN}$*${NC}" | tee -a "$REPORT_FILE"
}

# Execute ClickHouse query
query_clickhouse() {
    local query=$1
    docker exec clickhouse clickhouse-client --query="$query" 2>/dev/null || echo "Query failed"
}

# Generate report header
generate_header() {
    log_header "========================================="
    log_header "IoT Honeypot Daily Report"
    log_header "Date: $(date +'%Y-%m-%d')"
    log_header "Generated: $(date +'%Y-%m-%d %H:%M:%S')"
    log_header "========================================="
    log ""
}

# System status
generate_system_status() {
    log_header "1. System Status"
    log_header "---------------"

    # Container status
    local running_containers
    running_containers=$(docker ps --format '{{.Names}}' | wc -l)
    log_stat "Running containers: $running_containers"

    # Disk usage
    local disk_usage
    disk_usage=$(df -h "$PROJECT_ROOT" | awk 'NR==2 {print $5}')
    log_stat "Disk usage: $disk_usage"

    # Database size
    local db_size
    db_size=$(query_clickhouse "SELECT formatReadableSize(sum(bytes)) FROM system.parts WHERE database='honeynet' AND active")
    log_stat "Database size: $db_size"

    log ""
}

# Attack statistics (last 24 hours)
generate_attack_stats() {
    log_header "2. Attack Statistics (Last 24 Hours)"
    log_header "------------------------------------"

    # Total events
    local total_events
    total_events=$(query_clickhouse "SELECT count() FROM honeynet.events WHERE timestamp > now() - INTERVAL 24 HOUR")
    log_stat "Total events: $total_events"

    # Unique attackers
    local unique_attackers
    unique_attackers=$(query_clickhouse "SELECT uniq(source_ip_anon) FROM honeynet.events WHERE timestamp > now() - INTERVAL 24 HOUR")
    log_stat "Unique attackers: $unique_attackers"

    # IDS alerts
    local ids_alerts
    ids_alerts=$(query_clickhouse "SELECT count() FROM honeynet.ids_alerts WHERE timestamp > now() - INTERVAL 24 HOUR")
    log_stat "IDS alerts: $ids_alerts"

    # SSH events
    local ssh_events
    ssh_events=$(query_clickhouse "SELECT count() FROM honeynet.ssh_events WHERE timestamp > now() - INTERVAL 24 HOUR")
    log_stat "SSH/Telnet events: $ssh_events"

    # HTTP events
    local http_events
    http_events=$(query_clickhouse "SELECT count() FROM honeynet.http_events WHERE timestamp > now() - INTERVAL 24 HOUR")
    log_stat "HTTP events: $http_events"

    log ""
}

# Top attacking countries
generate_top_countries() {
    log_header "3. Top Attacking Countries"
    log_header "--------------------------"

    query_clickhouse "
        SELECT
            country_code,
            count() AS attacks
        FROM honeynet.events
        WHERE timestamp > now() - INTERVAL 24 HOUR
          AND country_code != 'XX'
        GROUP BY country_code
        ORDER BY attacks DESC
        LIMIT 10
        FORMAT PrettyCompact
    " | tee -a "$REPORT_FILE"

    log ""
}

# Top MITRE ATT&CK techniques
generate_top_techniques() {
    log_header "4. Top MITRE ATT&CK Techniques"
    log_header "------------------------------"

    query_clickhouse "
        SELECT
            attack_technique,
            attack_tactic,
            count() AS occurrences
        FROM honeynet.events
        WHERE timestamp > now() - INTERVAL 24 HOUR
          AND attack_technique != ''
        GROUP BY attack_technique, attack_tactic
        ORDER BY occurrences DESC
        LIMIT 10
        FORMAT PrettyCompact
    " | tee -a "$REPORT_FILE"

    log ""
}

# Most targeted ports
generate_top_ports() {
    log_header "5. Most Targeted Ports"
    log_header "----------------------"

    query_clickhouse "
        SELECT
            dest_port,
            count() AS hits
        FROM honeynet.events
        WHERE timestamp > now() - INTERVAL 24 HOUR
        GROUP BY dest_port
        ORDER BY hits DESC
        LIMIT 10
        FORMAT PrettyCompact
    " | tee -a "$REPORT_FILE"

    log ""
}

# Brute force statistics
generate_bruteforce_stats() {
    log_header "6. Brute Force Attacks"
    log_header "----------------------"

    # Failed logins
    local failed_logins
    failed_logins=$(query_clickhouse "SELECT count() FROM honeynet.ssh_events WHERE event_type='cowrie.login.failed' AND timestamp > now() - INTERVAL 24 HOUR")
    log_stat "Failed login attempts: $failed_logins"

    # Successful logins
    local successful_logins
    successful_logins=$(query_clickhouse "SELECT count() FROM honeynet.ssh_events WHERE event_type='cowrie.login.success' AND timestamp > now() - INTERVAL 24 HOUR")
    log_stat "Successful logins: $successful_logins"

    # Top attempted usernames
    log ""
    log "Top attempted usernames:"
    query_clickhouse "
        SELECT
            username,
            count() AS attempts
        FROM honeynet.ssh_events
        WHERE event_type='cowrie.login.failed'
          AND timestamp > now() - INTERVAL 24 HOUR
          AND username != ''
        GROUP BY username
        ORDER BY attempts DESC
        LIMIT 10
        FORMAT PrettyCompact
    " | tee -a "$REPORT_FILE"

    log ""
}

# Exploit statistics
generate_exploit_stats() {
    log_header "7. Exploit Attempts"
    log_header "-------------------"

    # HTTP exploits
    local http_exploits
    http_exploits=$(query_clickhouse "SELECT count() FROM honeynet.http_events WHERE is_exploit=1 AND timestamp > now() - INTERVAL 24 HOUR")
    log_stat "HTTP exploits detected: $http_exploits"

    if [ "$http_exploits" -gt 0 ]; then
        log ""
        log "Exploit types:"
        query_clickhouse "
            SELECT
                exploit_type,
                count() AS count
            FROM honeynet.http_events
            WHERE is_exploit=1
              AND timestamp > now() - INTERVAL 24 HOUR
              AND exploit_type != ''
            GROUP BY exploit_type
            ORDER BY count DESC
            FORMAT PrettyCompact
        " | tee -a "$REPORT_FILE"
    fi

    log ""
}

# Malware downloads
generate_malware_stats() {
    log_header "8. Malware Downloads"
    log_header "--------------------"

    local download_count
    download_count=$(query_clickhouse "SELECT count() FROM honeynet.downloaded_files WHERE timestamp > now() - INTERVAL 24 HOUR")
    log_stat "Files downloaded: $download_count"

    if [ "$download_count" -gt 0 ]; then
        log ""
        log "Downloaded file hashes:"
        query_clickhouse "
            SELECT
                file_hash,
                file_type,
                formatReadableSize(file_size) AS size,
                count() AS downloads
            FROM honeynet.downloaded_files
            WHERE timestamp > now() - INTERVAL 24 HOUR
            GROUP BY file_hash, file_type, file_size
            ORDER BY downloads DESC
            LIMIT 10
            FORMAT PrettyCompact
        " | tee -a "$REPORT_FILE"
    fi

    log ""
}

# Hourly activity chart (simple text-based)
generate_hourly_chart() {
    log_header "9. Hourly Activity Chart (Last 24h)"
    log_header "-----------------------------------"

    query_clickhouse "
        SELECT
            formatDateTime(toStartOfHour(timestamp), '%Y-%m-%d %H:00') AS hour,
            count() AS events,
            bar(events, 0, (SELECT max(c) FROM (SELECT count() AS c FROM honeynet.events WHERE timestamp > now() - INTERVAL 24 HOUR GROUP BY toStartOfHour(timestamp))), 50) AS chart
        FROM honeynet.events
        WHERE timestamp > now() - INTERVAL 24 HOUR
        GROUP BY hour
        ORDER BY hour
        FORMAT PrettyCompact
    " | tee -a "$REPORT_FILE"

    log ""
}

# Severity distribution
generate_severity_stats() {
    log_header "10. Attack Severity Distribution"
    log_header "--------------------------------"

    query_clickhouse "
        SELECT
            severity,
            count() AS count,
            bar(count, 0, (SELECT max(c) FROM (SELECT count() AS c FROM honeynet.events WHERE timestamp > now() - INTERVAL 24 HOUR GROUP BY severity)), 30) AS chart
        FROM honeynet.events
        WHERE timestamp > now() - INTERVAL 24 HOUR
        GROUP BY severity
        ORDER BY severity DESC
        FORMAT PrettyCompact
    " | tee -a "$REPORT_FILE"

    log ""
}

# Performance metrics
generate_performance_metrics() {
    log_header "11. Performance Metrics"
    log_header "----------------------"

    # Average events per hour
    local avg_events
    avg_events=$(query_clickhouse "SELECT round(count() / 24, 2) FROM honeynet.events WHERE timestamp > now() - INTERVAL 24 HOUR")
    log_stat "Average events per hour: $avg_events"

    # Peak hour
    local peak_hour
    peak_hour=$(query_clickhouse "SELECT formatDateTime(toStartOfHour(timestamp), '%H:00') AS hour, count() AS events FROM honeynet.events WHERE timestamp > now() - INTERVAL 24 HOUR GROUP BY hour ORDER BY events DESC LIMIT 1 FORMAT TSV" | awk '{print $1 " (" $2 " events)"}')
    log_stat "Peak activity hour: $peak_hour"

    # Database query performance (simple test)
    local query_time
    query_time=$(docker exec clickhouse bash -c "time clickhouse-client --query='SELECT count() FROM honeynet.events' 2>&1" | grep real | awk '{print $2}')
    log_stat "Query performance test: $query_time"

    log ""
}

# Generate footer
generate_footer() {
    log_header "========================================="
    log_header "End of Daily Report"
    log_header "Report saved to: $REPORT_FILE"
    log_header "========================================="
}

# Send email if configured
send_email() {
    if [ -n "$ALERT_EMAIL" ] && command -v mail &> /dev/null; then
        local subject="IoT Honeypot Daily Report - $(date +'%Y-%m-%d')"

        cat "$REPORT_FILE" | mail -s "$subject" "$ALERT_EMAIL"
        log "Report emailed to $ALERT_EMAIL"
    fi
}

# Main function
main() {
    # Clear report file
    > "$REPORT_FILE"

    # Generate all sections
    generate_header
    generate_system_status
    generate_attack_stats
    generate_top_countries
    generate_top_techniques
    generate_top_ports
    generate_bruteforce_stats
    generate_exploit_stats
    generate_malware_stats
    generate_hourly_chart
    generate_severity_stats
    generate_performance_metrics
    generate_footer

    # Send email if configured
    send_email

    # Clean up old reports (keep last 30 days)
    find "$REPORT_DIR" -name "daily_report_*.txt" -mtime +30 -delete 2>/dev/null || true

    echo ""
    echo "Daily report generated successfully!"
    echo "Report location: $REPORT_FILE"
}

# Run main function
main "$@"
