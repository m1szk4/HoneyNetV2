#!/bin/bash
#
# Health Check Script for IoT Honeypot
# Purpose: Monitor the status of all honeypot components and alert on failures
# Usage: ./health_check.sh
# Cron: */5 * * * * /opt/iot-honeynet/scripts/monitoring/health_check.sh

set -euo pipefail

# Configuration
PROJECT_ROOT="${PROJECT_ROOT:-/opt/iot-honeynet}"
ALERT_EMAIL="${ALERT_EMAIL:-}"
LOG_FILE="${PROJECT_ROOT}/logs/health_check.log"
ERROR_COUNT=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" | tee -a "$LOG_FILE"
    ((ERROR_COUNT++))
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $*" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*" | tee -a "$LOG_FILE"
}

# Check if docker-compose is available
check_docker() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        return 1
    fi

    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        return 1
    fi

    log_success "Docker is running"
    return 0
}

# Check container status
check_container() {
    local container_name=$1
    local status

    status=$(docker inspect -f '{{.State.Status}}' "$container_name" 2>/dev/null || echo "not_found")

    if [ "$status" = "running" ]; then
        log_success "Container $container_name is running"
        return 0
    elif [ "$status" = "not_found" ]; then
        log_error "Container $container_name not found"
        return 1
    else
        log_error "Container $container_name is $status"
        return 1
    fi
}

# Check container health (if healthcheck is defined)
check_container_health() {
    local container_name=$1
    local health

    health=$(docker inspect -f '{{.State.Health.Status}}' "$container_name" 2>/dev/null || echo "none")

    if [ "$health" = "healthy" ]; then
        log_success "Container $container_name is healthy"
        return 0
    elif [ "$health" = "none" ]; then
        # No healthcheck defined, skip
        return 0
    else
        log_warning "Container $container_name health: $health"
        return 1
    fi
}

# Check ClickHouse connectivity and query
check_clickhouse() {
    log "Checking ClickHouse database..."

    if ! docker exec clickhouse clickhouse-client --query="SELECT 1" &> /dev/null; then
        log_error "ClickHouse query failed"
        return 1
    fi

    # Check if tables exist
    local table_count
    table_count=$(docker exec clickhouse clickhouse-client --query="SELECT count() FROM system.tables WHERE database='honeynet'" 2>/dev/null || echo "0")

    if [ "$table_count" -ge 4 ]; then
        log_success "ClickHouse is operational ($table_count tables in honeynet database)"
        return 0
    else
        log_warning "ClickHouse has only $table_count tables in honeynet database (expected >= 4)"
        return 1
    fi
}

# Check Grafana API
check_grafana() {
    log "Checking Grafana..."

    local response
    response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/api/health 2>/dev/null || echo "000")

    if [ "$response" = "200" ]; then
        log_success "Grafana API is responding"
        return 0
    else
        log_error "Grafana API returned HTTP $response"
        return 1
    fi
}

# Check Logstash API
check_logstash() {
    log "Checking Logstash..."

    local response
    response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:9600/_node/stats 2>/dev/null || echo "000")

    if [ "$response" = "200" ]; then
        log_success "Logstash API is responding"

        # Check pipeline status
        local pipelines
        pipelines=$(curl -s http://localhost:9600/_node/stats/pipelines 2>/dev/null | grep -o '"id":"[^"]*"' | wc -l || echo "0")
        log_success "Logstash has $pipelines active pipeline(s)"
        return 0
    else
        log_error "Logstash API returned HTTP $response"
        return 1
    fi
}

# Check Suricata logs
check_suricata() {
    log "Checking Suricata..."

    local eve_log="/var/log/suricata/eve.json"
    if docker exec suricata test -f "$eve_log" 2>/dev/null; then
        local line_count
        line_count=$(docker exec suricata wc -l < "$eve_log" 2>/dev/null || echo "0")
        log_success "Suricata eve.json exists ($line_count lines)"
        return 0
    else
        log_warning "Suricata eve.json not found"
        return 1
    fi
}

# Check disk space
check_disk_space() {
    log "Checking disk space..."

    local usage
    usage=$(df -h "$PROJECT_ROOT" | awk 'NR==2 {print $5}' | sed 's/%//')

    if [ "$usage" -lt 80 ]; then
        log_success "Disk usage is $usage%"
        return 0
    elif [ "$usage" -lt 90 ]; then
        log_warning "Disk usage is $usage% (warning threshold)"
        return 1
    else
        log_error "Disk usage is $usage% (critical threshold)"
        return 1
    fi
}

# Check for recent events in ClickHouse
check_recent_events() {
    log "Checking for recent honeypot activity..."

    local event_count
    event_count=$(docker exec clickhouse clickhouse-client --query="SELECT count() FROM honeynet.events WHERE timestamp > now() - INTERVAL 1 HOUR" 2>/dev/null || echo "0")

    if [ "$event_count" -gt 0 ]; then
        log_success "$event_count events in the last hour"
        return 0
    else
        log_warning "No events recorded in the last hour (honeypots may be idle)"
        return 1
    fi
}

# Check container logs for errors
check_container_logs() {
    local container_name=$1
    local error_patterns="error|exception|fatal|failed"

    log "Checking $container_name logs for errors..."

    local error_count
    error_count=$(docker logs --tail=100 "$container_name" 2>&1 | grep -iE "$error_patterns" | wc -l || echo "0")

    if [ "$error_count" -eq 0 ]; then
        log_success "No errors in $container_name logs"
        return 0
    else
        log_warning "$error_count error(s) found in $container_name logs (last 100 lines)"
        # Show last 5 errors
        docker logs --tail=100 "$container_name" 2>&1 | grep -iE "$error_patterns" | tail -5 | while read -r line; do
            log "  $line"
        done
        return 1
    fi
}

# Send alert email if configured
send_alert() {
    if [ -n "$ALERT_EMAIL" ] && command -v mail &> /dev/null; then
        local subject="[Honeypot Alert] Health Check Failed - $ERROR_COUNT errors"
        local body="Health check completed with $ERROR_COUNT error(s).\n\nSee $LOG_FILE for details."

        echo -e "$body" | mail -s "$subject" "$ALERT_EMAIL"
        log "Alert email sent to $ALERT_EMAIL"
    fi
}

# Main health check routine
main() {
    log "========================================="
    log "Starting health check for IoT Honeypot"
    log "========================================="

    # Check Docker
    check_docker || true

    # Check all critical containers
    log ""
    log "Checking container status..."
    check_container "clickhouse" || true
    check_container "grafana" || true
    check_container "logstash" || true
    check_container "suricata" || true
    check_container "cowrie" || true
    check_container "zeek" || true

    # Check container health
    log ""
    log "Checking container health status..."
    check_container_health "clickhouse" || true
    check_container_health "grafana" || true
    check_container_health "logstash" || true

    # Check services
    log ""
    log "Checking service endpoints..."
    check_clickhouse || true
    check_grafana || true
    check_logstash || true

    # Check logs
    log ""
    log "Checking component logs..."
    check_suricata || true

    # Check system resources
    log ""
    log "Checking system resources..."
    check_disk_space || true

    # Check recent activity
    log ""
    log "Checking honeypot activity..."
    check_recent_events || true

    # Check for errors in logs (sample critical containers)
    log ""
    log "Scanning container logs for errors..."
    check_container_logs "logstash" || true
    check_container_logs "clickhouse" || true

    # Summary
    log ""
    log "========================================="
    if [ $ERROR_COUNT -eq 0 ]; then
        log_success "Health check completed: All systems operational"
        log "========================================="
        exit 0
    else
        log_error "Health check completed: $ERROR_COUNT issue(s) detected"
        log "========================================="

        # Send alert if configured
        send_alert

        exit 1
    fi
}

# Run main function
main "$@"
