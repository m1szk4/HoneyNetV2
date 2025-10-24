#!/bin/bash
################################################################################
# HoneyNetV2 - Discord Alert Testing Script
#
# Description:
#   Simulates various attack scenarios to test Discord alerting integration.
#   Generates traffic and inserts test data to trigger alert rules.
#
# Usage:
#   ./test_discord_alerts.sh [test_type]
#
# Test Types:
#   all              - Run all alert tests sequentially
#   suricata         - Trigger Suricata high alert rate (>1000/min)
#   connections      - Trigger honeypot connection spike (>500/min)
#   brute-force      - Trigger SSH brute force alert (>50 attempts)
#   malware          - Simulate malware capture
#   ics-attack       - Simulate ICS/SCADA attack
#   pipeline-lag     - Simulate log processing lag
#   test-webhook     - Send test message directly to Discord webhook
#
# Requirements:
#   - Docker and docker-compose installed
#   - HoneyNetV2 stack running
#   - Discord webhooks configured in .env
#
# Examples:
#   ./test_discord_alerts.sh all
#   ./test_discord_alerts.sh suricata
#   ./test_discord_alerts.sh test-webhook
#
################################################################################

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ENV_FILE="$PROJECT_ROOT/.env"

# Load environment variables
if [[ -f "$ENV_FILE" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
else
    echo -e "${RED}Error: .env file not found at $ENV_FILE${NC}"
    echo "Please copy .env.example to .env and configure it."
    exit 1
fi

# Functions
print_header() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

check_prerequisites() {
    print_header "Checking Prerequisites"

    # Check Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed"
        exit 1
    fi
    print_success "Docker is installed"

    # Check docker-compose
    if ! command -v docker-compose &> /dev/null; then
        print_error "docker-compose is not installed"
        exit 1
    fi
    print_success "docker-compose is installed"

    # Check if containers are running
    if ! docker-compose -f "$PROJECT_ROOT/docker-compose.yml" ps | grep -q "Up"; then
        print_error "HoneyNetV2 containers are not running"
        print_info "Start the stack with: docker-compose up -d"
        exit 1
    fi
    print_success "HoneyNetV2 stack is running"

    # Check webhook configuration
    if [[ -z "${DISCORD_WEBHOOK_URL:-}" ]]; then
        print_warning "DISCORD_WEBHOOK_URL is not configured in .env"
        print_info "Some tests will be limited without webhook configuration"
    else
        print_success "Discord webhook is configured"
    fi
}

test_webhook_direct() {
    print_header "Testing Discord Webhook (Direct)"

    if [[ -z "${DISCORD_WEBHOOK_URL:-}" ]]; then
        print_error "DISCORD_WEBHOOK_URL not configured"
        return 1
    fi

    print_info "Sending test message to Discord..."

    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S %Z')

    local payload
    payload=$(cat <<EOF
{
  "content": "**HoneyNetV2 Alert Test**",
  "embeds": [{
    "title": "🧪 Test Alert - System Check",
    "description": "This is a test message from the HoneyNetV2 alerting system.",
    "color": 3447003,
    "fields": [
      {
        "name": "Test Type",
        "value": "Webhook Direct Test",
        "inline": true
      },
      {
        "name": "Status",
        "value": "✅ Operational",
        "inline": true
      },
      {
        "name": "Timestamp",
        "value": "$timestamp",
        "inline": false
      }
    ],
    "footer": {
      "text": "HoneyNetV2 Testing Framework"
    }
  }]
}
EOF
)

    if curl -s -X POST "$DISCORD_WEBHOOK_URL" \
        -H "Content-Type: application/json" \
        -d "$payload" > /dev/null; then
        print_success "Test message sent to Discord"
        print_info "Check your Discord channel for the test alert"
        return 0
    else
        print_error "Failed to send test message"
        return 1
    fi
}

test_suricata_high_alert_rate() {
    print_header "Testing Suricata High Alert Rate Alert"

    print_info "This test generates 1500 connections to trigger >1000 alerts/min"
    print_info "Alert should fire after ~2 minutes of sustained rate"

    # Generate test traffic
    print_info "Generating test traffic to honeypots..."

    local count=0
    local total=1500

    for i in $(seq 1 $total); do
        # SSH honeypot (Cowrie)
        timeout 0.5 nc -z localhost 22 &> /dev/null &

        # HTTP honeypot (Dionaea)
        timeout 0.5 curl -s http://localhost:80 &> /dev/null &

        # Telnet honeypot
        timeout 0.5 nc -z localhost 23 &> /dev/null &

        count=$((count + 1))

        # Progress indicator
        if ((count % 100 == 0)); then
            echo -ne "\rProgress: $count/$total connections"
        fi

        # Rate limiting - don't overwhelm the system
        if ((i % 50 == 0)); then
            sleep 0.1
        fi
    done

    echo -e "\n"
    print_success "Generated $total test connections"

    print_warning "Alert evaluation time: ~2-3 minutes"
    print_info "Monitor your Discord channel for the alert"
    print_info "You can also check Grafana: http://localhost:3000/alerting/list"
}

test_honeypot_connection_spike() {
    print_header "Testing Honeypot Connection Spike Alert"

    print_info "This test generates 800 connections to trigger >500/min threshold"
    print_info "Alert should fire after ~3 minutes of sustained rate"

    print_info "Inserting test connection data into ClickHouse..."

    # Generate SQL to insert test data
    local sql="INSERT INTO cowrie_sessions (timestamp, session_id, src_ip, src_port, dst_port, username, success) VALUES "

    for i in $(seq 1 600); do
        local timestamp
        timestamp=$(date -u -d "-$((i % 60)) seconds" '+%Y-%m-%d %H:%M:%S')
        local src_ip="192.0.2.$((RANDOM % 255))"
        local src_port=$((30000 + RANDOM % 10000))
        sql+="('$timestamp', 'test-$RANDOM', '$src_ip', $src_port, 22, 'test', 0)"

        if [[ $i -lt 600 ]]; then
            sql+=", "
        fi
    done

    if docker-compose -f "$PROJECT_ROOT/docker-compose.yml" exec -T clickhouse \
        clickhouse-client --query "$sql" 2>/dev/null; then
        print_success "Inserted 600 test connection records"
    else
        print_warning "Failed to insert test data (table may not exist yet)"
        print_info "Falling back to live connection generation..."

        # Fallback: generate real connections
        for i in $(seq 1 800); do
            timeout 0.5 nc -z localhost 22 &> /dev/null &
            timeout 0.5 nc -z localhost 80 &> /dev/null &

            if ((i % 100 == 0)); then
                echo -ne "\rProgress: $i/800 connections"
            fi

            if ((i % 50 == 0)); then
                sleep 0.1
            fi
        done
        echo -e "\n"
        print_success "Generated 800 test connections"
    fi

    print_warning "Alert evaluation time: ~3-4 minutes"
    print_info "Monitor your Discord channel for the alert"
}

test_brute_force_attack() {
    print_header "Testing SSH Brute Force Attack Alert"

    print_info "This test generates 60 failed SSH authentication attempts"
    print_info "Alert should fire after ~5 minutes of sustained attempts"

    # Check if sshpass is available
    if ! command -v sshpass &> /dev/null; then
        print_warning "sshpass not installed, inserting test data directly"

        # Insert test data into ClickHouse
        local sql="INSERT INTO cowrie_auth (timestamp, session_id, src_ip, username, password, success) VALUES "

        local test_ip="198.51.100.42"
        for i in $(seq 1 60); do
            local timestamp
            timestamp=$(date -u -d "-$((600 - i * 10)) seconds" '+%Y-%m-%d %H:%M:%S')
            sql+="('$timestamp', 'brute-$i', '$test_ip', 'admin', 'password$i', 0)"

            if [[ $i -lt 60 ]]; then
                sql+=", "
            fi
        done

        if docker-compose -f "$PROJECT_ROOT/docker-compose.yml" exec -T clickhouse \
            clickhouse-client --query "$sql" 2>/dev/null; then
            print_success "Inserted 60 failed authentication attempts from $test_ip"
        else
            print_error "Failed to insert test data (table may not exist yet)"
            print_info "Please run the system for a while to create tables"
            return 1
        fi
    else
        print_info "Generating real SSH brute force attempts..."

        for i in $(seq 1 60); do
            sshpass -p "test_password_$i" ssh -o StrictHostKeyChecking=no \
                -o UserKnownHostsFile=/dev/null \
                -o ConnectTimeout=1 \
                test_user@localhost -p 22 &> /dev/null &

            if ((i % 10 == 0)); then
                echo -ne "\rProgress: $i/60 attempts"
                sleep 1  # Spread attempts over time
            fi
        done
        echo -e "\n"
        print_success "Generated 60 SSH brute force attempts"
    fi

    print_warning "Alert evaluation time: ~5-6 minutes"
    print_info "Monitor your Discord channel for the alert"
}

test_malware_capture() {
    print_header "Testing Malware Capture Alert"

    print_info "This test simulates malware binary capture by Dionaea"
    print_info "Alert should fire after ~1 minute"

    print_info "Inserting test malware capture data..."

    local md5hash
    md5hash=$(echo "test_malware_$RANDOM" | md5sum | cut -d' ' -f1)
    local timestamp
    timestamp=$(date -u '+%Y-%m-%d %H:%M:%S')

    local sql="INSERT INTO dionaea_binaries (timestamp, md5, sha256, url, src_ip) VALUES "
    sql+="('$timestamp', '$md5hash', '$(echo "test_$md5hash" | sha256sum | cut -d' ' -f1)', "
    sql+="'http://test.example.com/malware.exe', '203.0.113.10')"

    if docker-compose -f "$PROJECT_ROOT/docker-compose.yml" exec -T clickhouse \
        clickhouse-client --query "$sql" 2>/dev/null; then
        print_success "Inserted test malware capture record"
        print_success "MD5: $md5hash"
    else
        print_error "Failed to insert test data (table may not exist yet)"
        print_info "Please run the system for a while to create tables"
        return 1
    fi

    print_warning "Alert evaluation time: ~1-2 minutes"
    print_info "Monitor your Discord channel for the alert"
}

test_ics_attack() {
    print_header "Testing ICS/SCADA Attack Alert"

    print_info "This test simulates 15 ICS protocol command/write operations"
    print_info "Alert should fire after ~5 minutes"

    print_info "Inserting test ICS attack data..."

    local sql="INSERT INTO conpot_events (timestamp, src_ip, protocol, event_type, data) VALUES "

    local protocols=("modbus" "s7comm" "bacnet" "ipmi")
    local event_types=("write" "command" "write" "command")

    for i in $(seq 1 15); do
        local timestamp
        timestamp=$(date -u -d "-$((i * 30)) seconds" '+%Y-%m-%d %H:%M:%S')
        local src_ip="198.51.100.$((50 + RANDOM % 50))"
        local protocol="${protocols[$((RANDOM % ${#protocols[@]}))]}"
        local event_type="${event_types[$((RANDOM % ${#event_types[@]}))]}"

        sql+="('$timestamp', '$src_ip', '$protocol', '$event_type', 'test_data_$i')"

        if [[ $i -lt 15 ]]; then
            sql+=", "
        fi
    done

    if docker-compose -f "$PROJECT_ROOT/docker-compose.yml" exec -T clickhouse \
        clickhouse-client --query "$sql" 2>/dev/null; then
        print_success "Inserted 15 ICS attack event records"
    else
        print_error "Failed to insert test data (table may not exist yet)"
        print_info "Please run the system for a while to create tables"
        return 1
    fi

    print_warning "Alert evaluation time: ~5-6 minutes"
    print_info "Monitor your Discord channel for the alert"
}

test_pipeline_lag() {
    print_header "Testing Log Processing Pipeline Lag Alert"

    print_info "This alert is difficult to test without actually stopping Logstash"
    print_warning "To trigger this alert naturally:"
    echo "  1. Stop Logstash: docker-compose stop logstash"
    echo "  2. Wait 5 minutes for logs to age"
    echo "  3. Alert should fire when lag exceeds 5 minutes"
    echo "  4. Restart Logstash: docker-compose start logstash"

    print_info "Skipping automated test for this alert"
}

run_all_tests() {
    print_header "Running All Alert Tests"

    print_info "This will run all alert tests sequentially"
    print_warning "Total estimated time: 20-30 minutes"

    read -p "Continue? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Tests cancelled"
        return 0
    fi

    # Run tests with delays between them
    test_webhook_direct
    sleep 5

    test_suricata_high_alert_rate
    print_info "Waiting 3 minutes for alert to fire..."
    sleep 180

    test_honeypot_connection_spike
    print_info "Waiting 4 minutes for alert to fire..."
    sleep 240

    test_brute_force_attack
    print_info "Waiting 6 minutes for alert to fire..."
    sleep 360

    test_malware_capture
    print_info "Waiting 2 minutes for alert to fire..."
    sleep 120

    test_ics_attack
    print_info "Waiting 6 minutes for alert to fire..."
    sleep 360

    print_success "All tests completed!"
    print_info "Check your Discord channel for alerts"
    print_info "Check Grafana for alert status: http://localhost:3000/alerting/list"
}

show_usage() {
    cat <<EOF
Usage: $(basename "$0") [test_type]

Test Types:
  all              Run all alert tests sequentially
  suricata         Trigger Suricata high alert rate (>1000/min)
  connections      Trigger honeypot connection spike (>500/min)
  brute-force      Trigger SSH brute force alert (>50 attempts)
  malware          Simulate malware capture
  ics-attack       Simulate ICS/SCADA attack
  pipeline-lag     Show instructions for pipeline lag test
  test-webhook     Send test message directly to Discord webhook
  help             Show this help message

Examples:
  $(basename "$0") all
  $(basename "$0") suricata
  $(basename "$0") test-webhook

For more information, see: docs/DISCORD_ALERTING.md
EOF
}

# Main script
main() {
    local test_type="${1:-}"

    if [[ -z "$test_type" ]] || [[ "$test_type" == "help" ]]; then
        show_usage
        exit 0
    fi

    print_header "HoneyNetV2 Discord Alert Testing"
    print_info "Test Type: $test_type"

    check_prerequisites

    case "$test_type" in
        all)
            run_all_tests
            ;;
        suricata)
            test_suricata_high_alert_rate
            ;;
        connections)
            test_honeypot_connection_spike
            ;;
        brute-force)
            test_brute_force_attack
            ;;
        malware)
            test_malware_capture
            ;;
        ics-attack)
            test_ics_attack
            ;;
        pipeline-lag)
            test_pipeline_lag
            ;;
        test-webhook)
            test_webhook_direct
            ;;
        *)
            print_error "Unknown test type: $test_type"
            echo
            show_usage
            exit 1
            ;;
    esac

    print_success "Test execution completed"
    print_info "Monitor Discord channel and Grafana for alerts"
}

# Run main function
main "$@"
