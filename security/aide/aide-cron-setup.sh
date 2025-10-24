#!/bin/bash
##############################################################################
# AIDE Cron Job Setup Script for HoneyNetV2
#
# This script configures automated daily AIDE integrity checks with
# flexible notification options (email, log file, or Discord webhook).
#
# Usage: sudo ./aide-cron-setup.sh
##############################################################################

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root (use sudo)"
    exit 1
fi

echo "========================================================================"
log_info "AIDE Cron Job Configuration for HoneyNetV2"
echo "========================================================================"
echo ""

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Verify AIDE is installed
if ! command -v aide &> /dev/null; then
    log_error "AIDE is not installed. Please run aide-init.sh first."
    exit 1
fi

# Verify AIDE database exists
if [ ! -f /var/lib/aide/aide.db ]; then
    log_error "AIDE database not found. Please run aide-init.sh first."
    exit 1
fi

echo "Select notification method for AIDE reports:"
echo "  1) Email (requires configured SMTP)"
echo "  2) Log file only (save to /var/log/aide/)"
echo "  3) Discord webhook"
echo "  4) Multiple methods (email + Discord)"
echo ""
read -p "Enter choice [1-4]: " NOTIFY_CHOICE

# Variables for notification
EMAIL_ENABLED=false
DISCORD_ENABLED=false
EMAIL_ADDRESS=""
DISCORD_WEBHOOK=""

case $NOTIFY_CHOICE in
    1)
        EMAIL_ENABLED=true
        read -p "Enter administrator email address: " EMAIL_ADDRESS

        # Verify mail command exists
        if ! command -v mail &> /dev/null && ! command -v sendmail &> /dev/null; then
            log_warn "Mail command not found. Installing mailutils..."
            apt-get install -y mailutils
        fi

        log_info "Email notifications will be sent to: $EMAIL_ADDRESS"
        ;;
    2)
        log_info "Reports will be saved to /var/log/aide/ only"
        ;;
    3)
        DISCORD_ENABLED=true
        read -p "Enter Discord webhook URL: " DISCORD_WEBHOOK
        log_info "Discord notifications configured"
        ;;
    4)
        EMAIL_ENABLED=true
        DISCORD_ENABLED=true
        read -p "Enter administrator email address: " EMAIL_ADDRESS
        read -p "Enter Discord webhook URL: " DISCORD_WEBHOOK

        if ! command -v mail &> /dev/null && ! command -v sendmail &> /dev/null; then
            log_warn "Mail command not found. Installing mailutils..."
            apt-get install -y mailutils
        fi

        log_info "Email notifications will be sent to: $EMAIL_ADDRESS"
        log_info "Discord notifications configured"
        ;;
    *)
        log_error "Invalid choice"
        exit 1
        ;;
esac

echo ""
read -p "Enter cron schedule (default: 0 2 * * * for 2:00 AM daily): " CRON_SCHEDULE
if [ -z "$CRON_SCHEDULE" ]; then
    CRON_SCHEDULE="0 2 * * *"
fi

log_info "Cron schedule set to: $CRON_SCHEDULE"

# Create the AIDE check script
AIDE_CHECK_SCRIPT="/usr/local/bin/aide-check.sh"

log_info "Creating AIDE check script: $AIDE_CHECK_SCRIPT"

cat > "$AIDE_CHECK_SCRIPT" << 'EOF'
#!/bin/bash
##############################################################################
# AIDE Automated Check Script
# This script runs AIDE integrity checks and sends notifications
##############################################################################

# Configuration (will be replaced by setup script)
EMAIL_ENABLED=__EMAIL_ENABLED__
DISCORD_ENABLED=__DISCORD_ENABLED__
EMAIL_ADDRESS="__EMAIL_ADDRESS__"
DISCORD_WEBHOOK="__DISCORD_WEBHOOK__"

# Paths
AIDE_LOG="/var/log/aide/aide-check-$(date +%Y%m%d_%H%M%S).log"
AIDE_REPORT="/tmp/aide-report-$$.txt"

# Run AIDE check
echo "Running AIDE integrity check at $(date)" > "$AIDE_REPORT"
echo "========================================" >> "$AIDE_REPORT"
echo "" >> "$AIDE_REPORT"

aide --check >> "$AIDE_REPORT" 2>&1
AIDE_STATUS=$?

# Save to log file
cp "$AIDE_REPORT" "$AIDE_LOG"

# Determine if changes were detected
if [ $AIDE_STATUS -eq 0 ]; then
    SUBJECT="AIDE Report: No Changes Detected"
    DISCORD_COLOR="3066993"  # Green
    CHANGES_DETECTED=false
else
    SUBJECT="AIDE ALERT: Changes Detected!"
    DISCORD_COLOR="15158332"  # Red
    CHANGES_DETECTED=true
fi

# Email notification
if [ "$EMAIL_ENABLED" = "true" ] && [ -n "$EMAIL_ADDRESS" ]; then
    if command -v mail &> /dev/null; then
        cat "$AIDE_REPORT" | mail -s "$SUBJECT - HoneyNetV2" "$EMAIL_ADDRESS"
    elif command -v sendmail &> /dev/null; then
        {
            echo "To: $EMAIL_ADDRESS"
            echo "Subject: $SUBJECT - HoneyNetV2"
            echo ""
            cat "$AIDE_REPORT"
        } | sendmail "$EMAIL_ADDRESS"
    fi
fi

# Discord notification
if [ "$DISCORD_ENABLED" = "true" ] && [ -n "$DISCORD_WEBHOOK" ]; then
    # Extract summary from AIDE report
    SUMMARY=$(grep -A 20 "^Summary:" "$AIDE_REPORT" | head -20 | sed 's/"/\\"/g')

    # Create Discord embed
    DISCORD_PAYLOAD=$(cat <<DISCORD_EOF
{
  "embeds": [{
    "title": "$SUBJECT",
    "description": "AIDE integrity check completed on HoneyNetV2 host",
    "color": $DISCORD_COLOR,
    "fields": [
      {
        "name": "Status",
        "value": "$([ "$CHANGES_DETECTED" = "true" ] && echo "Changes Detected ⚠️" || echo "No Changes ✅")",
        "inline": true
      },
      {
        "name": "Timestamp",
        "value": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
        "inline": true
      },
      {
        "name": "Log File",
        "value": "$AIDE_LOG",
        "inline": false
      }
    ],
    "footer": {
      "text": "HoneyNetV2 AIDE Monitor"
    }
  }]
}
DISCORD_EOF
)

    curl -H "Content-Type: application/json" \
         -d "$DISCORD_PAYLOAD" \
         "$DISCORD_WEBHOOK" &> /dev/null
fi

# Cleanup temporary report
rm -f "$AIDE_REPORT"

exit $AIDE_STATUS
EOF

# Replace placeholders in the script
sed -i "s|__EMAIL_ENABLED__|$EMAIL_ENABLED|g" "$AIDE_CHECK_SCRIPT"
sed -i "s|__DISCORD_ENABLED__|$DISCORD_ENABLED|g" "$AIDE_CHECK_SCRIPT"
sed -i "s|__EMAIL_ADDRESS__|$EMAIL_ADDRESS|g" "$AIDE_CHECK_SCRIPT"
sed -i "s|__DISCORD_WEBHOOK__|$DISCORD_WEBHOOK|g" "$AIDE_CHECK_SCRIPT"

# Make script executable
chmod 755 "$AIDE_CHECK_SCRIPT"

log_info "AIDE check script created successfully"

# Create cron job
CRON_JOB="$CRON_SCHEDULE $AIDE_CHECK_SCRIPT"
CRON_FILE="/etc/cron.d/aide-honeynet"

log_info "Creating cron job in $CRON_FILE"

cat > "$CRON_FILE" << EOF
# AIDE Integrity Check for HoneyNetV2
# This cron job runs automated integrity checks
# Generated on $(date)

SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Run AIDE check
$CRON_JOB

EOF

chmod 644 "$CRON_FILE"

log_info "Cron job installed successfully"

# Test the check script
echo ""
log_info "Testing AIDE check script..."
read -p "Do you want to run a test check now? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    log_info "Running test check..."
    $AIDE_CHECK_SCRIPT
    log_info "Test check completed. Check your notification method for results."
fi

echo ""
echo "========================================================================"
log_info "AIDE cron job configuration completed!"
echo "========================================================================"
echo ""
echo "Configuration summary:"
echo "  - Schedule: $CRON_SCHEDULE"
echo "  - Check script: $AIDE_CHECK_SCRIPT"
echo "  - Cron file: $CRON_FILE"
echo "  - Log directory: /var/log/aide/"
if [ "$EMAIL_ENABLED" = "true" ]; then
    echo "  - Email notifications: $EMAIL_ADDRESS"
fi
if [ "$DISCORD_ENABLED" = "true" ]; then
    echo "  - Discord notifications: Enabled"
fi
echo ""
echo "You can manually run checks at any time with: sudo $AIDE_CHECK_SCRIPT"
echo ""
