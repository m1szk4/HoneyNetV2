#!/bin/bash
# Quick test for CVE-2014-8361 RTSP buffer overflow
# This script sends a DESCRIBE request with abnormally long Authorization header

HOST="${1:-localhost}"
PORT="${2:-554}"

echo "=================================================="
echo "CVE-2014-8361 RTSP Buffer Overflow Test"
echo "=================================================="
echo "Target: $HOST:$PORT"
echo ""

# Generate overflow payload (2048 bytes)
OVERFLOW=$(python3 -c "print('A' * 2048)")

echo "[*] Generating malicious RTSP request..."
echo "[*] Authorization header size: 2048 bytes (threshold: 1024)"
echo ""

# Send malicious DESCRIBE request
echo "[*] Sending DESCRIBE with long Authorization header..."
echo ""

RESPONSE=$(cat <<EOF | nc -w 5 $HOST $PORT
DESCRIBE rtsp://$HOST:$PORT/stream RTSP/1.0
CSeq: 2
Authorization: Basic $OVERFLOW

EOF
)

if [ -z "$RESPONSE" ]; then
    echo "[✗] No response received (honeypot might have crashed or be offline)"
    exit 1
else
    echo "[✓] Response received:"
    echo "---"
    echo "$RESPONSE"
    echo "---"
    echo ""
    echo "[✓] Connection remained open (honeypot did not crash)"
    echo ""
fi

echo "[*] Testing if connection is still functional..."
echo ""

# Send normal OPTIONS to verify connection is still alive
RESPONSE2=$(cat <<EOF | nc -w 5 $HOST $PORT
OPTIONS * RTSP/1.0
CSeq: 3

EOF
)

if [ -z "$RESPONSE2" ]; then
    echo "[✗] No response to OPTIONS (connection might be broken)"
    exit 1
else
    echo "[✓] Connection still functional after overflow attempt"
    echo "---"
    echo "$RESPONSE2"
    echo "---"
    echo ""
fi

echo "=================================================="
echo "CVE-2014-8361 Test Complete"
echo "=================================================="
echo ""
echo "[✓] Honeypot successfully simulated CVE-2014-8361"
echo "[*] Check Suricata logs for alert SID 2000015"
echo "[*] Check honeypot logs: ./data/rtsp/rtsp.json"
echo ""
echo "Expected Suricata alert:"
echo "  msg: \"IoT RTSP exploit - CVE-2014-8361 buffer overflow attempt\""
echo "  sid: 2000015"
echo "  classification: attempted-admin"
echo ""
