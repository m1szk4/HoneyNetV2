#!/bin/bash
# UPnP Honeypot Test Suite
# Tests SSDP discovery and SOAP port mapping functionality

set -e

# Configuration
HONEYPOT_IP="${HONEYPOT_IP:-172.20.0.14}"
SSDP_PORT=1900
HTTP_PORT=5000
SSDP_MCAST="239.255.255.250"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "=========================================="
echo "UPnP Honeypot Test Suite"
echo "=========================================="
echo "Target: $HONEYPOT_IP"
echo "SSDP Port: $SSDP_PORT"
echo "HTTP Port: $HTTP_PORT"
echo "=========================================="
echo ""

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

test_result() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}[PASS]${NC} $2"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "${RED}[FAIL]${NC} $2"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# Test 1: SSDP M-SEARCH discovery (unicast)
echo -e "${BLUE}Test 1: SSDP M-SEARCH Discovery (Unicast)${NC}"
echo "Sending M-SEARCH to $HONEYPOT_IP:$SSDP_PORT..."

MSEARCH_REQUEST="M-SEARCH * HTTP/1.1\r
HOST: $SSDP_MCAST:$SSDP_PORT\r
MAN: \"ssdp:discover\"\r
MX: 3\r
ST: ssdp:all\r
\r
"

# Send M-SEARCH and capture response
SSDP_RESPONSE=$(echo -ne "$MSEARCH_REQUEST" | nc -u -w 3 "$HONEYPOT_IP" "$SSDP_PORT" 2>/dev/null || echo "")

if echo "$SSDP_RESPONSE" | grep -q "LOCATION:"; then
    test_result 0 "SSDP M-SEARCH received valid response"
    echo "Response preview:"
    echo "$SSDP_RESPONSE" | head -5
    echo ""

    # Extract location URL
    LOCATION=$(echo "$SSDP_RESPONSE" | grep "LOCATION:" | cut -d' ' -f2 | tr -d '\r')
    echo "Device location: $LOCATION"
else
    test_result 1 "SSDP M-SEARCH no response received"
fi
echo ""

# Test 2: Device Description XML
echo -e "${BLUE}Test 2: Device Description XML${NC}"
echo "Fetching device description from http://$HONEYPOT_IP:$HTTP_PORT/description.xml..."

DESC_RESPONSE=$(curl -s -m 5 "http://$HONEYPOT_IP:$HTTP_PORT/description.xml" 2>/dev/null || echo "")

if echo "$DESC_RESPONSE" | grep -q "InternetGatewayDevice"; then
    test_result 0 "Device description XML retrieved successfully"
    echo "Device info:"
    echo "$DESC_RESPONSE" | grep -E "(friendlyName|manufacturer|modelName)" | sed 's/^/  /'
else
    test_result 1 "Failed to retrieve device description XML"
fi
echo ""

# Test 3: Service Description XML
echo -e "${BLUE}Test 3: Service Description XML${NC}"
echo "Fetching service description from http://$HONEYPOT_IP:$HTTP_PORT/WANIPConnection.xml..."

SERVICE_RESPONSE=$(curl -s -m 5 "http://$HONEYPOT_IP:$HTTP_PORT/WANIPConnection.xml" 2>/dev/null || echo "")

if echo "$SERVICE_RESPONSE" | grep -q "AddPortMapping"; then
    test_result 0 "Service description XML retrieved successfully"
    echo "Service includes AddPortMapping action"
else
    test_result 1 "Failed to retrieve service description XML"
fi
echo ""

# Test 4: SOAP AddPortMapping request
echo -e "${BLUE}Test 4: SOAP AddPortMapping Attack${NC}"
echo "Sending AddPortMapping SOAP request (simulated attack)..."

SOAP_REQUEST='<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewExternalPort>8080</NewExternalPort>
      <NewInternalPort>80</NewInternalPort>
      <NewInternalClient>192.168.1.100</NewInternalClient>
      <NewProtocol>TCP</NewProtocol>
      <NewPortMappingDescription>Test Mapping</NewPortMappingDescription>
      <NewLeaseDuration>0</NewLeaseDuration>
    </u:AddPortMapping>
  </s:Body>
</s:Envelope>'

SOAP_RESPONSE=$(curl -s -m 5 \
    -X POST \
    -H "Content-Type: text/xml; charset=utf-8" \
    -H "SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"" \
    -d "$SOAP_REQUEST" \
    "http://$HONEYPOT_IP:$HTTP_PORT/ctl/IPConn" 2>/dev/null || echo "")

if echo "$SOAP_RESPONSE" | grep -q "AddPortMappingResponse"; then
    test_result 0 "SOAP AddPortMapping received successful response"
    echo "Honeypot accepted port mapping request (logged as attack)"
else
    test_result 1 "SOAP AddPortMapping request failed"
fi
echo ""

# Test 5: SOAP GetExternalIPAddress request
echo -e "${BLUE}Test 5: SOAP GetExternalIPAddress${NC}"
echo "Sending GetExternalIPAddress SOAP request..."

SOAP_GET_IP='<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:GetExternalIPAddress xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
    </u:GetExternalIPAddress>
  </s:Body>
</s:Envelope>'

SOAP_IP_RESPONSE=$(curl -s -m 5 \
    -X POST \
    -H "Content-Type: text/xml; charset=utf-8" \
    -H "SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress\"" \
    -d "$SOAP_GET_IP" \
    "http://$HONEYPOT_IP:$HTTP_PORT/ctl/IPConn" 2>/dev/null || echo "")

if echo "$SOAP_IP_RESPONSE" | grep -q "GetExternalIPAddressResponse"; then
    test_result 0 "SOAP GetExternalIPAddress received response"
    EXTERNAL_IP=$(echo "$SOAP_IP_RESPONSE" | grep -oP '(?<=<NewExternalIPAddress>)[^<]+' || echo "unknown")
    echo "External IP returned: $EXTERNAL_IP"
else
    test_result 1 "SOAP GetExternalIPAddress request failed"
fi
echo ""

# Test 6: nmap UPnP discovery (if nmap is available)
if command -v nmap &> /dev/null; then
    echo -e "${BLUE}Test 6: nmap UPnP Discovery${NC}"
    echo "Running: nmap -sU -p $SSDP_PORT --script=broadcast-upnp-info $HONEYPOT_IP"

    NMAP_OUTPUT=$(nmap -sU -p "$SSDP_PORT" --script=broadcast-upnp-info "$HONEYPOT_IP" 2>/dev/null || echo "")

    if echo "$NMAP_OUTPUT" | grep -q "upnp-info"; then
        test_result 0 "nmap UPnP discovery successful"
        echo "$NMAP_OUTPUT" | grep -A 10 "upnp-info"
    else
        test_result 1 "nmap UPnP discovery failed"
    fi
    echo ""
else
    echo -e "${YELLOW}[SKIP]${NC} Test 6: nmap not available"
    echo ""
fi

# Test 7: Check honeypot logs
echo -e "${BLUE}Test 7: Verify Honeypot Logs${NC}"
LOG_FILE="../data/upnp/upnp.json"

if [ -f "$LOG_FILE" ]; then
    LOG_COUNT=$(wc -l < "$LOG_FILE")
    if [ "$LOG_COUNT" -gt 0 ]; then
        test_result 0 "Honeypot logs created ($LOG_COUNT events)"
        echo "Recent log entries:"
        tail -3 "$LOG_FILE" | jq -r '.event_type' 2>/dev/null | sed 's/^/  - /' || tail -3 "$LOG_FILE"
    else
        test_result 1 "Honeypot logs empty"
    fi
else
    test_result 1 "Honeypot log file not found at $LOG_FILE"
fi
echo ""

# Test 8: Check for attack detection in logs
echo -e "${BLUE}Test 8: Verify Attack Detection in Logs${NC}"

if [ -f "$LOG_FILE" ]; then
    ATTACK_COUNT=$(grep -c '"attack_detected":true' "$LOG_FILE" 2>/dev/null || echo "0")

    if [ "$ATTACK_COUNT" -gt 0 ]; then
        test_result 0 "Attack detection logged ($ATTACK_COUNT attacks detected)"
        echo "Attack types:"
        grep '"attack_type"' "$LOG_FILE" | jq -r '.attack_type' 2>/dev/null | sort | uniq -c | sed 's/^/  /'
    else
        test_result 1 "No attacks detected in logs"
    fi
else
    test_result 1 "Cannot check attack logs (file not found)"
fi
echo ""

# Test 9: Multiple M-SEARCH requests (SSDP scan simulation)
echo -e "${BLUE}Test 9: SSDP Scan Simulation (20+ requests)${NC}"
echo "Sending 25 M-SEARCH requests to trigger Suricata threshold..."

for i in {1..25}; do
    echo -ne "$MSEARCH_REQUEST" | nc -u -w 1 "$HONEYPOT_IP" "$SSDP_PORT" > /dev/null 2>&1 &
done

wait
test_result 0 "Sent 25 M-SEARCH requests (should trigger Suricata SID 2000016)"
echo "Check Suricata logs for alert: 'IoT UPnP SSDP scan - M-SEARCH discovery'"
echo ""

# Summary
echo "=========================================="
echo -e "${GREEN}Tests Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Tests Failed: $TESTS_FAILED${NC}"
echo "=========================================="

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed.${NC}"
    exit 1
fi
