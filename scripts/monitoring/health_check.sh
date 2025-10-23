#!/bin/bash
# HoneyNetV2 Health Check Script
# Checks the health status of all services

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "======================================================================"
echo "HoneyNetV2 Health Check"
echo "======================================================================"
echo "Timestamp: $(date)"
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}✗ Docker is not running${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Docker is running${NC}"

# Check container status
echo ""
echo "Container Status:"
echo "----------------------------------------------------------------------"

containers=(
    "honeynet-cowrie"
    "honeynet-dionaea"
    "honeynet-conpot"
    "honeynet-suricata"
    "honeynet-zeek"
    "honeynet-clickhouse"
    "honeynet-logstash"
    "honeynet-grafana"
    "honeynet-jupyter"
)

all_healthy=true

for container in "${containers[@]}"; do
    if docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
        status=$(docker inspect --format='{{.State.Status}}' "$container")
        if [ "$status" == "running" ]; then
            echo -e "  ${GREEN}✓${NC} $container: running"
        else
            echo -e "  ${RED}✗${NC} $container: $status"
            all_healthy=false
        fi
    else
        echo -e "  ${RED}✗${NC} $container: not found"
        all_healthy=false
    fi
done

# Check resource usage
echo ""
echo "Resource Usage:"
echo "----------------------------------------------------------------------"
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}" ${containers[@]} 2>/dev/null || true

# Check disk usage
echo ""
echo "Disk Usage:"
echo "----------------------------------------------------------------------"
df -h | grep -E "Filesystem|/$" || true

# Check data directory sizes
echo ""
echo "Data Directory Sizes:"
echo "----------------------------------------------------------------------"
du -sh data/* 2>/dev/null || echo "  No data directories found"

# Check recent logs for errors
echo ""
echo "Recent Critical Errors (last 100 lines):"
echo "----------------------------------------------------------------------"
error_count=0
for container in "${containers[@]}"; do
    if docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
        errors=$(docker logs --tail 100 "$container" 2>&1 | grep -i "error\|fatal\|critical" | wc -l)
        if [ "$errors" -gt 0 ]; then
            echo "  $container: $errors error(s) found"
            error_count=$((error_count + errors))
        fi
    fi
done

if [ $error_count -eq 0 ]; then
    echo -e "  ${GREEN}No critical errors found${NC}"
else
    echo -e "  ${YELLOW}Found $error_count error message(s)${NC}"
fi

# Check ClickHouse connectivity
echo ""
echo "Service Connectivity:"
echo "----------------------------------------------------------------------"

# ClickHouse HTTP
if curl -s http://localhost:8123/ping > /dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} ClickHouse HTTP (8123): accessible"
else
    echo -e "  ${RED}✗${NC} ClickHouse HTTP (8123): not accessible"
    all_healthy=false
fi

# Grafana
if curl -s http://localhost:3000/api/health > /dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} Grafana (3000): accessible"
else
    echo -e "  ${RED}✗${NC} Grafana (3000): not accessible"
    all_healthy=false
fi

# Jupyter
if curl -s http://localhost:8888 > /dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} Jupyter (8888): accessible"
else
    echo -e "  ${YELLOW}⚠${NC} Jupyter (8888): not accessible (may require token)"
fi

# Summary
echo ""
echo "======================================================================"
if $all_healthy; then
    echo -e "${GREEN}✓ All systems healthy${NC}"
    exit 0
else
    echo -e "${RED}✗ Some systems unhealthy - check logs${NC}"
    exit 1
fi
