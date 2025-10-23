#!/bin/bash
# HoneyNetV2 Deployment Script
# Automates the deployment of the entire honeypot infrastructure

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "======================================================================"
echo "HoneyNetV2 Deployment Script"
echo "======================================================================"

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo -e "${YELLOW}Warning: Running as root. Consider using a non-root user with sudo.${NC}"
fi

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed${NC}"
    echo "Please install Docker first or run the Ansible playbook:"
    echo "  ansible-playbook -i ansible/inventory/hosts.ini ansible/playbooks/01-docker-install.yml"
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}Error: Docker Compose is not installed${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Docker and Docker Compose are installed${NC}"

# Check if .env file exists
if [ ! -f .env ]; then
    echo -e "${YELLOW}Warning: .env file not found${NC}"
    echo "Creating .env from .env.example..."
    cp .env.example .env
    echo -e "${YELLOW}Please edit .env and configure your settings before continuing!${NC}"
    echo "Press Enter to continue or Ctrl+C to abort..."
    read
fi

echo -e "${GREEN}✓ .env file exists${NC}"

# Create data directories if they don't exist
echo "Creating data directories..."
mkdir -p data/{cowrie,dionaea,conpot,suricata,zeek,clickhouse,grafana,logstash}

echo -e "${GREEN}✓ Data directories created${NC}"

# Pull Docker images
echo "Pulling Docker images (this may take a while)..."
docker-compose pull

echo -e "${GREEN}✓ Docker images pulled${NC}"

# Start services
echo "Starting HoneyNet services..."
docker-compose up -d

echo -e "${GREEN}✓ Services started${NC}"

# Wait for services to be healthy
echo "Waiting for services to become healthy (30 seconds)..."
sleep 30

# Check container status
echo ""
echo "Container Status:"
docker-compose ps

# Run tests
echo ""
echo "======================================================================"
echo "Running Tests"
echo "======================================================================"

# Test port accessibility
if [ -x tests/test_ports.py ]; then
    echo ""
    echo "Running port accessibility test..."
    python3 tests/test_ports.py
else
    echo -e "${YELLOW}Warning: test_ports.py not found or not executable${NC}"
fi

# Test isolation
if [ -x tests/test_isolation.py ]; then
    echo ""
    echo "Running isolation test..."
    python3 tests/test_isolation.py
else
    echo -e "${YELLOW}Warning: test_isolation.py not found or not executable${NC}"
fi

# Print access information
echo ""
echo "======================================================================"
echo "Deployment Complete!"
echo "======================================================================"
echo ""
echo "Access Information:"
echo "  Grafana:    http://localhost:3000 (admin/admin)"
echo "  Jupyter:    http://localhost:8888 (token from .env)"
echo "  ClickHouse: http://localhost:8123"
echo ""
echo "Next steps:"
echo "  1. Access Grafana and explore dashboards"
echo "  2. Monitor honeypot activity: docker-compose logs -f cowrie dionaea conpot"
echo "  3. View IDS alerts: docker-compose logs -f suricata zeek"
echo "  4. Run analytics in Jupyter notebooks"
echo ""
echo "Useful commands:"
echo "  docker-compose logs -f <service>  # View logs"
echo "  docker-compose restart <service>  # Restart service"
echo "  docker-compose down               # Stop all services"
echo "  docker-compose ps                 # Check status"
echo ""
