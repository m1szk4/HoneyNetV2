FROM python:3.11-slim

LABEL maintainer="HoneyNetV2 Project"
LABEL description="UPnP Honeypot - Router/IoT Gateway Emulation with SSDP and SOAP"
LABEL version="1.0"

# Set working directory
WORKDIR /app

# Create log directory
RUN mkdir -p /var/log/upnp

# Copy honeypot application
COPY upnp_honeypot.py /app/

# Make script executable
RUN chmod +x /app/upnp_honeypot.py

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash upnp && \
    chown -R upnp:upnp /app /var/log/upnp

# Switch to non-root user
USER upnp

# Expose UPnP ports
EXPOSE 1900/udp
EXPOSE 5000/tcp

# Health check - verify HTTP server is responding
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import socket; s=socket.socket(); s.settimeout(2); s.connect(('localhost', 5000)); s.close()" || exit 1

# Run the honeypot
CMD ["python3", "-u", "/app/upnp_honeypot.py"]
