FROM python:3.11-slim

LABEL maintainer="HoneyNetV2 Project"
LABEL description="RTSP Honeypot - IoT Camera/DVR Emulation with CVE-2014-8361"
LABEL version="1.0"

# Set working directory
WORKDIR /app

# Create log directory
RUN mkdir -p /var/log/rtsp

# Copy honeypot application
COPY rtsp_honeypot.py /app/

# Make script executable
RUN chmod +x /app/rtsp_honeypot.py

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash rtsp && \
    chown -R rtsp:rtsp /app /var/log/rtsp

# Switch to non-root user
USER rtsp

# Expose RTSP port
EXPOSE 554/tcp

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import socket; s=socket.socket(); s.settimeout(2); s.connect(('localhost', 554)); s.close()" || exit 1

# Run the honeypot
CMD ["python3", "-u", "/app/rtsp_honeypot.py"]
