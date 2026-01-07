# DaDude Agent - Lightweight Docker image for network scanning
# Ottimizzato per MikroTik RouterOS 7 Container

FROM python:3.11-slim

# Metadata
LABEL maintainer="DaDude Team"
LABEL description="Network scanning agent for DaDude inventory system"
LABEL version="1.1.0"

# Create app directory
WORKDIR /app

# Install system dependencies + network tools + nmap + git + docker-cli
# Retry apt-get update in case of network issues
RUN set -e; \
    for i in 1 2 3; do \
        apt-get update && break || sleep 5; \
    done && \
    apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    iputils-ping \
    dnsutils \
    net-tools \
    iproute2 \
    nmap \
    procps \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Docker CLI for self-update capability (v27.x for API 1.46+)
RUN curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-27.3.1.tgz | \
    tar xz -C /tmp && \
    mv /tmp/docker/docker /usr/local/bin/docker && \
    rm -rf /tmp/docker && \
    chmod +x /usr/local/bin/docker

# Install docker-compose plugin (v2.31.x)
RUN mkdir -p /usr/local/lib/docker/cli-plugins && \
    curl -SL "https://github.com/docker/compose/releases/download/v2.31.0/docker-compose-linux-x86_64" \
    -o /usr/local/lib/docker/cli-plugins/docker-compose && \
    chmod +x /usr/local/lib/docker/cli-plugins/docker-compose && \
    ln -s /usr/local/lib/docker/cli-plugins/docker-compose /usr/local/bin/docker-compose

# Copy requirements first for caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt \
    && rm -rf /root/.cache/pip

# Copy application code
COPY app/ ./app/
COPY config/ ./config/

# Expose API port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV DADUDE_AGENT_PORT=8080

# Run the agent
CMD ["python", "-m", "app.main"]

