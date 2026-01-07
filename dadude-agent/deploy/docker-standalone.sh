#!/bin/bash
#
# DaDude Agent - Docker Standalone Installer
# Per installazione su qualsiasi host Linux con Docker
#
# Uso: curl -sSL https://raw.githubusercontent.com/grandir66/dadude/main/dadude-agent/deploy/docker-standalone.sh | bash -s -- [OPZIONI]
#

set -e

# Colori
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Valori default
SERVER_URL=""
AGENT_TOKEN=""
AGENT_ID=""
AGENT_NAME="DaDude Agent"
DNS_SERVER=""
INSTALL_DIR="/opt/dadude-agent"

# Parse argomenti
while [[ $# -gt 0 ]]; do
    case $1 in
        --server-url) SERVER_URL="$2"; shift 2 ;;
        --agent-token) AGENT_TOKEN="$2"; shift 2 ;;
        --agent-id) AGENT_ID="$2"; shift 2 ;;
        --agent-name) AGENT_NAME="$2"; shift 2 ;;
        --dns-server) DNS_SERVER="$2"; shift 2 ;;
        --install-dir) INSTALL_DIR="$2"; shift 2 ;;
        *) echo -e "${RED}Opzione sconosciuta: $1${NC}"; exit 1 ;;
    esac
done

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════╗"
echo "║   DaDude Agent - Docker Installer        ║"
echo "╚══════════════════════════════════════════╝"
echo -e "${NC}"

# Verifica parametri obbligatori
if [ -z "$SERVER_URL" ]; then
    echo -e "${RED}Errore: --server-url è richiesto${NC}"
    exit 1
fi

if [ -z "$AGENT_TOKEN" ]; then
    echo -e "${RED}Errore: --agent-token è richiesto${NC}"
    exit 1
fi

# Verifica Docker
if ! command -v docker &> /dev/null; then
    echo -e "${YELLOW}Docker non trovato. Installo...${NC}"
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
fi

# Genera agent_id se non specificato
if [ -z "$AGENT_ID" ]; then
    AGENT_ID="agent-$(hostname)-$(date +%s | tail -c 5)"
fi

echo -e "${YELLOW}Configurazione:${NC}"
echo "  Install dir: $INSTALL_DIR"
echo "  Server URL:  $SERVER_URL"
echo "  Agent ID:    $AGENT_ID"
echo "  Agent Name:  $AGENT_NAME"
echo ""

# Crea directory
mkdir -p $INSTALL_DIR/config

# Crea docker-compose.yml
cat > $INSTALL_DIR/docker-compose.yml << EOF
version: '3.8'

services:
  agent:
    image: ghcr.io/dadude/agent:latest
    container_name: dadude-agent
    restart: unless-stopped
    network_mode: host
    environment:
      - DADUDE_SERVER_URL=${SERVER_URL}
      - DADUDE_AGENT_ID=${AGENT_ID}
      - DADUDE_AGENT_NAME=${AGENT_NAME}
      - DADUDE_AGENT_TOKEN=${AGENT_TOKEN}
      - DADUDE_DNS_SERVERS=${DNS_SERVER:-8.8.8.8}
      - DADUDE_API_PORT=8080
      - DADUDE_LOG_LEVEL=INFO
    volumes:
      - ./config:/app/config:ro
    healthcheck:
      test: ['CMD', 'wget', '-q', '--spider', 'http://localhost:8080/health']
      interval: 30s
      timeout: 10s
      retries: 3
EOF

# Crea config.json
cat > $INSTALL_DIR/config/config.json << EOF
{
  "server_url": "${SERVER_URL}",
  "agent_token": "${AGENT_TOKEN}",
  "agent_id": "${AGENT_ID}",
  "agent_name": "${AGENT_NAME}",
  "dns_servers": ["${DNS_SERVER:-8.8.8.8}"],
  "api_port": 8080,
  "log_level": "INFO"
}
EOF

# Crea systemd service
cat > /etc/systemd/system/dadude-agent.service << EOF
[Unit]
Description=DaDude Agent
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${INSTALL_DIR}
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable dadude-agent

# Avvia
cd $INSTALL_DIR
docker compose pull 2>/dev/null || echo "Immagine non disponibile, verrà costruita..."
docker compose up -d

echo ""
echo -e "${GREEN}✅ Installazione completata!${NC}"
echo ""
echo -e "Agent ID:   ${BLUE}$AGENT_ID${NC}"
echo -e "Agent API:  ${BLUE}http://$(hostname -I | awk '{print $1}'):8080${NC}"
echo ""
echo -e "${YELLOW}Comandi utili:${NC}"
echo "  docker logs -f dadude-agent    # Log agent"
echo "  systemctl status dadude-agent  # Stato servizio"
echo "  systemctl restart dadude-agent # Riavvia"

