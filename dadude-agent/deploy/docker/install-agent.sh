#!/bin/bash
#
# DaDude Agent - Installazione Docker
# 
# Uso (con auto-registrazione):
#   curl -sSL https://raw.githubusercontent.com/grandir66/dadude/main/dadude-agent/deploy/docker/install-agent.sh | bash -s -- --server http://192.168.4.45:8000
#
# Uso (con token pre-esistente):
#   curl -sSL https://raw.githubusercontent.com/grandir66/dadude/main/dadude-agent/deploy/docker/install-agent.sh | bash -s -- --server http://192.168.4.45:8000 --token YOUR_TOKEN
#

set -e

# Colori
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Default
INSTALL_DIR="/opt/dadude-agent"
AGENT_PORT="8080"
SERVER_URL=""
AGENT_TOKEN=""
AGENT_NAME=""
DNS_SERVERS=""
AUTO_REGISTER=true

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --server) SERVER_URL="$2"; shift 2 ;;
        --token) AGENT_TOKEN="$2"; AUTO_REGISTER=false; shift 2 ;;
        --name) AGENT_NAME="$2"; shift 2 ;;
        --port) AGENT_PORT="$2"; shift 2 ;;
        --dns) DNS_SERVERS="$2"; shift 2 ;;
        --dir) INSTALL_DIR="$2"; shift 2 ;;
        -h|--help)
            echo "DaDude Agent Installer"
            echo ""
            echo "Uso: $0 [opzioni]"
            echo ""
            echo "Opzioni:"
            echo "  --server URL     URL del server DaDude (richiesto)"
            echo "  --token TOKEN    Token di autenticazione (opzionale - auto-registrazione se omesso)"
            echo "  --name NAME      Nome dell'agent (default: hostname)"
            echo "  --port PORT      Porta API agent (default: 8080)"
            echo "  --dns SERVERS    Server DNS (es: 8.8.8.8,1.1.1.1)"
            echo "  --dir DIR        Directory installazione"
            echo ""
            echo "Se --token non viene specificato, l'agent si registrerà automaticamente"
            echo "e dovrà essere approvato dal pannello DaDude (Agent → In Attesa)."
            exit 0
            ;;
        *) echo "Opzione sconosciuta: $1"; exit 1 ;;
    esac
done

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════╗"
echo "║     DaDude Agent - Installazione         ║"
echo "╚══════════════════════════════════════════╝"
echo -e "${NC}"

# Verifica parametri richiesti
if [ -z "$SERVER_URL" ]; then
    echo -e "${RED}Errore: --server è richiesto${NC}"
    echo "Esempio: $0 --server http://192.168.4.45:8000"
    exit 1
fi

# Genera token temporaneo se non specificato
if [ -z "$AGENT_TOKEN" ]; then
    AGENT_TOKEN=$(openssl rand -hex 16)
    echo -e "${YELLOW}Nessun token specificato. L'agent userà auto-registrazione.${NC}"
    echo -e "${YELLOW}Dopo l'avvio, approva l'agent dal pannello DaDude.${NC}"
fi

# Default agent name
if [ -z "$AGENT_NAME" ]; then
    AGENT_NAME=$(hostname)
fi

# Auto-detect IP
AGENT_IP=$(ip route get 1 | awk '{print $7;exit}' 2>/dev/null || hostname -I | awk '{print $1}')

# Verifica requisiti
echo -e "${YELLOW}[1/5] Verifica requisiti...${NC}"

if ! command -v docker &> /dev/null; then
    echo -e "${RED}Docker non installato. Installo...${NC}"
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
fi

if ! command -v git &> /dev/null; then
    echo -e "${YELLOW}Installo git...${NC}"
    apt-get update && apt-get install -y git
fi

echo -e "${GREEN}✓ Requisiti OK${NC}"

# Verifica connessione al server
echo -e "${YELLOW}[2/5] Verifico connessione al server...${NC}"
if curl -s --connect-timeout 5 "${SERVER_URL}/health" &>/dev/null; then
    echo -e "${GREEN}✓ Server raggiungibile${NC}"
else
    echo -e "${YELLOW}⚠ Server non raggiungibile - continuo comunque${NC}"
fi

# Clone repository
echo -e "${YELLOW}[3/5] Scarico DaDude Agent...${NC}"

if [ -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}Directory esistente, aggiorno...${NC}"
    cd "$INSTALL_DIR"
    git pull || true
else
    git clone https://github.com/grandir66/dadude.git "$INSTALL_DIR"
fi

cd "$INSTALL_DIR/dadude-agent"

# Crea .env
echo -e "${YELLOW}[4/5] Configuro ambiente...${NC}"

AGENT_ID="agent-${AGENT_NAME}-$(date +%s | tail -c 5)"

cat > .env << EOF
# DaDude Agent Configuration
DADUDE_SERVER_URL=${SERVER_URL}
DADUDE_AGENT_TOKEN=${AGENT_TOKEN}
DADUDE_AGENT_ID=${AGENT_ID}
DADUDE_AGENT_NAME=${AGENT_NAME}
DADUDE_AGENT_PORT=${AGENT_PORT}
DADUDE_DNS_SERVERS=${DNS_SERVERS:-8.8.8.8}
EOF

# Crea docker-compose.yml
cat > docker-compose.yml << EOF
services:
  dadude-agent:
    build: .
    container_name: dadude-agent
    restart: unless-stopped
    network_mode: host
    volumes:
      - ./.env:/app/.env:ro
    environment:
      - TZ=Europe/Rome
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:${AGENT_PORT}/health"]
      interval: 30s
      timeout: 10s
      retries: 3
EOF

# Disabilita iptables Docker
mkdir -p /etc/docker
if [ ! -f /etc/docker/daemon.json ]; then
    echo '{"iptables": false}' > /etc/docker/daemon.json
    systemctl restart docker
    sleep 3
fi

# Build e start
echo -e "${YELLOW}[5/5] Avvio DaDude Agent...${NC}"

docker compose build --quiet
docker compose up -d

# Attendi avvio
echo -e "${YELLOW}Attendo avvio agent...${NC}"
for i in {1..30}; do
    if curl -s http://localhost:${AGENT_PORT}/health &>/dev/null; then
        break
    fi
    sleep 1
done

# Verifica
if curl -s http://localhost:${AGENT_PORT}/health &>/dev/null; then
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════╗"
    echo "║    ✅ DaDude Agent Installato!           ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo -e "  ${GREEN}Agent ID:${NC}   ${AGENT_ID}"
    echo -e "  ${GREEN}Agent Name:${NC} ${AGENT_NAME}"
    echo -e "  ${GREEN}Agent IP:${NC}   ${AGENT_IP}"
    echo -e "  ${GREEN}Agent API:${NC}  http://${AGENT_IP}:${AGENT_PORT}"
    echo -e "  ${GREEN}Server:${NC}     ${SERVER_URL}"
    echo ""
    echo -e "${YELLOW}Prossimi passi:${NC}"
    echo ""
    echo -e "${BLUE}L'agent si è registrato automaticamente sul server.${NC}"
    echo "Vai sul pannello DaDude per approvarlo:"
    echo ""
    echo "   1. Apri: ${SERVER_URL}/agents"
    echo "   2. Nella sezione 'Agent in Attesa', clicca 'Approva'"
    echo "   3. Seleziona il cliente a cui assegnare l'agent"
    echo ""
    echo "Una volta approvato, l'agent sarà attivo e pronto per le scansioni."
    echo ""
    echo "Comandi utili:"
    echo "  cd ${INSTALL_DIR}/dadude-agent"
    echo "  docker compose logs -f    # Visualizza log"
    echo "  docker compose restart    # Riavvia"
    echo "  docker compose down       # Ferma"
    echo ""
else
    echo -e "${RED}Errore: Agent non raggiungibile${NC}"
    echo "Verifica i log: docker compose logs"
    exit 1
fi

