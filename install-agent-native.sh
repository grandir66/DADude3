#!/bin/bash
#
# DaDude Agent - Installazione NATIVA (NO Docker) su Proxmox LXC
# 
# Uso:
#   curl -fsSL https://raw.githubusercontent.com/.../install-agent-native.sh | bash
#   oppure: bash install-agent-native.sh
#

set -e

# Colori
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[DaDude]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Verifica che siamo su Debian/Ubuntu
if ! command -v apt-get &> /dev/null; then
    error "Questo script richiede Debian/Ubuntu"
fi

# Verifica root
if [[ $EUID -ne 0 ]]; then
   error "Questo script deve essere eseguito come root"
fi

log "=== DaDude Agent - Installazione Nativa ==="

# 1. Aggiornamento sistema
log "Aggiornamento sistema..."
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get upgrade -y

# 2. Installazione dipendenze di sistema
log "Installazione dipendenze di sistema..."
apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential \
    nmap \
    curl \
    git \
    openssl \
    ca-certificates

# 3. Creazione directory
log "Creazione directory..."
mkdir -p /opt/dadude-agent
mkdir -p /var/log/dadude-agent
mkdir -p /var/lib/dadude-agent

# 4. Clone/Copy codice
if [[ ! -d "/opt/dadude-agent/dadude-agent" ]]; then
    log "Copia codice sorgente..."
    if [[ -d "dadude-agent" ]]; then
        cp -r dadude-agent /opt/dadude-agent/
    else
        error "Directory dadude-agent non trovata. Eseguire lo script dalla root del progetto."
    fi
fi

# 5. Creazione virtualenv
log "Creazione virtualenv..."
cd /opt/dadude-agent
python3 -m venv venv
source venv/bin/activate

# 6. Installazione dipendenze Python
log "Installazione dipendenze Python..."
pip install --upgrade pip
pip install -r dadude-agent/requirements.txt

# 7. Configurazione interattiva
log "Configurazione Agent..."
echo ""
read -p "Server URL (es: https://192.168.4.45:8000): " SERVER_URL
read -p "Agent Name (es: MyAgent): " AGENT_NAME
read -p "Agent Token (dal server): " AGENT_TOKEN

AGENT_ID="agent-$(hostname)-$(date +%s | tail -c 5)"

# Crea file .env
cat > /opt/dadude-agent/dadude-agent/.env <<EOF
# DaDude Agent Configuration
DADUDE_SERVER_URL=${SERVER_URL}
DADUDE_AGENT_ID=${AGENT_ID}
DADUDE_AGENT_NAME=${AGENT_NAME}
DADUDE_AGENT_TOKEN=${AGENT_TOKEN}
DADUDE_CONNECTION_MODE=websocket
DADUDE_LOG_LEVEL=INFO
DADUDE_DATA_DIR=/var/lib/dadude-agent
EOF

log "Configurazione salvata in /opt/dadude-agent/dadude-agent/.env"

# 8. Installazione systemd service
log "Installazione servizio systemd..."
if [[ -f "dadude-agent/dadude-agent.service" ]]; then
    cp dadude-agent/dadude-agent.service /etc/systemd/system/
elif [[ -f "/opt/dadude-agent/dadude-agent/dadude-agent.service" ]]; then
    cp /opt/dadude-agent/dadude-agent/dadude-agent.service /etc/systemd/system/
else
    error "File dadude-agent.service non trovato!"
fi
systemctl daemon-reload
systemctl enable dadude-agent.service

log "Installazione completata!"
echo ""
echo -e "${GREEN}Prossimi passi:${NC}"
echo "1. Verificare configurazione in /opt/dadude-agent/dadude-agent/.env"
echo "2. Avviare il servizio: systemctl start dadude-agent"
echo "3. Verificare log: journalctl -u dadude-agent -f"
echo "4. Approvare l'agent sul server DaDude"
