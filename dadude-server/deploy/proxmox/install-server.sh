#!/bin/bash
#
# DaDude Server - Installazione su Proxmox LXC
# 
# Uso:
#   curl -fsSL https://raw.githubusercontent.com/grandir66/dadude/main/dadude/deploy/proxmox/install-server.sh | bash -s -- \
#     --ip 192.168.40.3 \
#     --gateway 192.168.40.1 \
#     --ctid 800
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

# Defaults
CTID=""
HOSTNAME="dadude-server"
STORAGE="local-lvm"
TEMPLATE_STORAGE="local"
MEMORY=1024
DISK=10
IP_ADDRESS=""
GATEWAY=""
BRIDGE="vmbr0"
SERVER_PORT=8000
DNS="8.8.8.8"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --ctid) CTID="$2"; shift 2 ;;
        --hostname) HOSTNAME="$2"; shift 2 ;;
        --ip) IP_ADDRESS="$2"; shift 2 ;;
        --gateway) GATEWAY="$2"; shift 2 ;;
        --bridge) BRIDGE="$2"; shift 2 ;;
        --memory) MEMORY="$2"; shift 2 ;;
        --disk) DISK="$2"; shift 2 ;;
        --storage) STORAGE="$2"; shift 2 ;;
        --dns) DNS="$2"; shift 2 ;;
        --port) SERVER_PORT="$2"; shift 2 ;;
        -h|--help)
            echo "Uso: $0 [opzioni]"
            echo ""
            echo "Opzioni:"
            echo "  --ctid ID         ID container (default: auto)"
            echo "  --hostname NAME   Hostname (default: dadude-server)"
            echo "  --ip IP/MASK      IP address (es: 192.168.40.3/24)"
            echo "  --gateway IP      Gateway"
            echo "  --bridge NAME     Bridge di rete (default: vmbr0)"
            echo "  --memory MB       Memoria in MB (default: 1024)"
            echo "  --disk GB         Disco in GB (default: 10)"
            echo "  --port PORT       Porta server (default: 8000)"
            echo "  --dns IP          DNS server (default: 8.8.8.8)"
            exit 0
            ;;
        *) error "Opzione sconosciuta: $1" ;;
    esac
done

# Verifica che siamo su Proxmox
if ! command -v pct &> /dev/null; then
    error "Questo script deve essere eseguito su un host Proxmox"
fi

# Verifica parametri obbligatori
if [[ -z "$IP_ADDRESS" ]]; then
    error "IP address richiesto (--ip 192.168.x.x/24)"
fi
if [[ -z "$GATEWAY" ]]; then
    error "Gateway richiesto (--gateway 192.168.x.1)"
fi

# Auto CTID se non specificato
if [[ -z "$CTID" ]]; then
    CTID=$(pvesh get /cluster/nextid)
    log "Usando CTID: $CTID"
fi

# Genera chiave di encryption
ENCRYPTION_KEY=$(openssl rand -hex 32)

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     DaDude Server - Proxmox Install      ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════╝${NC}"
echo ""
echo "Configurazione:"
echo "  CTID:        $CTID"
echo "  Hostname:    $HOSTNAME"
echo "  IP:          $IP_ADDRESS"
echo "  Gateway:     $GATEWAY"
echo "  Porta:       $SERVER_PORT"
echo "  Memory:      ${MEMORY}MB"
echo "  Disk:        ${DISK}GB"
echo ""

read -p "Procedere con l'installazione? [y/N] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Installazione annullata"
    exit 0
fi

# [1/6] Verifica template
log "[1/6] Verifico template..."

# Cerca template Debian disponibile
TEMPLATE=$(pveam list $TEMPLATE_STORAGE 2>/dev/null | grep -E "debian-12|debian-11" | head -1 | awk '{print $1}')

if [[ -z "$TEMPLATE" ]]; then
    log "Nessun template trovato. Cerco template disponibili..."
    pveam update
    
    # Lista template disponibili
    AVAILABLE=$(pveam available --section system | grep -E "debian-12|debian-11|ubuntu-22|ubuntu-24" | head -1 | awk '{print $2}')
    
    if [[ -z "$AVAILABLE" ]]; then
        error "Nessun template Debian/Ubuntu disponibile"
    fi
    
    log "Scarico template: $AVAILABLE"
    pveam download $TEMPLATE_STORAGE $AVAILABLE || error "Download template fallito"
    TEMPLATE="${TEMPLATE_STORAGE}:vztmpl/${AVAILABLE}"
else
    log "Template trovato: $TEMPLATE"
fi

# [2/6] Crea container
log "[2/6] Creo container LXC..."

pct create $CTID $TEMPLATE \
    --hostname $HOSTNAME \
    --storage $STORAGE \
    --rootfs ${STORAGE}:${DISK} \
    --memory $MEMORY \
    --cores 2 \
    --net0 name=eth0,bridge=$BRIDGE,ip=$IP_ADDRESS,gw=$GATEWAY \
    --nameserver $DNS \
    --unprivileged 1 \
    --features nesting=1 \
    --onboot 1 \
    --start 1 || error "Creazione container fallita"

log "Container $CTID creato"

# Attendi avvio
sleep 5

# [3/6] Installa Docker
log "[3/6] Installo Docker..."

pct exec $CTID -- bash -c "
    apt-get update
    apt-get install -y ca-certificates curl gnupg
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo \"deb [arch=\$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \$(. /etc/os-release && echo \$VERSION_CODENAME) stable\" > /etc/apt/sources.list.d/docker.list
    apt-get update
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin git
" || error "Installazione Docker fallita"

# [4/6] Clone repository
log "[4/6] Clono repository DaDude..."

pct exec $CTID -- bash -c "
    mkdir -p /opt/dadude
    cd /opt/dadude
    git clone https://github.com/grandir66/dadude.git . || true
    cd dadude
" || warn "Clone repository (potrebbe già esistere)"

# [5/6] Configura e avvia
log "[5/6] Configuro e avvio DaDude..."

# Crea file .env
pct exec $CTID -- bash -c "
cat > /opt/dadude/dadude/.env << 'ENVFILE'
# DaDude Server Configuration - SOLO PostgreSQL
DATABASE_URL=postgresql+psycopg2://dadude:dadude@localhost:5432/dadude
ENCRYPTION_KEY=${ENCRYPTION_KEY}

# Server
HOST=0.0.0.0
PORT=${SERVER_PORT}
DEBUG=false

# Dude Server (opzionale)
DUDE_HOST=
DUDE_USER=
DUDE_PASSWORD=
DUDE_PORT=8728
ENVFILE
"

# Crea docker-compose-dual.yml
pct exec $CTID -- bash -c "
cat > /opt/dadude/dadude/docker-compose-dual.yml << 'COMPOSEFILE'
version: \"3.8\"

services:
  dadude:
    build:
      context: .
      dockerfile: Dockerfile.dual
    container_name: dadude
    restart: unless-stopped
    ports:
      - \"8000:8000\"  # Agent API (pubblico)
      - \"8001:8001\"  # Admin UI (privato)
    environment:
      - DADUDE_HOST=0.0.0.0
      - DADUDE_AGENT_PORT=8000
      - DADUDE_ADMIN_PORT=8001
      - LOG_LEVEL=INFO
      - DATABASE_URL=postgresql+psycopg2://dadude:dadude@postgres:5432/dadude
      - TZ=Europe/Rome
    volumes:
      - dadude_data:/app/data
      - dadude_logs:/app/logs
      - /var/run/docker.sock:/var/run/docker.sock
      - .:/app/repo
      - ./app:/app/app:ro
    networks:
      - dadude_network
    dns:
      - 192.168.4.1
      - 8.8.8.8
    healthcheck:
      test: [\"CMD-SHELL\", \"(curl -fk https://localhost:8000/health || curl -f http://localhost:8000/health) && (curl -fk https://localhost:8001/health || curl -f http://localhost:8001/health) || exit 1\"]
      interval: 30s
      timeout: 15s
      retries: 3
      start_period: 30s

volumes:
  dadude_data:
  dadude_logs:

networks:
  dadude_network:
    driver: bridge
COMPOSEFILE
"

# Crea Dockerfile.dual se non esiste
pct exec $CTID -- bash -c "
if [ ! -f /opt/dadude/dadude/Dockerfile.dual ]; then
cat > /opt/dadude/dadude/Dockerfile.dual << 'DOCKERFILE'
# DaDude - The Dude MikroTik Connector (Dual Port Configuration)
FROM python:3.11-slim

LABEL maintainer=\"Domarc Srl\"
LABEL description=\"DaDude Dual Port - Agent API (8000) + Admin UI (8001)\"
LABEL version=\"3.0.0\"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV TZ=Europe/Rome

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \\
    curl \\
    openssl \\
    git \\
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-27.3.1.tgz | \\
    tar xz -C /tmp && \\
    mv /tmp/docker/docker /usr/local/bin/docker && \\
    rm -rf /tmp/docker && \\
    chmod +x /usr/local/bin/docker

RUN mkdir -p /usr/local/lib/docker/cli-plugins && \\
    curl -SL \"https://github.com/docker/compose/releases/download/v2.31.0/docker-compose-linux-x86_64\" \\
    -o /usr/local/lib/docker/cli-plugins/docker-compose && \\
    chmod +x /usr/local/lib/docker/cli-plugins/docker-compose

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN mkdir -p /app/data /app/logs /app/app

RUN useradd -m -u 1000 dadude && \\
    chown -R dadude:dadude /app
USER dadude

EXPOSE 8000 8001

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \\
    CMD curl -f http://localhost:8000/health && curl -f http://localhost:8001/health || exit 1

CMD [\"python\", \"-m\", \"app.run_dual\"]
DOCKERFILE
fi
"

# Crea directory dati
pct exec $CTID -- mkdir -p /opt/dadude/dadude/data

# Build e avvia
pct exec $CTID -- bash -c "
    cd /opt/dadude/dadude
    docker compose -f docker-compose-dual.yml build
    docker compose -f docker-compose-dual.yml up -d
"

# [6/6] Verifica
log "[6/6] Verifico installazione..."

sleep 10

# Estrai IP senza maschera
SERVER_IP=$(echo $IP_ADDRESS | cut -d'/' -f1)

# Test health
if pct exec $CTID -- curl -sf http://localhost:${SERVER_PORT}/health > /dev/null 2>&1; then
    log "✅ Server DaDude attivo!"
else
    warn "Server potrebbe richiedere più tempo per avviarsi"
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║    ✅ Installazione Completata!          ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo "Container ID:  $CTID"
echo "Hostname:      $HOSTNAME"
echo "Server URL:    http://${SERVER_IP}:${SERVER_PORT}"
echo "Dashboard:     http://${SERVER_IP}:${SERVER_PORT}/"
echo ""
echo "Encryption Key (salva in un posto sicuro):"
echo "  $ENCRYPTION_KEY"
echo ""
echo "Comandi utili:"
echo "  pct enter $CTID                              # Entra nel container"
echo "  pct exec $CTID -- docker logs -f dadude      # Vedi log"
echo "  pct exec $CTID -- docker compose -f /opt/dadude/dadude/docker-compose-dual.yml restart"
echo ""
echo "Prossimi passi:"
echo "  1. Accedi a http://${SERVER_IP}:${SERVER_PORT}/"
echo "  2. Crea un cliente"
echo "  3. Installa agent sui siti remoti"
echo ""
