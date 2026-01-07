#!/bin/bash
# Script per ricostruire l'immagine Docker dell'agent DaDude su Proxmox LXC
# Uso: bash rebuild-agent.sh <container_id>

set -euo pipefail

# Colori
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║      DaDude Agent - Rebuild Docker Image                 ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"

# Richiedi CTID
if [ -z "${1:-}" ]; then
    read -p "Inserisci l'ID del container LXC (es: 901): " CTID
else
    CTID=$1
fi

if [ -z "$CTID" ]; then
    error "CTID non può essere vuoto."
fi

# Verifica che il container esista
if ! pct status "$CTID" &>/dev/null; then
    error "Container LXC $CTID non trovato."
fi

if [ "$(pct status "$CTID" | awk '{print $2}')" != "running" ]; then
    warn "Container $CTID non è in esecuzione. Tentativo di avvio..."
    pct start "$CTID" || error "Fallito avvio container $CTID."
    sleep 5
fi

log "Ricostruzione immagine Docker per container $CTID..."

# Directory agent
AGENT_DIR="/opt/dadude-agent"
COMPOSE_DIR="${AGENT_DIR}/dadude-agent"

# Verifica che la directory esista
if ! pct exec "$CTID" -- test -d "$COMPOSE_DIR"; then
    error "Directory agent non trovata: $COMPOSE_DIR"
fi

# Verifica che docker-compose.yml esista
if ! pct exec "$CTID" -- test -f "${COMPOSE_DIR}/docker-compose.yml"; then
    error "docker-compose.yml non trovato in ${COMPOSE_DIR}"
fi

# Step 1: Aggiorna codice git
log "Step 1: Aggiornamento codice da git..."
pct exec "$CTID" -- bash -c "cd ${AGENT_DIR} && git fetch origin main && git reset --hard origin/main" || error "Fallito aggiornamento git"

# Step 2: Pulisci immagini Docker vecchie (opzionale, per liberare spazio)
log "Step 2: Pulizia immagini Docker vecchie..."
pct exec "$CTID" -- docker system prune -f --volumes 2>&1 | tail -3 || warn "Pulizia Docker fallita (non critico)"

# Step 3: Ricostruisci immagine
log "Step 3: Ricostruzione immagine Docker..."
if ! pct exec "$CTID" -- bash -c "cd ${COMPOSE_DIR} && docker compose build --quiet"; then
    error "Fallita ricostruzione immagine Docker"
fi

success "Immagine Docker ricostruita con successo!"

# Step 4: Riavvia container
log "Step 4: Riavvio container Docker..."
if ! pct exec "$CTID" -- docker restart dadude-agent; then
    warn "Docker restart fallito, provo con docker compose up..."
    pct exec "$CTID" -- bash -c "cd ${COMPOSE_DIR} && docker compose up -d --force-recreate" || error "Fallito riavvio container"
fi

success "Container Docker riavviato!"

# Step 5: Verifica stato
log "Step 5: Verifica stato container..."
sleep 5
STATUS=$(pct exec "$CTID" -- docker ps --filter name=dadude-agent --format "{{.Status}}" 2>&1)
if [ -n "$STATUS" ]; then
    success "Container status: $STATUS"
else
    warn "Impossibile verificare stato container"
fi

# Step 6: Mostra ultimi log
log "Step 6: Ultimi log container..."
pct exec "$CTID" -- docker logs dadude-agent --tail 10 2>&1 | grep -E "DaDude Agent|version|Connected|ERROR" || warn "Nessun log disponibile"

success "Rebuild completato!"
log "Per vedere i log completi: pct exec $CTID -- docker logs -f dadude-agent"

