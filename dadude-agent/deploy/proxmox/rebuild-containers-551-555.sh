#!/bin/bash
# Script per ricostruire agent su container 551 e 555
# Esegui sul server Proxmox

set -euo pipefail

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║      Rebuild Agent - Container 551 e 555                 ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"

# Funzione per rebuild singolo container
rebuild_container() {
    local CTID=$1
    log "Rebuilding container $CTID..."
    
    # Verifica container esiste
    if ! pct status "$CTID" &>/dev/null; then
        error "Container $CTID non trovato"
    fi
    
    # Avvia se non running
    if [ "$(pct status "$CTID" | awk '{print $2}')" != "running" ]; then
        log "Avvio container $CTID..."
        pct start "$CTID" || error "Fallito avvio container $CTID"
        sleep 5
    fi
    
    # Aggiorna codice
    log "Aggiornamento codice git..."
    pct exec "$CTID" -- bash -c "cd /opt/dadude-agent && git fetch origin main && git reset --hard origin/main" || error "Fallito aggiornamento git"
    
    # Pulisci spazio (opzionale)
    log "Pulizia spazio Docker..."
    pct exec "$CTID" -- docker system prune -f --volumes 2>&1 | tail -3 || log "Pulizia non critica"
    
    # Rebuild immagine
    log "Ricostruzione immagine Docker..."
    pct exec "$CTID" -- bash -c "cd /opt/dadude-agent/dadude-agent && docker compose build --quiet" || error "Fallito rebuild"
    
    # Riavvia container
    log "Riavvio container..."
    pct exec "$CTID" -- docker restart dadude-agent || error "Fallito restart"
    
    # Verifica
    sleep 5
    VERSION=$(pct exec "$CTID" -- docker logs dadude-agent --tail 10 2>&1 | grep "DaDude Agent" | head -1 | grep -oP 'v\d+\.\d+\.\d+' || echo "unknown")
    success "Container $CTID rebuild completato - Versione: $VERSION"
}

# Rebuild container 551
rebuild_container 551

echo ""

# Rebuild container 555
rebuild_container 555

echo ""
success "Rebuild completato per entrambi i container!"
log "Per vedere i log:"
log "  pct exec 551 -- docker logs -f dadude-agent"
log "  pct exec 555 -- docker logs -f dadude-agent"

