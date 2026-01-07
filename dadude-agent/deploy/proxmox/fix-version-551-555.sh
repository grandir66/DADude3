#!/bin/bash
# Script per fixare la versione su container 551 e 555
# Il problema è che il codice montato come volume deve essere aggiornato

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

fix_container() {
    local CTID=$1
    log "Fixing version for container $CTID..."
    
    # 1. Aggiorna codice git
    log "Step 1: Aggiornamento codice git..."
    pct exec "$CTID" -- bash -c "cd /opt/dadude-agent && git fetch origin main && git reset --hard origin/main" || error "Fallito aggiornamento git"
    
    # 2. Verifica commit
    COMMIT=$(pct exec "$CTID" -- bash -c "cd /opt/dadude-agent && git log --oneline -1" | awk '{print $1}')
    log "Commit corrente: $COMMIT"
    
    # 3. Verifica versione nel file montato
    VERSION_MOUNTED=$(pct exec "$CTID" -- docker exec dadude-agent grep "AGENT_VERSION" /opt/dadude-agent/dadude-agent/app/agent.py 2>/dev/null | grep -oP '"\K[^"]+' || echo "not found")
    log "Versione nel file montato: $VERSION_MOUNTED"
    
    # 4. Riavvia container per applicare cambiamenti
    log "Step 2: Riavvio container per applicare codice aggiornato..."
    pct exec "$CTID" -- docker restart dadude-agent || error "Fallito restart"
    
    # 5. Attendi e verifica
    sleep 10
    VERSION_LOG=$(pct exec "$CTID" -- docker logs dadude-agent --tail 50 2>&1 | grep "DaDude Agent" | head -1 | grep -oP 'v\d+\.\d+\.\d+' || echo "unknown")
    
    if [ "$VERSION_LOG" != "unknown" ]; then
        success "Container $CTID - Versione rilevata: $VERSION_LOG"
    else
        warn "Container $CTID - Impossibile determinare versione dai log"
    fi
}

echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║      Fix Versione - Container 551 e 555                 ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"

# Fix container 551
fix_container 551

echo ""

# Fix container 555
fix_container 555

echo ""
success "Fix completato!"
log "Per vedere i log completi:"
log "  pct exec 551 -- docker logs -f dadude-agent"
log "  pct exec 555 -- docker logs -f dadude-agent"

