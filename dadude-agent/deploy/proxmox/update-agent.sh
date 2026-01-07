#!/bin/bash
# Script robusto per aggiornare agent DaDude
# Eseguito FUORI dal container Docker per evitare problemi di mount e permessi

set -euo pipefail

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Parametri
CTID="${1:-}"
AGENT_DIR="/opt/dadude-agent"
COMPOSE_DIR="${AGENT_DIR}/dadude-agent"

# Funzione di logging
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Verifica parametri
if [ -z "$CTID" ]; then
    error "Usage: $0 <container_id>"
    exit 1
fi

# Verifica che il container esista
if ! pct status $CTID &>/dev/null; then
    error "Container $CTID non trovato"
    exit 1
fi

log "Inizio update agent per container $CTID"

# Step 1: Backup file .env
log "Step 1: Backup file .env"
ENV_BACKUP_ROOT=""
ENV_BACKUP_SUBDIR=""

if pct exec $CTID -- test -f "${AGENT_DIR}/.env" 2>/dev/null; then
    ENV_BACKUP_ROOT=$(mktemp)
    pct exec $CTID -- cat "${AGENT_DIR}/.env" > "$ENV_BACKUP_ROOT"
    log "Backup .env principale salvato in $ENV_BACKUP_ROOT"
fi

if pct exec $CTID -- test -f "${COMPOSE_DIR}/.env" 2>/dev/null; then
    ENV_BACKUP_SUBDIR=$(mktemp)
    pct exec $CTID -- cat "${COMPOSE_DIR}/.env" > "$ENV_BACKUP_SUBDIR"
    log "Backup .env subdirectory salvato in $ENV_BACKUP_SUBDIR"
fi

# Step 2: Verifica repository git
log "Step 2: Verifica repository git"
if ! pct exec $CTID -- test -d "${AGENT_DIR}/.git" 2>/dev/null; then
    error "Directory ${AGENT_DIR} non è un repository git"
    
    # Prova a inizializzare il repository
    warning "Tentativo di inizializzare il repository git..."
    pct exec $CTID -- bash -c "cd ${AGENT_DIR} && git init && git remote add origin https://github.com/grandir66/Dadude.git || true"
    
    if ! pct exec $CTID -- test -d "${AGENT_DIR}/.git" 2>/dev/null; then
        error "Impossibile inizializzare il repository git"
        exit 1
    fi
fi

# Step 3: Fetch aggiornamenti
log "Step 3: Fetch aggiornamenti da GitHub"
FETCH_OUTPUT=$(pct exec $CTID -- bash -c "cd ${AGENT_DIR} && git fetch origin main 2>&1" || true)
if echo "$FETCH_OUTPUT" | grep -q "fatal\|error"; then
    error "Git fetch fallito: $FETCH_OUTPUT"
    exit 1
fi
log "Fetch completato"

# Step 4: Verifica se ci sono aggiornamenti
log "Step 4: Verifica aggiornamenti disponibili"
CURRENT_COMMIT=$(pct exec $CTID -- bash -c "cd ${AGENT_DIR} && git rev-parse HEAD 2>/dev/null || echo 'unknown'")
REMOTE_COMMIT=$(pct exec $CTID -- bash -c "cd ${AGENT_DIR} && git rev-parse origin/main 2>/dev/null || echo 'unknown'")

if [ "$CURRENT_COMMIT" = "$REMOTE_COMMIT" ] && [ "$CURRENT_COMMIT" != "unknown" ]; then
    success "Agent già aggiornato (commit: ${CURRENT_COMMIT:0:7})"
    exit 0
fi

log "Aggiornamento disponibile: ${CURRENT_COMMIT:0:7} -> ${REMOTE_COMMIT:0:7}"

# Step 5: Stop container Docker
log "Step 5: Stop container Docker"
if pct exec $CTID -- docker ps --filter name=dadude-agent --format "{{.Names}}" 2>/dev/null | grep -q dadude-agent; then
    log "Arresto container dadude-agent..."
    pct exec $CTID -- docker stop dadude-agent 2>/dev/null || true
    sleep 2
fi

# Step 6: Reset git (preservando .env)
log "Step 6: Reset repository git"
RESET_OUTPUT=$(pct exec $CTID -- bash -c "cd ${AGENT_DIR} && git reset --hard origin/main 2>&1" || true)
if echo "$RESET_OUTPUT" | grep -q "fatal\|error"; then
    error "Git reset fallito: $RESET_OUTPUT"
    # Ripristina .env se il reset fallisce
    if [ -n "$ENV_BACKUP_ROOT" ] && [ -f "$ENV_BACKUP_ROOT" ]; then
        pct exec $CTID -- bash -c "cat > ${AGENT_DIR}/.env" < "$ENV_BACKUP_ROOT"
        log ".env ripristinato dopo errore"
    fi
    exit 1
fi
log "Reset completato"

# Step 7: Ripristina file .env
log "Step 7: Ripristina file .env"
if [ -n "$ENV_BACKUP_ROOT" ] && [ -f "$ENV_BACKUP_ROOT" ]; then
    pct exec $CTID -- bash -c "cat > ${AGENT_DIR}/.env" < "$ENV_BACKUP_ROOT"
    log ".env principale ripristinato"
fi

if [ -n "$ENV_BACKUP_SUBDIR" ] && [ -f "$ENV_BACKUP_SUBDIR" ]; then
    pct exec $CTID -- mkdir -p "${COMPOSE_DIR}" 2>/dev/null || true
    pct exec $CTID -- bash -c "cat > ${COMPOSE_DIR}/.env" < "$ENV_BACKUP_SUBDIR"
    log ".env subdirectory ripristinato"
elif [ -n "$ENV_BACKUP_ROOT" ] && [ -f "$ENV_BACKUP_ROOT" ]; then
    # Se non esiste il backup della subdirectory, copia dalla root
    pct exec $CTID -- mkdir -p "${COMPOSE_DIR}" 2>/dev/null || true
    pct exec $CTID -- cp "${AGENT_DIR}/.env" "${COMPOSE_DIR}/.env" 2>/dev/null || true
    log ".env copiato in subdirectory"
fi

# Step 8: Verifica struttura directory
log "Step 8: Verifica struttura directory"
if ! pct exec $CTID -- test -d "${COMPOSE_DIR}" 2>/dev/null; then
    warning "Directory ${COMPOSE_DIR} non esiste, creazione..."
    pct exec $CTID -- mkdir -p "${COMPOSE_DIR}" 2>/dev/null || true
fi

# Step 9: Verifica docker-compose.yml
log "Step 9: Verifica docker-compose.yml"
if ! pct exec $CTID -- test -f "${COMPOSE_DIR}/docker-compose.yml" 2>/dev/null; then
    warning "docker-compose.yml non trovato in ${COMPOSE_DIR}, creazione..."
    pct exec $CTID -- bash -c "cat > ${COMPOSE_DIR}/docker-compose.yml << 'EOF'
services:
  agent:
    build: .
    image: dadude-agent:latest
    container_name: dadude-agent
    restart: unless-stopped
    command: [\"python\", \"-m\", \"app.agent\"]
    network_mode: host
    env_file:
      - .env
    cap_add:
      - NET_RAW
      - NET_ADMIN
    volumes:
      - ./config:/app/config:ro
      - /var/run/docker.sock:/var/run/docker.sock
      - ../:/opt/dadude-agent
    working_dir: /app
    healthcheck:
      test: [\"CMD\", \"python\", \"-c\", \"import sys; sys.exit(0)\"]
      interval: 30s
      timeout: 10s
      retries: 3
EOF
"
fi

# Step 10: Build immagine Docker
log "Step 10: Build immagine Docker"
BUILD_OUTPUT=$(pct exec $CTID -- bash -c "cd ${COMPOSE_DIR} && docker compose build --quiet 2>&1" || true)
if echo "$BUILD_OUTPUT" | grep -qi "error\|failed"; then
    error "Docker build fallito: $BUILD_OUTPUT"
    exit 1
fi
log "Build completato"

# Step 11: Avvia container
log "Step 11: Avvia container Docker"
# Rimuovi eventuali container vecchi in stato "Created" o "Exited"
pct exec $CTID -- docker rm -f dadude-agent 2>/dev/null || true
pct exec $CTID -- docker ps -a --filter name=dadude-agent --format "{{.Names}}" | grep -v "^$" | while read name; do
    if [ "$name" != "dadude-agent" ]; then
        pct exec $CTID -- docker rm -f "$name" 2>/dev/null || true
    fi
done

START_OUTPUT=$(pct exec $CTID -- bash -c "cd ${COMPOSE_DIR} && docker compose up -d --force-recreate 2>&1" || true)
if echo "$START_OUTPUT" | grep -qi "error\|failed"; then
    error "Avvio container fallito: $START_OUTPUT"
    exit 1
fi
log "Container avviato"

# Attendi che il container sia effettivamente avviato
sleep 3

# Step 12: Verifica stato
log "Step 12: Verifica stato container"
sleep 5
CONTAINER_STATUS=$(pct exec $CTID -- docker ps --filter name=dadude-agent --format "{{.Status}}" 2>/dev/null || echo "")
if echo "$CONTAINER_STATUS" | grep -q "Up"; then
    success "Container avviato correttamente"
    
    # Verifica che l'agent si stia connettendo (attendi fino a 30 secondi)
    log "Attendo connessione agent al server..."
    for i in {1..30}; do
        sleep 1
        if pct exec $CTID -- docker logs dadude-agent --tail 10 2>&1 | grep -q "Connected to DaDude server"; then
            success "Agent connesso al server"
            break
        fi
        if [ $i -eq 30 ]; then
            warning "Agent potrebbe non essersi connesso al server (verifica i log)"
        fi
    done
else
    warning "Container potrebbe non essere avviato correttamente"
    pct exec $CTID -- docker ps -a --filter name=dadude-agent 2>/dev/null || true
    
    # Prova a riavviare manualmente
    log "Tentativo di riavvio manuale..."
    pct exec $CTID -- docker start dadude-agent 2>/dev/null || true
    sleep 3
    if pct exec $CTID -- docker ps --filter name=dadude-agent --format "{{.Status}}" 2>/dev/null | grep -q "Up"; then
        success "Container riavviato manualmente"
    else
        error "Impossibile avviare il container. Verifica manualmente: pct exec $CTID -- docker logs dadude-agent"
    fi
fi

# Cleanup backup files
if [ -n "$ENV_BACKUP_ROOT" ] && [ -f "$ENV_BACKUP_ROOT" ]; then
    rm -f "$ENV_BACKUP_ROOT"
fi
if [ -n "$ENV_BACKUP_SUBDIR" ] && [ -f "$ENV_BACKUP_SUBDIR" ]; then
    rm -f "$ENV_BACKUP_SUBDIR"
fi

success "Update completato con successo!"
log "Commit attuale: $(pct exec $CTID -- bash -c "cd ${AGENT_DIR} && git rev-parse --short HEAD 2>/dev/null || echo 'unknown'")"

