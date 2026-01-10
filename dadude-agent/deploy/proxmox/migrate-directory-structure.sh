#!/bin/bash
#
# Script di Migrazione Struttura Directory Agent DaDude
# =======================================================
# Migra da struttura vecchia (/opt/dadude-agent/dadude-agent) 
# a struttura nuova (/opt/dadude-agent)
#
# Uso:
#   ./migrate-directory-structure.sh [CTID]
#   oppure eseguito direttamente nel container: ./migrate-directory-structure.sh --local
#

set -e

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
warning() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1" >&2; }

# Rileva se siamo su host Proxmox o dentro un container
is_proxmox_host() {
    [ -f /usr/bin/pct ] && [ "$1" != "--local" ]
}

# Migrazione locale (dentro il container)
migrate_local() {
    log "Inizio migrazione struttura directory..."
    
    OLD_AGENT_DIR="/opt/dadude-agent/dadude-agent"
    NEW_AGENT_DIR="/opt/dadude-agent"
    UPDATER_DIR="/opt/dadude-updater"
    
    # Verifica che esista la vecchia struttura
    if [ ! -d "$OLD_AGENT_DIR" ]; then
        warning "Vecchia struttura non trovata in $OLD_AGENT_DIR"
        warning "Potrebbe essere già migrata o struttura diversa"
        
        # Verifica se è già nella nuova struttura
        if [ -d "$NEW_AGENT_DIR/app" ] && [ ! -d "$NEW_AGENT_DIR/dadude-agent" ]; then
            success "Struttura già migrata!"
            exit 0
        fi
        
        error "Impossibile determinare la struttura attuale"
    fi
    
    log "Trovata vecchia struttura in $OLD_AGENT_DIR"
    
    # Backup completo prima della migrazione
    log "Creo backup completo..."
    BACKUP_DIR="/opt/dadude-agent/backup-pre-migration-$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    
    if [ -d "$OLD_AGENT_DIR" ]; then
        cp -r "$OLD_AGENT_DIR" "$BACKUP_DIR/dadude-agent" 2>/dev/null || true
    fi
    
    if [ -f "$NEW_AGENT_DIR/.env" ]; then
        cp "$NEW_AGENT_DIR/.env" "$BACKUP_DIR/.env" 2>/dev/null || true
    fi
    
    success "Backup salvato in $BACKUP_DIR"
    
    # Ferma servizi
    log "Fermo servizi..."
    systemctl stop dadude-agent 2>/dev/null || true
    systemctl stop dadude-git-watchdog 2>/dev/null || true
    
    # Step 1: Sposta contenuto da dadude-agent/dadude-agent a dadude-agent
    log "Step 1: Sposto contenuto repository..."
    
    if [ -d "$OLD_AGENT_DIR/app" ]; then
        # Se esiste già app nella root, rimuovila
        if [ -d "$NEW_AGENT_DIR/app" ] && [ "$NEW_AGENT_DIR/app" != "$OLD_AGENT_DIR/app" ]; then
            warning "Rimuovo vecchia directory app duplicata..."
            rm -rf "$NEW_AGENT_DIR/app"
        fi
        
        # Sposta app
        mv "$OLD_AGENT_DIR/app" "$NEW_AGENT_DIR/app"
        success "Spostato app/"
    fi
    
    # Sposta altri file importanti
    for file in VERSION requirements.txt .env .git; do
        if [ -e "$OLD_AGENT_DIR/$file" ]; then
            if [ -e "$NEW_AGENT_DIR/$file" ] && [ "$NEW_AGENT_DIR/$file" != "$OLD_AGENT_DIR/$file" ]; then
                warning "File $file già esistente, mantengo quello nella root"
            else
                mv "$OLD_AGENT_DIR/$file" "$NEW_AGENT_DIR/$file" 2>/dev/null || true
                success "Spostato $file"
            fi
        fi
    done
    
    # Sposta config se esiste
    if [ -d "$OLD_AGENT_DIR/config" ]; then
        if [ -d "$NEW_AGENT_DIR/config" ]; then
            warning "Directory config già esistente, unisco contenuti..."
            cp -r "$OLD_AGENT_DIR/config"/* "$NEW_AGENT_DIR/config/" 2>/dev/null || true
        else
            mv "$OLD_AGENT_DIR/config" "$NEW_AGENT_DIR/config"
        fi
        success "Spostato config/"
    fi
    
    # Rimuovi vecchia directory se vuota
    if [ -d "$OLD_AGENT_DIR" ]; then
        if [ -z "$(ls -A "$OLD_AGENT_DIR" 2>/dev/null)" ]; then
            rmdir "$OLD_AGENT_DIR"
            success "Rimossa directory vuota $OLD_AGENT_DIR"
        else
            warning "Directory $OLD_AGENT_DIR non vuota, mantengo per sicurezza"
        fi
    fi
    
    # Step 2: Aggiorna servizio systemd agent
    log "Step 2: Aggiorno servizio systemd agent..."
    
    if [ -f "/etc/systemd/system/dadude-agent.service" ]; then
        sed -i 's|WorkingDirectory=/opt/dadude-agent/dadude-agent|WorkingDirectory=/opt/dadude-agent|g' /etc/systemd/system/dadude-agent.service
        sed -i 's|PYTHONPATH=/opt/dadude-agent/dadude-agent|PYTHONPATH=/opt/dadude-agent|g' /etc/systemd/system/dadude-agent.service
        success "Servizio agent aggiornato"
    fi
    
    # Step 3: Setup Updater separato
    log "Step 3: Setup Agent Updater..."
    
    mkdir -p "$UPDATER_DIR/logs"
    
    # Cerca updater nel repository
    if [ -f "$NEW_AGENT_DIR/updater/updater.py" ]; then
        cp "$NEW_AGENT_DIR/updater/updater.py" "$UPDATER_DIR/"
        cp "$NEW_AGENT_DIR/updater/dadude-updater.service" /etc/systemd/system/
        success "Updater copiato da repository"
    elif [ -f "$NEW_AGENT_DIR/git-update-watchdog.py" ]; then
        # Usa il vecchio watchdog come base
        cp "$NEW_AGENT_DIR/git-update-watchdog.py" "$UPDATER_DIR/updater.py"
        # Aggiorna path nel file
        sed -i 's|AGENT_DIR = Path(os.getenv("AGENT_DIR", "/opt/dadude-agent"))|AGENT_DIR = Path(os.getenv("AGENT_DIR", "/opt/dadude-agent"))|g' "$UPDATER_DIR/updater.py"
        sed -i 's|DADUDE_AGENT_SUBDIR = AGENT_DIR / "dadude-agent"|# DADUDE_AGENT_SUBDIR rimosso|g' "$UPDATER_DIR/updater.py"
        sed -i 's|self.dadude_agent_dir = DADUDE_AGENT_SUBDIR|# self.dadude_agent_dir rimosso|g' "$UPDATER_DIR/updater.py"
        success "Updater creato da git-update-watchdog.py"
    else
        # Scarica da GitHub
        warning "Updater non trovato localmente, scarico da GitHub..."
        curl -fsSL https://raw.githubusercontent.com/grandir66/DADude3/main/dadude-agent/updater/updater.py -o "$UPDATER_DIR/updater.py" || {
            error "Impossibile scaricare updater.py"
        }
        curl -fsSL https://raw.githubusercontent.com/grandir66/DADude3/main/dadude-agent/updater/dadude-updater.service -o /etc/systemd/system/dadude-updater.service || {
            error "Impossibile scaricare dadude-updater.service"
        }
        success "Updater scaricato da GitHub"
    fi
    
    chmod +x "$UPDATER_DIR/updater.py"
    
    # Crea config.env per updater
    cat > "$UPDATER_DIR/config.env" << EOF
AGENT_DIR=/opt/dadude-agent
UPDATER_DIR=/opt/dadude-updater
UPDATE_CHECK_INTERVAL=3600
AGENT_HEALTH_TIMEOUT=120
GIT_REMOTE=origin
GIT_BRANCH=main
EOF
    
    # Disabilita vecchio watchdog se esiste
    if systemctl list-units --type=service | grep -q "dadude-git-watchdog"; then
        log "Disabilito vecchio watchdog..."
        systemctl stop dadude-git-watchdog 2>/dev/null || true
        systemctl disable dadude-git-watchdog 2>/dev/null || true
        success "Vecchio watchdog disabilitato"
    fi
    
    # Abilita nuovo updater
    systemctl daemon-reload
    systemctl enable dadude-updater.service
    success "Nuovo updater abilitato"
    
    # Step 4: Pulisci cache Python
    log "Step 4: Pulisco cache Python..."
    find "$NEW_AGENT_DIR" -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
    find "$NEW_AGENT_DIR" -name "*.pyc" -delete 2>/dev/null || true
    success "Cache Python pulita"
    
    # Step 5: Verifica struttura finale
    log "Step 5: Verifica struttura finale..."
    
    if [ ! -d "$NEW_AGENT_DIR/app" ]; then
        error "ERRORE: Directory app non trovata dopo migrazione!"
        exit 1
    fi
    
    if [ ! -f "$NEW_AGENT_DIR/VERSION" ]; then
        warning "File VERSION non trovato, potrebbe essere un problema"
    fi
    
    success "Struttura verificata"
    
    # Step 6: Riavvia servizi
    log "Step 6: Riavvio servizi..."
    
    systemctl start dadude-agent
    sleep 2
    
    if systemctl is-active --quiet dadude-agent; then
        success "Agent avviato correttamente"
    else
        error "Agent non avviato correttamente!"
        systemctl status dadude-agent --no-pager || true
    fi
    
    systemctl start dadude-updater
    sleep 1
    
    if systemctl is-active --quiet dadude-updater; then
        success "Updater avviato correttamente"
    else
        warning "Updater potrebbe non essere avviato correttamente"
        systemctl status dadude-updater --no-pager || true
    fi
    
    echo ""
    success "╔══════════════════════════════════════════════════════════╗"
    success "║           ✅ MIGRAZIONE COMPLETATA!                       ║"
    success "╚══════════════════════════════════════════════════════════╝"
    echo ""
    echo -e "${BLUE}Nuova struttura:${NC}"
    echo "  Agent:   $NEW_AGENT_DIR"
    echo "  Updater: $UPDATER_DIR"
    echo ""
    echo -e "${BLUE}Backup salvato in:${NC} $BACKUP_DIR"
    echo ""
    echo -e "${YELLOW}Comandi utili:${NC}"
    echo "  systemctl status dadude-agent"
    echo "  systemctl status dadude-updater"
    echo "  journalctl -u dadude-agent -f"
    echo "  journalctl -u dadude-updater -f"
    echo ""
}

# Migrazione in container Proxmox
migrate_in_container() {
    local CTID="$1"
    
    log "Migrazione struttura directory nel container ${CTID}..."
    
    # Verifica container
    if ! pct status "${CTID}" &>/dev/null; then
        error "Container ${CTID} non trovato"
        exit 1
    fi
    
    if ! pct status "${CTID}" | grep -q "running"; then
        error "Container ${CTID} non in esecuzione"
        exit 1
    fi
    
    # Copia script nel container ed eseguilo
    local TMP_SCRIPT="/tmp/migrate-${CTID}.sh"
    cat > "${TMP_SCRIPT}" << 'MIGRATE_SCRIPT'
#!/bin/bash
set -e

OLD_AGENT_DIR="/opt/dadude-agent/dadude-agent"
NEW_AGENT_DIR="/opt/dadude-agent"
UPDATER_DIR="/opt/dadude-updater"

# Backup
BACKUP_DIR="/opt/dadude-agent/backup-pre-migration-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
[ -d "$OLD_AGENT_DIR" ] && cp -r "$OLD_AGENT_DIR" "$BACKUP_DIR/dadude-agent" 2>/dev/null || true

# Stop servizi
systemctl stop dadude-agent 2>/dev/null || true
systemctl stop dadude-git-watchdog 2>/dev/null || true

# Sposta contenuto
[ -d "$OLD_AGENT_DIR/app" ] && mv "$OLD_AGENT_DIR/app" "$NEW_AGENT_DIR/app" || true
[ -f "$OLD_AGENT_DIR/VERSION" ] && mv "$OLD_AGENT_DIR/VERSION" "$NEW_AGENT_DIR/VERSION" 2>/dev/null || true
[ -f "$OLD_AGENT_DIR/requirements.txt" ] && mv "$OLD_AGENT_DIR/requirements.txt" "$NEW_AGENT_DIR/requirements.txt" 2>/dev/null || true
[ -d "$OLD_AGENT_DIR/.git" ] && mv "$OLD_AGENT_DIR/.git" "$NEW_AGENT_DIR/.git" 2>/dev/null || true

# Aggiorna servizio
sed -i 's|WorkingDirectory=/opt/dadude-agent/dadude-agent|WorkingDirectory=/opt/dadude-agent|g' /etc/systemd/system/dadude-agent.service
sed -i 's|PYTHONPATH=/opt/dadude-agent/dadude-agent|PYTHONPATH=/opt/dadude-agent|g' /etc/systemd/system/dadude-agent.service

# Setup updater
mkdir -p "$UPDATER_DIR/logs"
curl -fsSL https://raw.githubusercontent.com/grandir66/DADude3/main/dadude-agent/updater/updater.py -o "$UPDATER_DIR/updater.py"
curl -fsSL https://raw.githubusercontent.com/grandir66/DADude3/main/dadude-agent/updater/dadude-updater.service -o /etc/systemd/system/dadude-updater.service
chmod +x "$UPDATER_DIR/updater.py"

cat > "$UPDATER_DIR/config.env" << EOF
AGENT_DIR=/opt/dadude-agent
UPDATER_DIR=/opt/dadude-updater
UPDATE_CHECK_INTERVAL=3600
AGENT_HEALTH_TIMEOUT=120
GIT_REMOTE=origin
GIT_BRANCH=main
EOF

# Disabilita vecchio watchdog
systemctl stop dadude-git-watchdog 2>/dev/null || true
systemctl disable dadude-git-watchdog 2>/dev/null || true

# Abilita nuovo updater
systemctl daemon-reload
systemctl enable dadude-updater.service

# Pulisci cache
find "$NEW_AGENT_DIR" -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

# Riavvia servizi
systemctl start dadude-agent
systemctl start dadude-updater

echo "SUCCESS"
MIGRATE_SCRIPT

    # Push ed esegui nel container
    pct push "${CTID}" "${TMP_SCRIPT}" /tmp/migrate.sh
    local RESULT=$(pct exec "${CTID}" -- bash /tmp/migrate.sh 2>&1)
    
    # Cleanup
    rm -f "${TMP_SCRIPT}"
    pct exec "${CTID}" -- rm -f /tmp/migrate.sh
    
    if echo "${RESULT}" | grep -q "SUCCESS"; then
        success "Migrazione completata nel container ${CTID}"
    else
        error "Migrazione fallita nel container ${CTID}"
        echo "${RESULT}"
        exit 1
    fi
}

# Main
main() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║         DaDude Agent - Migrazione Struttura Directory      ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    
    if [ "${1:-}" = "--local" ]; then
        # Migrazione locale
        migrate_local
    elif [ -n "${1:-}" ] && is_proxmox_host "${1:-}"; then
        # Migrazione in container specifico
        migrate_in_container "$1"
    elif is_proxmox_host "${1:-}"; then
        # Nessun argomento su Proxmox
        echo "Uso:"
        echo "  $0 <CTID>       Migra il container specificato"
        echo "  $0 --local      Migra localmente (dentro container/VM)"
        echo ""
        exit 1
    else
        # Non siamo su Proxmox, migra localmente
        migrate_local
    fi
}

main "$@"
