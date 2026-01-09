#!/bin/bash
#
# DaDude Git Update Watchdog - Script di Installazione
# =====================================================
# Installa il watchdog per aggiornamenti automatici via Git
# 
# Uso:
#   ./install-git-watchdog.sh [CTID]           # Su host Proxmox
#   ./install-git-watchdog.sh --local          # Direttamente nel container/VM
#
# Il watchdog:
# - È completamente indipendente dall'agent
# - Controlla Git ogni ora per nuovi aggiornamenti
# - Aggiorna automaticamente e riavvia l'agent
# - Si auto-ripara anche se l'agent è corrotto
# - Ha rollback automatico se l'update fallisce
#

set -euo pipefail

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${BLUE}[$(date +'%H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
warning() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_DIR="/opt/dadude-agent"
DADUDE_AGENT_DIR="${AGENT_DIR}/dadude-agent"

# Rileva se siamo su host Proxmox o dentro un container
is_proxmox_host() {
    [ -f /usr/bin/pct ] && [ "$1" != "--local" ]
}

# Installa il watchdog localmente (dentro il container/VM)
install_local() {
    log "Installazione locale del Git Update Watchdog..."
    
    # Verifica Python3
    if ! command -v python3 &>/dev/null; then
        error "Python3 non trovato. Installare con: apt install python3"
        exit 1
    fi
    
    # Verifica git
    if ! command -v git &>/dev/null; then
        error "Git non trovato. Installare con: apt install git"
        exit 1
    fi
    
    # Verifica directory agent
    if [ ! -d "${AGENT_DIR}" ]; then
        error "Directory agent non trovata: ${AGENT_DIR}"
        exit 1
    fi
    
    # Cerca lo script watchdog
    WATCHDOG_SCRIPT=""
    if [ -f "${AGENT_DIR}/git-update-watchdog.py" ]; then
        WATCHDOG_SCRIPT="${AGENT_DIR}/git-update-watchdog.py"
    elif [ -f "${DADUDE_AGENT_DIR}/git-update-watchdog.py" ]; then
        WATCHDOG_SCRIPT="${DADUDE_AGENT_DIR}/git-update-watchdog.py"
    else
        # Prova a fare git pull per ottenere il file
        log "Script watchdog non trovato, tentativo git pull..."
        cd "${AGENT_DIR}"
        git fetch origin main 2>/dev/null || true
        git checkout origin/main -- git-update-watchdog.py 2>/dev/null || \
        git checkout origin/main -- dadude-agent/git-update-watchdog.py 2>/dev/null || true
        
        if [ -f "${AGENT_DIR}/git-update-watchdog.py" ]; then
            WATCHDOG_SCRIPT="${AGENT_DIR}/git-update-watchdog.py"
        elif [ -f "${DADUDE_AGENT_DIR}/git-update-watchdog.py" ]; then
            WATCHDOG_SCRIPT="${DADUDE_AGENT_DIR}/git-update-watchdog.py"
        else
            error "Script git-update-watchdog.py non trovato nel repository"
            exit 1
        fi
    fi
    
    log "Trovato script watchdog: ${WATCHDOG_SCRIPT}"
    
    # Copia script nella posizione corretta
    if [ "${WATCHDOG_SCRIPT}" != "${AGENT_DIR}/git-update-watchdog.py" ]; then
        cp "${WATCHDOG_SCRIPT}" "${AGENT_DIR}/git-update-watchdog.py"
    fi
    chmod +x "${AGENT_DIR}/git-update-watchdog.py"
    
    # Cerca il file service
    SERVICE_FILE=""
    if [ -f "${AGENT_DIR}/dadude-git-watchdog.service" ]; then
        SERVICE_FILE="${AGENT_DIR}/dadude-git-watchdog.service"
    elif [ -f "${DADUDE_AGENT_DIR}/dadude-git-watchdog.service" ]; then
        SERVICE_FILE="${DADUDE_AGENT_DIR}/dadude-git-watchdog.service"
    else
        # Prova a scaricare
        git checkout origin/main -- dadude-git-watchdog.service 2>/dev/null || \
        git checkout origin/main -- dadude-agent/dadude-git-watchdog.service 2>/dev/null || true
        
        if [ -f "${AGENT_DIR}/dadude-git-watchdog.service" ]; then
            SERVICE_FILE="${AGENT_DIR}/dadude-git-watchdog.service"
        elif [ -f "${DADUDE_AGENT_DIR}/dadude-git-watchdog.service" ]; then
            SERVICE_FILE="${DADUDE_AGENT_DIR}/dadude-git-watchdog.service"
        fi
    fi
    
    # Crea il file service se non esiste
    if [ -z "${SERVICE_FILE}" ] || [ ! -f "${SERVICE_FILE}" ]; then
        warning "File service non trovato, creazione manuale..."
        cat > /etc/systemd/system/dadude-git-watchdog.service << 'EOF'
[Unit]
Description=DaDude Git Update Watchdog
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/dadude-agent
Environment="PYTHONUNBUFFERED=1"
Environment="AGENT_DIR=/opt/dadude-agent"
Environment="UPDATE_CHECK_INTERVAL=3600"
EnvironmentFile=-/opt/dadude-agent/.env.watchdog
ExecStart=/usr/bin/python3 /opt/dadude-agent/git-update-watchdog.py
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal
SyslogIdentifier=dadude-git-watchdog

[Install]
WantedBy=multi-user.target
EOF
    else
        log "Installazione file service..."
        cp "${SERVICE_FILE}" /etc/systemd/system/dadude-git-watchdog.service
    fi
    
    # Crea file di configurazione opzionale
    if [ ! -f "${AGENT_DIR}/.env.watchdog" ]; then
        cat > "${AGENT_DIR}/.env.watchdog" << EOF
# DaDude Git Watchdog Configuration
# Decommentare per modificare i valori di default

# Intervallo di controllo in secondi (default: 3600 = 1 ora)
#UPDATE_CHECK_INTERVAL=3600

# Timeout per verifica salute agent (default: 120 secondi)
#AGENT_HEALTH_TIMEOUT=120

# Remote e branch Git
#GIT_REMOTE=origin
#GIT_BRANCH=main
EOF
        log "Creato file di configurazione: ${AGENT_DIR}/.env.watchdog"
    fi
    
    # Crea directory log
    mkdir -p "${AGENT_DIR}/logs"
    
    # Reload systemd e abilita servizio
    log "Configurazione systemd..."
    systemctl daemon-reload
    systemctl enable dadude-git-watchdog.service
    
    # Ferma se già in esecuzione (per aggiornamento)
    systemctl stop dadude-git-watchdog.service 2>/dev/null || true
    
    # Avvia servizio
    log "Avvio servizio..."
    systemctl start dadude-git-watchdog.service
    
    # Verifica stato
    sleep 2
    if systemctl is-active --quiet dadude-git-watchdog.service; then
        success "Servizio dadude-git-watchdog avviato correttamente"
    else
        error "Servizio non avviato. Controlla con: journalctl -u dadude-git-watchdog -f"
        exit 1
    fi
    
    echo ""
    success "Git Update Watchdog installato con successo!"
    echo ""
    echo "Comandi utili:"
    echo "  Stato:    systemctl status dadude-git-watchdog"
    echo "  Log:      journalctl -u dadude-git-watchdog -f"
    echo "  Stop:     systemctl stop dadude-git-watchdog"
    echo "  Restart:  systemctl restart dadude-git-watchdog"
    echo "  Config:   ${AGENT_DIR}/.env.watchdog"
    echo ""
    echo "Il watchdog controllerà Git ogni ora per nuovi aggiornamenti."
    echo "Per forzare un controllo immediato:"
    echo "  python3 ${AGENT_DIR}/git-update-watchdog.py --once"
}

# Installa il watchdog in un container Proxmox
install_in_container() {
    local CTID="$1"
    
    log "Installazione Git Update Watchdog nel container ${CTID}..."
    
    # Verifica container
    if ! pct status "${CTID}" &>/dev/null; then
        error "Container ${CTID} non trovato"
        exit 1
    fi
    
    if ! pct status "${CTID}" | grep -q "running"; then
        error "Container ${CTID} non in esecuzione"
        exit 1
    fi
    
    # Verifica prerequisiti nel container
    log "Verifica prerequisiti..."
    if ! pct exec "${CTID}" -- python3 --version &>/dev/null; then
        error "Python3 non trovato nel container ${CTID}"
        exit 1
    fi
    
    if ! pct exec "${CTID}" -- git --version &>/dev/null; then
        error "Git non trovato nel container ${CTID}"
        exit 1
    fi
    
    # Verifica directory agent
    if ! pct exec "${CTID}" -- test -d "${AGENT_DIR}"; then
        error "Directory agent non trovata: ${AGENT_DIR}"
        exit 1
    fi
    
    # Aggiorna repository per ottenere i nuovi file
    log "Aggiornamento repository per ottenere file watchdog..."
    pct exec "${CTID}" -- bash -c "cd ${AGENT_DIR} && git fetch origin main && git checkout origin/main -- git-update-watchdog.py dadude-git-watchdog.service 2>/dev/null || true"
    
    # Verifica che i file esistano (potrebbero essere in dadude-agent/)
    pct exec "${CTID}" -- bash -c "
        if [ -f ${DADUDE_AGENT_DIR}/git-update-watchdog.py ]; then
            cp ${DADUDE_AGENT_DIR}/git-update-watchdog.py ${AGENT_DIR}/
        fi
        if [ -f ${DADUDE_AGENT_DIR}/dadude-git-watchdog.service ]; then
            cp ${DADUDE_AGENT_DIR}/dadude-git-watchdog.service ${AGENT_DIR}/
        fi
    "
    
    # Copia questo script nel container e eseguilo
    log "Esecuzione installazione nel container..."
    
    # Crea script temporaneo
    local TMP_SCRIPT="/tmp/install-watchdog-${CTID}.sh"
    cat > "${TMP_SCRIPT}" << 'INSTALL_SCRIPT'
#!/bin/bash
set -e

AGENT_DIR="/opt/dadude-agent"
DADUDE_AGENT_DIR="${AGENT_DIR}/dadude-agent"

# Trova e copia script
if [ -f "${DADUDE_AGENT_DIR}/git-update-watchdog.py" ]; then
    cp "${DADUDE_AGENT_DIR}/git-update-watchdog.py" "${AGENT_DIR}/"
fi
chmod +x "${AGENT_DIR}/git-update-watchdog.py"

# Crea service file
cat > /etc/systemd/system/dadude-git-watchdog.service << 'EOF'
[Unit]
Description=DaDude Git Update Watchdog
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/dadude-agent
Environment="PYTHONUNBUFFERED=1"
Environment="AGENT_DIR=/opt/dadude-agent"
Environment="UPDATE_CHECK_INTERVAL=3600"
EnvironmentFile=-/opt/dadude-agent/.env.watchdog
ExecStart=/usr/bin/python3 /opt/dadude-agent/git-update-watchdog.py
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal
SyslogIdentifier=dadude-git-watchdog

[Install]
WantedBy=multi-user.target
EOF

# Crea config
if [ ! -f "${AGENT_DIR}/.env.watchdog" ]; then
    cat > "${AGENT_DIR}/.env.watchdog" << 'ENVEOF'
# DaDude Git Watchdog Configuration
#UPDATE_CHECK_INTERVAL=3600
#AGENT_HEALTH_TIMEOUT=120
ENVEOF
fi

# Directory log
mkdir -p "${AGENT_DIR}/logs"

# Systemd
systemctl daemon-reload
systemctl enable dadude-git-watchdog.service
systemctl stop dadude-git-watchdog.service 2>/dev/null || true
systemctl start dadude-git-watchdog.service

# Verifica
sleep 2
systemctl is-active --quiet dadude-git-watchdog.service && echo "SUCCESS" || echo "FAILED"
INSTALL_SCRIPT

    # Push ed esegui nel container
    pct push "${CTID}" "${TMP_SCRIPT}" /tmp/install-watchdog.sh
    local RESULT=$(pct exec "${CTID}" -- bash /tmp/install-watchdog.sh 2>&1)
    
    # Cleanup
    rm -f "${TMP_SCRIPT}"
    pct exec "${CTID}" -- rm -f /tmp/install-watchdog.sh
    
    if echo "${RESULT}" | grep -q "SUCCESS"; then
        success "Git Update Watchdog installato nel container ${CTID}"
        echo ""
        echo "Comandi utili (nel container ${CTID}):"
        echo "  pct exec ${CTID} -- systemctl status dadude-git-watchdog"
        echo "  pct exec ${CTID} -- journalctl -u dadude-git-watchdog -f"
    else
        error "Installazione fallita nel container ${CTID}"
        echo "${RESULT}"
        exit 1
    fi
}

# Installa in tutti i container agent
install_all_containers() {
    log "Ricerca container con agent DaDude..."
    
    local FOUND=0
    
    # Trova tutti i container LXC con l'agent
    for CTID in $(pct list | grep running | awk '{print $1}'); do
        if pct exec "${CTID}" -- test -d /opt/dadude-agent 2>/dev/null; then
            echo ""
            log "Trovato agent nel container ${CTID}"
            install_in_container "${CTID}"
            FOUND=$((FOUND + 1))
        fi
    done
    
    if [ "${FOUND}" -eq 0 ]; then
        warning "Nessun container con agent DaDude trovato"
    else
        echo ""
        success "Installato watchdog in ${FOUND} container"
    fi
}

# Main
main() {
    echo ""
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║         DaDude Git Update Watchdog - Installer             ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    
    if [ "${1:-}" = "--local" ]; then
        # Installazione locale
        install_local
    elif [ "${1:-}" = "--all" ] && is_proxmox_host "${1:-}"; then
        # Installa in tutti i container
        install_all_containers
    elif [ -n "${1:-}" ] && is_proxmox_host "${1:-}"; then
        # Installazione in container specifico
        install_in_container "$1"
    elif is_proxmox_host "${1:-}"; then
        # Nessun argomento su Proxmox
        echo "Uso:"
        echo "  $0 <CTID>       Installa nel container specificato"
        echo "  $0 --all        Installa in tutti i container con agent"
        echo "  $0 --local      Installa localmente (dentro container/VM)"
        echo ""
        exit 1
    else
        # Non siamo su Proxmox, installa localmente
        install_local
    fi
}

main "$@"
