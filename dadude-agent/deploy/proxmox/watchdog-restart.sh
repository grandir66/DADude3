#!/bin/bash
# Watchdog script per riavviare automaticamente i container agent dopo update
# Eseguito sul server Proxmox, monitora i file .restart_required

set -euo pipefail

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Cerca tutti i container LXC con agent Docker
find_agent_containers() {
    pct list | grep running | awk '{print $1}' | while read ctid; do
        if pct exec $ctid -- docker ps --filter name=dadude-agent --format "{{.Names}}" 2>/dev/null | grep -q dadude-agent; then
            echo $ctid
        fi
    done
}

# Controlla se un container ha bisogno di restart
check_restart_flag() {
    local ctid=$1
    local flag_file="/opt/dadude-agent/.restart_required"
    
    if pct exec $ctid -- test -f "$flag_file" 2>/dev/null; then
        return 0  # Flag file esiste
    else
        return 1  # Flag file non esiste
    fi
}

# Riavvia il container agent
restart_agent_container() {
    local ctid=$1
    
    log "Restarting agent container $ctid..."
    
    local compose_dir="/opt/dadude-agent/dadude-agent"
    
    # Rimuovi il flag file
    pct exec $ctid -- rm -f /opt/dadude-agent/.restart_required 2>/dev/null || true
    
    # Riavvia il container
    local result=$(pct exec $ctid -- bash -c "cd $compose_dir && docker compose up -d --force-recreate 2>&1" || echo "ERROR")
    
    if echo "$result" | grep -qi "error\|failed"; then
        error "Failed to restart container $ctid: $result"
        return 1
    else
        success "Container $ctid restarted successfully"
        return 0
    fi
}

# Main loop
main() {
    log "Starting agent restart watchdog..."
    
    while true; do
        # Cerca container con agent
        containers=$(find_agent_containers)
        
        for ctid in $containers; do
            if check_restart_flag $ctid; then
                log "Found restart flag for container $ctid"
                restart_agent_container $ctid
            fi
        done
        
        # Attendi 30 secondi prima del prossimo check
        sleep 30
    done
}

# Se eseguito direttamente, avvia il watchdog
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main
fi

