#!/bin/bash
# Script completo per aggiornare agent DaDude su Proxmox LXC
# Esegue git pull, rebuild Docker e force-recreate del container
# Uso: ./update-agent-remote.sh <proxmox_ip> <container_id> [ssh_user] [ssh_password]

set -euo pipefail

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

PROXMOX_IP="${1:-}"
CONTAINER_ID="${2:-}"
SSH_USER="${3:-root}"
SSH_PASSWORD="${4:-}"

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

if [ -z "$PROXMOX_IP" ] || [ -z "$CONTAINER_ID" ]; then
    error "Uso: $0 <proxmox_ip> <container_id> [ssh_user] [ssh_password]"
    echo ""
    echo "Esempi:"
    echo "  $0 192.168.40.15 600 root"
    echo "  $0 192.168.40.15 610 root mypassword"
    exit 1
fi

log "=========================================="
log "Aggiornamento Agent DaDude"
log "Server Proxmox: $PROXMOX_IP"
log "Container LXC: $CONTAINER_ID"
log "=========================================="

# Comando completo da eseguire sul Proxmox
UPDATE_COMMAND="
set -e
AGENT_DIR=\"/opt/dadude-agent\"
COMPOSE_DIR=\"\${AGENT_DIR}/dadude-agent\"

# Verifica che il container esista
if ! pct status $CONTAINER_ID &>/dev/null; then
    echo \"ERROR: Container $CONTAINER_ID non trovato\"
    exit 1
fi

# Verifica directory agent
if ! pct exec $CONTAINER_ID -- test -d \"\${AGENT_DIR}\" 2>/dev/null; then
    echo \"ERROR: Directory \${AGENT_DIR} non trovata nel container\"
    exit 1
fi

echo \"[1/8] Verifica spazio disco...\"
# Verifica spazio disco disponibile
DISK_USAGE=\$(pct exec $CONTAINER_ID -- df -h / | tail -1 | awk '{print \$5}' | sed 's/%//' || echo '100')
if [ \"\$DISK_USAGE\" -gt 90 ]; then
    echo \"ERROR: Spazio disco insufficiente (utilizzato: \${DISK_USAGE}%)\"
    echo \"SOLUZIONI:\"
    echo \"1. Pulisci spazio nel container:\"
    echo \"   pct exec $CONTAINER_ID -- docker system prune -a -f --volumes\"
    echo \"   pct exec $CONTAINER_ID -- apt-get clean\"
    echo \"   pct exec $CONTAINER_ID -- journalctl --vacuum-time=7d\"
    echo \"\"
    echo \"2. Verifica spazio disponibile:\"
    echo \"   pct exec $CONTAINER_ID -- df -h\"
    exit 1
elif [ \"\$DISK_USAGE\" -gt 80 ]; then
    echo \"   WARNING: Spazio disco limitato (\${DISK_USAGE}%), pulizia automatica...\"
    # Pulisci cache Docker (container fermati, reti non utilizzate, build cache)
    echo \"   Pulizia cache Docker...\"
    pct exec $CONTAINER_ID -- docker system prune -f 2>/dev/null || true
    # Pulisci anche immagini non utilizzate se ancora sopra 85%
    sleep 1
    DISK_USAGE_AFTER=\$(pct exec $CONTAINER_ID -- df -h / | tail -1 | awk '{print \$5}' | sed 's/%//' || echo '100')
    if [ \"\$DISK_USAGE_AFTER\" -gt 85 ]; then
        echo \"   Spazio ancora limitato (\${DISK_USAGE_AFTER}%), pulizia immagini non utilizzate...\"
        pct exec $CONTAINER_ID -- docker image prune -f 2>/dev/null || true
    fi
    echo \"   Pulizia completata\"
else
    echo \"   Spazio disco: OK (\${DISK_USAGE}% utilizzato)\"
fi

echo \"[2/8] Verifica connettività internet e DNS...\"
# Verifica connettività internet prima
if ! pct exec $CONTAINER_ID -- ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
    echo \"ERROR: Container non ha connettività internet\"
    echo \"SOLUZIONE: Verifica configurazione rete del container LXC\"
    exit 1
fi
echo \"   Connettività internet: OK\"

# Verifica se il container usa DHCP
GATEWAY=\$(pct exec $CONTAINER_ID -- ip route | grep default | awk '{print \$3}' | head -1 || echo '')
echo \"   Gateway: \$GATEWAY\"

# Verifica risoluzione DNS - prova più percorsi per trovare DNS configurato
DNS_SERVERS=\"\"
DNS_FOUND=false

# Metodo 1: /etc/resolv.conf (può essere gestito da DHCP o systemd-resolved)
if pct exec $CONTAINER_ID -- test -f /etc/resolv.conf 2>/dev/null; then
    RESOLV_CONTENT=\$(pct exec $CONTAINER_ID -- cat /etc/resolv.conf 2>/dev/null || echo '')
    if echo \"\$RESOLV_CONTENT\" | grep -q nameserver; then
        DNS_SERVERS=\$(echo \"\$RESOLV_CONTENT\" | grep nameserver | awk '{print \$2}' | head -1 || echo '')
        if [ -n \"\$DNS_SERVERS\" ]; then
            echo \"   DNS da /etc/resolv.conf: \$DNS_SERVERS\"
            DNS_FOUND=true
        fi
    fi
fi

# Metodo 2: systemd-resolved (se attivo)
if [ \"\$DNS_FOUND\" = false ] && pct exec $CONTAINER_ID -- systemctl is-active systemd-resolved >/dev/null 2>&1; then
    if pct exec $CONTAINER_ID -- test -f /run/systemd/resolve/resolv.conf 2>/dev/null; then
        DNS_SERVERS=\$(pct exec $CONTAINER_ID -- cat /run/systemd/resolve/resolv.conf 2>/dev/null | grep nameserver | awk '{print \$2}' | head -1 || echo '')
        if [ -n \"\$DNS_SERVERS\" ]; then
            echo \"   DNS da systemd-resolved: \$DNS_SERVERS\"
            DNS_FOUND=true
        fi
    fi
fi

# Metodo 3: Verifica configurazione DHCP (se il container usa DHCP)
if [ \"\$DNS_FOUND\" = false ]; then
    echo \"   Verifica configurazione DHCP...\"
    # Prova a forzare il rinnovo DHCP se disponibile
    if pct exec $CONTAINER_ID -- which dhclient >/dev/null 2>&1; then
        echo \"   Tentativo rinnovo DHCP...\"
        pct exec $CONTAINER_ID -- dhclient -r 2>/dev/null || true
        sleep 1
        pct exec $CONTAINER_ID -- dhclient 2>/dev/null || true
        sleep 2
        # Ricontrolla /etc/resolv.conf dopo rinnovo DHCP
        if pct exec $CONTAINER_ID -- test -f /etc/resolv.conf 2>/dev/null; then
            DNS_SERVERS=\$(pct exec $CONTAINER_ID -- cat /etc/resolv.conf 2>/dev/null | grep nameserver | awk '{print \$2}' | head -1 || echo '')
            if [ -n \"\$DNS_SERVERS\" ]; then
                echo \"   DNS dopo rinnovo DHCP: \$DNS_SERVERS\"
                DNS_FOUND=true
            fi
        fi
    fi
fi

# Metodo 4: Verifica configurazione Proxmox
if [ \"\$DNS_FOUND\" = false ]; then
    PROXMOX_DNS=\$(ssh -o StrictHostKeyChecking=no root@$PROXMOX_IP \"pct config $CONTAINER_ID | grep nameserver | awk '{print \\\$2}'\" 2>/dev/null | head -1 || echo '')
    if [ -n \"\$PROXMOX_DNS\" ]; then
        DNS_SERVERS=\"\$PROXMOX_DNS\"
        echo \"   DNS dalla configurazione Proxmox: \$DNS_SERVERS\"
        DNS_FOUND=true
    fi
fi

# Se ancora non trovato, usa il gateway come DNS (comune per container DHCP)
if [ \"\$DNS_FOUND\" = false ] && [ -n \"\$GATEWAY\" ]; then
    echo \"   WARNING: DNS non trovato, configurazione gateway come DNS: \$GATEWAY\"
    DNS_SERVERS=\"\$GATEWAY\"
    # Crea/aggiorna /etc/resolv.conf con gateway come DNS
    pct exec $CONTAINER_ID -- bash -c \"cat > /etc/resolv.conf << EOF
nameserver \$GATEWAY
nameserver 8.8.8.8
EOF
\" 2>/dev/null || true
    echo \"   Configurato /etc/resolv.conf con gateway e 8.8.8.8\"
    DNS_FOUND=true
fi

# Verifica risoluzione DNS
if [ -n \"\$DNS_SERVERS\" ]; then
    echo \"   DNS server configurato: \$DNS_SERVERS\"
    # Attendi un momento per permettere al DNS di essere disponibile
    sleep 1
    
    # Prova risoluzione DNS
    if pct exec $CONTAINER_ID -- nslookup github.com >/dev/null 2>&1 || pct exec $CONTAINER_ID -- getent hosts github.com >/dev/null 2>&1; then
        echo \"   Risoluzione DNS: OK\"
    else
        echo \"   WARNING: DNS configurato ma risoluzione non funziona\"
        echo \"   Uso IP diretto di GitHub come fallback...\"
        # Verifica se già presente in /etc/hosts
        if ! pct exec $CONTAINER_ID -- grep -q \"github.com\" /etc/hosts 2>/dev/null; then
            # Aggiungi IP diretto di GitHub (usa IP più recente e affidabile)
            pct exec $CONTAINER_ID -- bash -c \"echo '140.82.121.4 github.com' >> /etc/hosts\" 2>/dev/null || true
            echo \"   Aggiunto IP diretto di GitHub in /etc/hosts\"
        fi
    fi
else
    echo \"   WARNING: Impossibile trovare DNS, uso IP diretto di GitHub\"
    if ! pct exec $CONTAINER_ID -- grep -q \"github.com\" /etc/hosts 2>/dev/null; then
        pct exec $CONTAINER_ID -- bash -c \"echo '140.82.121.4 github.com' >> /etc/hosts\" 2>/dev/null || true
        echo \"   Aggiunto IP diretto di GitHub in /etc/hosts\"
    fi
fi

echo \"[3/8] Verifica repository git...\"
if ! pct exec $CONTAINER_ID -- test -d \"\${AGENT_DIR}/.git\" 2>/dev/null; then
    echo \"WARNING: Directory non è un repository git, inizializzazione...\"
    pct exec $CONTAINER_ID -- bash -c \"cd \${AGENT_DIR} && git init && git remote add origin https://github.com/grandir66/Dadude.git || true\"
fi

echo \"[4/8] Fetch aggiornamenti da GitHub...\"
FETCH_OUTPUT=\$(pct exec $CONTAINER_ID -- bash -c \"cd \${AGENT_DIR} && git fetch origin main 2>&1\" || echo \"FETCH_FAILED\")
if echo \"\$FETCH_OUTPUT\" | grep -q \"FETCH_FAILED\|fatal\|Could not resolve host\"; then
    echo \"ERROR: Git fetch fallito\"
    echo \"Output: \$FETCH_OUTPUT\"
    echo \"\"
    echo \"SOLUZIONI:\"
    echo \"1. Configura DNS nel container:\"
    echo \"   pct set $CONTAINER_ID --nameserver 8.8.8.8\"
    echo \"\"
    echo \"2. Verifica connettività internet:\"
    echo \"   pct exec $CONTAINER_ID -- ping -c 3 8.8.8.8\"
    echo \"\"
    echo \"3. Verifica gateway del container:\"
    echo \"   pct exec $CONTAINER_ID -- ip route\"
    exit 1
fi

echo \"[5/8] Backup file di configurazione...\"
# Backup file .env principale
ENV_BACKUP_ROOT=\"\"
ENV_BACKUP_SUBDIR=\"\"
if pct exec $CONTAINER_ID -- test -f \"\${AGENT_DIR}/.env\" 2>/dev/null; then
    ENV_BACKUP_ROOT=\$(mktemp)
    pct exec $CONTAINER_ID -- cat \"\${AGENT_DIR}/.env\" > \"\$ENV_BACKUP_ROOT\"
    echo \"   Backup .env principale salvato\"
fi

# Backup file .env nella subdirectory
if pct exec $CONTAINER_ID -- test -f \"\${COMPOSE_DIR}/.env\" 2>/dev/null; then
    ENV_BACKUP_SUBDIR=\$(mktemp)
    pct exec $CONTAINER_ID -- cat \"\${COMPOSE_DIR}/.env\" > \"\$ENV_BACKUP_SUBDIR\"
    echo \"   Backup .env subdirectory salvato\"
fi

# Backup file config personalizzati
CONFIG_BACKUP=\"\"
if pct exec $CONTAINER_ID -- test -d \"\${COMPOSE_DIR}/config\" 2>/dev/null; then
    CONFIG_BACKUP=\$(mktemp -d)
    pct exec $CONTAINER_ID -- bash -c \"cd \${COMPOSE_DIR} && tar czf - config/\" 2>/dev/null | tar xzf - -C \"\$CONFIG_BACKUP\" 2>/dev/null || true
    if [ -d \"\$CONFIG_BACKUP/config\" ]; then
        echo \"   Backup directory config salvato\"
    fi
fi

echo \"[6/8] Verifica versione corrente...\"
CURRENT_COMMIT=\$(pct exec $CONTAINER_ID -- bash -c \"cd \${AGENT_DIR} && git rev-parse HEAD 2>/dev/null || echo 'unknown'\")
REMOTE_COMMIT=\$(pct exec $CONTAINER_ID -- bash -c \"cd \${AGENT_DIR} && git rev-parse origin/main 2>/dev/null || echo 'unknown'\")
CURRENT_VERSION=\$(pct exec $CONTAINER_ID -- bash -c \"cd \${AGENT_DIR}/dadude-agent && grep -oP 'AGENT_VERSION\\s*=\\s*\\\"\\K[^\\\"]+' app/agent.py 2>/dev/null || echo 'unknown'\")

echo \"   Commit corrente: \${CURRENT_COMMIT:0:8}\"
echo \"   Commit remoto:   \${REMOTE_COMMIT:0:8}\"
echo \"   Versione corrente: v\${CURRENT_VERSION}\"

if [ \"\$CURRENT_COMMIT\" = \"\$REMOTE_COMMIT\" ] && [ \"\$CURRENT_COMMIT\" != \"unknown\" ]; then
    echo \"[INFO] Agent già aggiornato all'ultima versione\"
    # Cleanup backup files
    [ -n \"\$ENV_BACKUP_ROOT\" ] && [ -f \"\$ENV_BACKUP_ROOT\" ] && rm -f \"\$ENV_BACKUP_ROOT\"
    [ -n \"\$ENV_BACKUP_SUBDIR\" ] && [ -f \"\$ENV_BACKUP_SUBDIR\" ] && rm -f \"\$ENV_BACKUP_SUBDIR\"
    [ -n \"\$CONFIG_BACKUP\" ] && [ -d \"\$CONFIG_BACKUP\" ] && rm -rf \"\$CONFIG_BACKUP\"
    exit 0
fi

echo \"[7/8] Applicazione aggiornamenti...\"
pct exec $CONTAINER_ID -- bash -c \"cd \${AGENT_DIR} && git reset --hard origin/main 2>&1\" || {
    echo \"ERROR: Git reset fallito\"
    # Ripristina backup in caso di errore
    if [ -n \"\$ENV_BACKUP_ROOT\" ] && [ -f \"\$ENV_BACKUP_ROOT\" ]; then
        pct exec $CONTAINER_ID -- bash -c \"cat > \${AGENT_DIR}/.env\" < \"\$ENV_BACKUP_ROOT\"
        echo \"   .env ripristinato dopo errore\"
    fi
    exit 1
}

NEW_VERSION=\$(pct exec $CONTAINER_ID -- bash -c \"cd \${AGENT_DIR}/dadude-agent && grep -oP 'AGENT_VERSION\\s*=\\s*\\\"\\K[^\\\"]+' app/agent.py 2>/dev/null || echo 'unknown'\")
echo \"   Nuova versione: v\${NEW_VERSION}\"

echo \"[8/8] Ripristino file di configurazione...\"
# Ripristina .env principale
if [ -n \"\$ENV_BACKUP_ROOT\" ] && [ -f \"\$ENV_BACKUP_ROOT\" ]; then
    pct exec $CONTAINER_ID -- bash -c \"cat > \${AGENT_DIR}/.env\" < \"\$ENV_BACKUP_ROOT\"
    echo \"   .env principale ripristinato\"
fi

# Ripristina .env subdirectory
if [ -n \"\$ENV_BACKUP_SUBDIR\" ] && [ -f \"\$ENV_BACKUP_SUBDIR\" ]; then
    pct exec $CONTAINER_ID -- mkdir -p \"\${COMPOSE_DIR}\" 2>/dev/null || true
    pct exec $CONTAINER_ID -- bash -c \"cat > \${COMPOSE_DIR}/.env\" < \"\$ENV_BACKUP_SUBDIR\"
    echo \"   .env subdirectory ripristinato\"
elif [ -n \"\$ENV_BACKUP_ROOT\" ] && [ -f \"\$ENV_BACKUP_ROOT\" ]; then
    # Se non esiste backup subdirectory, copia dalla root
    pct exec $CONTAINER_ID -- mkdir -p \"\${COMPOSE_DIR}\" 2>/dev/null || true
    pct exec $CONTAINER_ID -- cp \"\${AGENT_DIR}/.env\" \"\${COMPOSE_DIR}/.env\" 2>/dev/null || true
    echo \"   .env copiato in subdirectory\"
fi

# IMPORTANTE: Assicura che .env esista nel percorso corretto per docker-compose
# docker-compose.yml legge da /opt/dadude-agent/.env
if [ -n \"\$ENV_BACKUP_ROOT\" ] && [ -f \"\$ENV_BACKUP_ROOT\" ]; then
    # Verifica che il file .env principale esista e sia corretto
    if ! pct exec $CONTAINER_ID -- test -f \"\${AGENT_DIR}/.env\" 2>/dev/null; then
        pct exec $CONTAINER_ID -- bash -c \"cat > \${AGENT_DIR}/.env\" < \"\$ENV_BACKUP_ROOT\"
        echo \"   .env principale ripristinato per docker-compose\"
    fi
fi

# Ripristina config personalizzati (solo se esistevano)
if [ -n \"\$CONFIG_BACKUP\" ] && [ -d \"\$CONFIG_BACKUP/config\" ]; then
    pct exec $CONTAINER_ID -- mkdir -p \"\${COMPOSE_DIR}/config\" 2>/dev/null || true
    cd \"\$CONFIG_BACKUP\" && tar czf - config/ | pct exec $CONTAINER_ID -- bash -c \"cd \${COMPOSE_DIR} && tar xzf -\" 2>/dev/null || true
    echo \"   Directory config ripristinata\"
fi

echo \"[9/9] Rebuild immagine Docker...\"
if ! pct exec $CONTAINER_ID -- test -d \"\${COMPOSE_DIR}\" 2>/dev/null; then
    echo \"WARNING: Directory \${COMPOSE_DIR} non trovata, creazione...\"
    pct exec $CONTAINER_ID -- mkdir -p \"\${COMPOSE_DIR}\"
fi

# Verifica docker-compose.yml
if ! pct exec $CONTAINER_ID -- test -f \"\${COMPOSE_DIR}/docker-compose.yml\" 2>/dev/null; then
    echo \"WARNING: docker-compose.yml non trovato, copia da template...\"
    pct exec $CONTAINER_ID -- bash -c \"cp -r \${AGENT_DIR}/dadude-agent/* \${COMPOSE_DIR}/ 2>/dev/null || true\"
fi

# Rebuild immagine
pct exec $CONTAINER_ID -- bash -c \"cd \${COMPOSE_DIR} && docker compose build --quiet 2>&1\" || {
    echo \"ERROR: Docker build fallito\"
    exit 1
}

echo \"[10/10] Riavvio container con force-recreate...\"
# Stop container esistente
pct exec $CONTAINER_ID -- docker stop dadude-agent 2>/dev/null || true
sleep 2

# Force recreate
pct exec $CONTAINER_ID -- bash -c \"cd \${COMPOSE_DIR} && docker compose up -d --force-recreate 2>&1\" || {
    echo \"ERROR: Avvio container fallito\"
    exit 1
}

# Attendi avvio
echo \"   Attendo avvio container...\"
sleep 5

# Verifica stato - controlla più volte per container che si riavviano
MAX_CHECKS=6
CONTAINER_UP=false
for i in \$(seq 1 \$MAX_CHECKS); do
    CONTAINER_STATUS=\$(pct exec $CONTAINER_ID -- docker ps --filter name=dadude-agent --format '{{.Status}}' 2>/dev/null || echo '')
    if echo \"\$CONTAINER_STATUS\" | grep -q \"Up\" && ! echo \"\$CONTAINER_STATUS\" | grep -q \"Restarting\"; then
        CONTAINER_UP=true
        break
    fi
    sleep 2
done

if [ \"\$CONTAINER_UP\" = true ]; then
    echo \"SUCCESS: Container avviato correttamente\"
    
    # Verifica versione nei log
    sleep 3
    LOG_VERSION=\$(pct exec $CONTAINER_ID -- docker logs dadude-agent --tail 20 2>&1 | grep -oP 'DaDude Agent v\\K[0-9.]+' | head -1 || echo '')
    if [ -n \"\$LOG_VERSION\" ]; then
        echo \"   Versione nei log: v\$LOG_VERSION\"
    fi
else
    echo \"ERROR: Container non avviato correttamente o in loop di riavvio\"
    echo \"\"
    echo \"Stato container:\"
    pct exec $CONTAINER_ID -- docker ps -a --filter name=dadude-agent
    echo \"\"
    echo \"Ultimi log del container (ultimi 50 righe):\"
    pct exec $CONTAINER_ID -- docker logs dadude-agent --tail 50 2>&1 || echo \"Impossibile leggere log\"
    echo \"\"
    echo \"SOLUZIONI:\"
    echo \"1. Verifica configurazione .env:\"
    echo \"   pct exec $CONTAINER_ID -- cat /opt/dadude-agent/dadude-agent/.env\"
    echo \"\"
    echo \"2. Verifica docker-compose.yml:\"
    echo \"   pct exec $CONTAINER_ID -- cat /opt/dadude-agent/dadude-agent/docker-compose.yml\"
    echo \"\"
    echo \"3. Prova a riavviare manualmente:\"
    echo \"   pct exec $CONTAINER_ID -- docker restart dadude-agent\"
    echo \"\"
    echo \"4. Verifica log in tempo reale:\"
    echo \"   pct exec $CONTAINER_ID -- docker logs -f dadude-agent\"
    exit 1
fi

echo \"==========================================\"
echo \"Update completato con successo!\"
echo \"Versione: v\${NEW_VERSION}\"
echo \"==========================================\"

# Cleanup backup files
[ -n \"\$ENV_BACKUP_ROOT\" ] && [ -f \"\$ENV_BACKUP_ROOT\" ] && rm -f \"\$ENV_BACKUP_ROOT\"
[ -n \"\$ENV_BACKUP_SUBDIR\" ] && [ -f \"\$ENV_BACKUP_SUBDIR\" ] && rm -f \"\$ENV_BACKUP_SUBDIR\"
[ -n \"\$CONFIG_BACKUP\" ] && [ -d \"\$CONFIG_BACKUP\" ] && rm -rf \"\$CONFIG_BACKUP\"
"

# Esegui comando via SSH
if [ -n "$SSH_PASSWORD" ]; then
    if ! command -v sshpass &> /dev/null; then
        error "sshpass non installato. Installa con: apt-get install sshpass"
        exit 1
    fi
    sshpass -p "$SSH_PASSWORD" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$SSH_USER@$PROXMOX_IP" "$UPDATE_COMMAND"
else
    ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$SSH_USER@$PROXMOX_IP" "$UPDATE_COMMAND"
fi

success "Script completato!"

