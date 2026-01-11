#!/bin/bash
#
# DaDude Agent v3.1+ - Installazione Nativa su Proxmox LXC
# ==========================================================
# Crea un container LXC nativo con Python virtualenv (NO Docker)
# Struttura pulita: /opt/dadude-agent (agent) + /opt/dadude-updater (watchdog)
#
# Uso:
#   curl -fsSL https://raw.githubusercontent.com/grandir66/DADude3/main/dadude-agent/deploy/proxmox/install-native.sh | bash
#   oppure: bash install-native.sh [opzioni]
#
# Opzioni:
#   --server-url URL      URL server DaDude (default: https://dadude.domarc.it:8000)
#   --agent-name NAME     Nome descrittivo agent (obbligatorio)
#   --agent-token TOKEN   Token autenticazione (auto-generato se vuoto)
#   --ctid ID             ID container Proxmox
#   --hostname NAME       Hostname container
#   --bridge BRIDGE       Bridge Proxmox (default: vmbr0)
#   --vlan TAG            VLAN tag (opzionale)
#   --ip CIDR             IP statico (es: 192.168.1.100/24) o "dhcp"
#   --gateway IP          Gateway
#   --storage STORAGE     Storage Proxmox (default: local-lvm)
#   --memory MB           RAM in MB (default: 512)
#   --disk GB             Disco in GB (default: 4)
#

set -e

# Colori
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${GREEN}[DaDude]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }

# Banner
echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║     DaDude Agent v3.1+ - Installazione Nativa            ║"
echo "║        Modalità: WebSocket mTLS (Nativo, no Docker)      ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Valori default
DEFAULT_SERVER_URL="https://dadude.domarc.it:8000"
GIT_REPO="https://github.com/grandir66/DADude3.git"
CTID=""
HOSTNAME=""
BRIDGE=""
VLAN=""
STORAGE=""
TEMPLATE_STORAGE="local"
MEMORY=""
DISK=""
IP_CONFIG=""
GATEWAY=""
SERVER_URL=""
AGENT_TOKEN=""
AGENT_NAME=""
DNS_SERVER=""

# Parse argomenti da linea di comando (opzionale)
while [[ $# -gt 0 ]]; do
    case $1 in
        --server-url) SERVER_URL="$2"; shift 2 ;;
        --agent-token) AGENT_TOKEN="$2"; shift 2 ;;
        --agent-name) AGENT_NAME="$2"; shift 2 ;;
        --ctid) CTID="$2"; shift 2 ;;
        --hostname) HOSTNAME="$2"; shift 2 ;;
        --ip) IP_CONFIG="$2"; shift 2 ;;
        --gateway) GATEWAY="$2"; shift 2 ;;
        --dns) DNS_SERVER="$2"; shift 2 ;;
        --bridge) BRIDGE="$2"; shift 2 ;;
        --vlan) VLAN="$2"; shift 2 ;;
        --storage) STORAGE="$2"; shift 2 ;;
        --memory) MEMORY="$2"; shift 2 ;;
        --disk) DISK="$2"; shift 2 ;;
        --help)
            echo "Uso: $0 [opzioni]"
            echo ""
            echo "Se non vengono forniti parametri, lo script li chiederà interattivamente."
            echo ""
            echo "Opzioni:"
            echo "  --server-url URL     URL server DaDude (default: $DEFAULT_SERVER_URL)"
            echo "  --agent-name NAME    Nome identificativo agent"
            echo "  --agent-token TOKEN  Token agent (auto-generato se vuoto)"
            echo "  --ctid ID            ID container LXC"
            echo "  --hostname NAME      Hostname del container"
            echo "  --bridge BRIDGE      Bridge di rete (es: vmbr0)"
            echo "  --vlan TAG           VLAN tag (opzionale)"
            echo "  --ip IP/MASK         IP statico con netmask (es: 192.168.1.100/24) o 'dhcp'"
            echo "  --gateway IP         Gateway di rete"
            echo "  --dns IP             Server DNS (default: da DHCP o gateway)"
            echo "  --storage NAME       Storage per il container (default: local-lvm)"
            echo "  --memory MB          Memoria RAM in MB (default: 512)"
            echo "  --disk GB            Spazio disco in GB (default: 4)"
            exit 0
            ;;
        *) echo -e "${RED}Opzione sconosciuta: $1${NC}"; exit 1 ;;
    esac
done

# Verifica Proxmox
if ! command -v pct &> /dev/null; then
    error "Questo script deve essere eseguito su un host Proxmox VE"
fi

# =============================================================================
# CONFIGURAZIONE INTERATTIVA
# =============================================================================

echo -e "${YELLOW}Configurazione Agent DaDude${NC}"
echo "Inserisci i parametri richiesti (premi Invio per accettare i default tra parentesi)"
echo ""

# === CONFIGURAZIONE SERVER ===
echo -e "${BLUE}--- Server DaDude ---${NC}"

while [ -z "$SERVER_URL" ]; do
    if [ -t 0 ]; then
        read -p "URL Server DaDude [$DEFAULT_SERVER_URL]: " SERVER_URL
    fi
    SERVER_URL=${SERVER_URL:-$DEFAULT_SERVER_URL}
done
echo -e "${GREEN}Server: $SERVER_URL${NC}"

# === CONFIGURAZIONE AGENT ===
echo -e "\n${BLUE}--- Identificazione Agent ---${NC}"

while [ -z "$AGENT_NAME" ]; do
    if [ -t 0 ]; then
        read -p "Nome Agent (es: agent-sede-milano): " AGENT_NAME
    fi
    if [ -z "$AGENT_NAME" ]; then
        echo -e "${YELLOW}⚠ Nome agent è obbligatorio${NC}"
        if [ ! -t 0 ]; then
            error "AGENT_NAME è obbligatorio. Usa --agent-name o esegui lo script interattivamente."
        fi
    fi
done

if [ -z "$AGENT_TOKEN" ]; then
    if [ -t 0 ]; then
        read -p "Token Agent (lascia vuoto per generare automaticamente): " AGENT_TOKEN
    fi
    if [ -z "$AGENT_TOKEN" ]; then
        AGENT_TOKEN=$(openssl rand -hex 24)
        echo -e "${GREEN}Token generato: ${AGENT_TOKEN}${NC}"
    fi
fi

# Genera agent ID univoco
AGENT_ID="agent-${AGENT_NAME}-$(date +%s | tail -c 5)"

# === CONFIGURAZIONE CONTAINER ===
echo -e "\n${BLUE}--- Container LXC ---${NC}"

if [ -z "$CTID" ]; then
    SUGGESTED_CTID=$(pvesh get /cluster/nextid 2>/dev/null || echo "100")
    read -p "ID Container [$SUGGESTED_CTID]: " CTID
    CTID=${CTID:-$SUGGESTED_CTID}
fi

if [ -z "$HOSTNAME" ]; then
    SUGGESTED_HOSTNAME="dadude-agent-${AGENT_NAME}"
    read -p "Hostname container [$SUGGESTED_HOSTNAME]: " HOSTNAME
    HOSTNAME=${HOSTNAME:-$SUGGESTED_HOSTNAME}
fi

if [ -z "$STORAGE" ]; then
    echo ""
    echo -e "${YELLOW}Storage disponibili per container:${NC}"
    AVAILABLE_STORAGES=$(pvesm status 2>/dev/null | grep "active" | awk '{print $1}')
    
    i=1
    declare -a STORAGE_OPTIONS
    for s in $AVAILABLE_STORAGES; do
        SIZE=$(pvesm status 2>/dev/null | grep "^$s " | awk '{print $5}')
        USED=$(pvesm status 2>/dev/null | grep "^$s " | awk '{print $4}')
        echo "  $i) $s (usato: ${USED:-?}, totale: ${SIZE:-?})"
        STORAGE_OPTIONS[$i]=$s
        ((i++))
    done
    
    if [ ${#STORAGE_OPTIONS[@]} -eq 0 ]; then
        STORAGE="local-lvm"
    elif [ ${#STORAGE_OPTIONS[@]} -eq 1 ]; then
        STORAGE="${STORAGE_OPTIONS[1]}"
        echo -e "${GREEN}Selezionato automaticamente: $STORAGE${NC}"
    else
        read -p "Scegli storage [1-$((i-1))]: " STORAGE_CHOICE
        if [ -n "$STORAGE_CHOICE" ] && [ -n "${STORAGE_OPTIONS[$STORAGE_CHOICE]}" ]; then
            STORAGE="${STORAGE_OPTIONS[$STORAGE_CHOICE]}"
        else
            STORAGE="${STORAGE_OPTIONS[1]}"
        fi
    fi
    echo -e "${GREEN}Storage selezionato: $STORAGE${NC}"
fi

if [ -z "$MEMORY" ]; then
    read -p "Memoria RAM in MB [512]: " MEMORY
    MEMORY=${MEMORY:-512}
fi

if [ -z "$DISK" ]; then
    read -p "Disco in GB [4]: " DISK
    DISK=${DISK:-4}
fi

# === CONFIGURAZIONE RETE ===
echo -e "\n${BLUE}--- Configurazione Rete ---${NC}"

if [ -z "$BRIDGE" ]; then
    echo ""
    echo -e "${YELLOW}Bridge di rete disponibili:${NC}"
    AVAILABLE_BRIDGES=$(ip link show type bridge 2>/dev/null | grep -oP '^\d+: \K[^:]+' | grep -E '^vmbr')
    
    i=1
    declare -a BRIDGE_OPTIONS
    for b in $AVAILABLE_BRIDGES; do
        BRIDGE_IP=$(ip -4 addr show $b 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
        if [ -n "$BRIDGE_IP" ]; then
            echo "  $i) $b (IP: $BRIDGE_IP)"
        else
            echo "  $i) $b"
        fi
        BRIDGE_OPTIONS[$i]=$b
        ((i++))
    done
    
    if [ ${#BRIDGE_OPTIONS[@]} -eq 0 ]; then
        read -p "Nessun bridge trovato. Inserisci nome bridge [vmbr0]: " BRIDGE
        BRIDGE=${BRIDGE:-vmbr0}
    elif [ ${#BRIDGE_OPTIONS[@]} -eq 1 ]; then
        BRIDGE="${BRIDGE_OPTIONS[1]}"
        echo -e "${GREEN}Selezionato automaticamente: $BRIDGE${NC}"
    else
        read -p "Scegli bridge [1-$((i-1))]: " BRIDGE_CHOICE
        if [ -n "$BRIDGE_CHOICE" ] && [ -n "${BRIDGE_OPTIONS[$BRIDGE_CHOICE]}" ]; then
            BRIDGE="${BRIDGE_OPTIONS[$BRIDGE_CHOICE]}"
        else
            BRIDGE="${BRIDGE_OPTIONS[1]}"
        fi
    fi
    echo -e "${GREEN}Bridge selezionato: $BRIDGE${NC}"
fi

# VLAN
if [ -z "$VLAN" ]; then
    CONFIGURED_VLANS=$(grep -oP "bridge-vids \K[\d\s-]+" /etc/network/interfaces 2>/dev/null | tr ' ' '\n' | grep -E "^[0-9]+$" | head -5)
    if [ -n "$CONFIGURED_VLANS" ]; then
        echo -e "${YELLOW}VLAN rilevate: $CONFIGURED_VLANS${NC}"
    fi
    read -p "VLAN tag (lascia vuoto se non usi VLAN): " VLAN
fi

# IP Configuration
if [ -z "$IP_CONFIG" ]; then
    echo ""
    echo -e "${YELLOW}Configurazione IP:${NC}"
    echo "  1) DHCP (automatico)"
    echo "  2) IP Statico"
    read -p "Scegli [1]: " IP_MODE
    IP_MODE=${IP_MODE:-1}

    if [ "$IP_MODE" == "1" ]; then
        IP_CONFIG="dhcp"
        GATEWAY=""
        echo -e "${GREEN}Modalità DHCP selezionata${NC}"
    else
        # Suggerisci rete basandosi su bridge
        SUGGESTED_NETWORK=$(ip -4 addr show $BRIDGE 2>/dev/null | grep -oP 'inet \K[\d.]+/\d+' | head -1)
        if [ -n "$SUGGESTED_NETWORK" ]; then
            SUGGESTED_PREFIX=$(echo $SUGGESTED_NETWORK | grep -oP '[\d.]+' | head -1 | sed 's/\.[0-9]*$//')
            SUGGESTED_MASK=$(echo $SUGGESTED_NETWORK | grep -oP '/\d+')
            echo -e "${YELLOW}Rete rilevata: ${SUGGESTED_PREFIX}.0${SUGGESTED_MASK}${NC}"
        fi

        while [ -z "$IP_CONFIG" ] || [ "$IP_CONFIG" == "dhcp" ]; do
            if [ -n "$SUGGESTED_PREFIX" ]; then
                read -p "IP/Netmask (es: ${SUGGESTED_PREFIX}.100${SUGGESTED_MASK:-/24}): " IP_CONFIG
            else
                read -p "IP/Netmask (es: 192.168.1.100/24): " IP_CONFIG
            fi
        done

        # Gateway
        IP_PREFIX=$(echo $IP_CONFIG | grep -oP '[\d.]+' | head -1 | sed 's/\.[0-9]*$//')
        SUGGESTED_GW="${IP_PREFIX}.1"
        
        while [ -z "$GATEWAY" ]; do
            read -p "Gateway [$SUGGESTED_GW]: " GATEWAY
            GATEWAY=${GATEWAY:-$SUGGESTED_GW}
        done
    fi
fi

# DNS Server - default da DHCP o gateway
if [ -z "$DNS_SERVER" ]; then
    if [ "$IP_CONFIG" == "dhcp" ]; then
        # Per DHCP, usa il DNS del sistema Proxmox
        SYSTEM_DNS=$(grep -m1 "nameserver" /etc/resolv.conf 2>/dev/null | awk '{print $2}')
        DNS_SERVER=${SYSTEM_DNS:-""}  # Vuoto = usa DHCP
        if [ -n "$DNS_SERVER" ]; then
            echo -e "${GREEN}DNS dal sistema: $DNS_SERVER${NC}"
        else
            echo -e "${GREEN}DNS: verrà assegnato via DHCP${NC}"
        fi
    else
        # Per IP statico, suggerisci il gateway
        read -p "Server DNS [${GATEWAY}]: " DNS_SERVER
        DNS_SERVER=${DNS_SERVER:-$GATEWAY}
    fi
fi

# Verifica se container esiste già
while pct status $CTID &>/dev/null; do
    EXISTING_NAME=$(pct config $CTID 2>/dev/null | grep "^hostname:" | awk '{print $2}')
    NEXT_FREE=$(pvesh get /cluster/nextid 2>/dev/null || echo "$((CTID + 1))")
    
    echo ""
    echo -e "${RED}══════════════════════════════════════════════════════════${NC}"
    echo -e "${RED}  ⚠️  ATTENZIONE: Container $CTID esiste già!${NC}"
    echo -e "${RED}══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Hostname: ${YELLOW}${EXISTING_NAME:-sconosciuto}${NC}"
    echo -e "  Status:   $(pct status $CTID 2>/dev/null | awk '{print $2}')"
    echo ""
    echo -e "Opzioni:"
    echo -e "  1) Usa un altro ID (prossimo libero: ${GREEN}$NEXT_FREE${NC})"
    echo -e "  2) Elimina container $CTID e continua"
    echo -e "  3) Annulla installazione"
    echo ""
    read -p "Scegli [1]: " CONFLICT_CHOICE
    CONFLICT_CHOICE=${CONFLICT_CHOICE:-1}
    
    case $CONFLICT_CHOICE in
        1)
            read -p "Nuovo CTID [$NEXT_FREE]: " NEW_CTID
            CTID=${NEW_CTID:-$NEXT_FREE}
            ;;
        2)
            echo -e "${YELLOW}Elimino container $CTID...${NC}"
            pct stop $CTID 2>/dev/null || true
            sleep 2
            pct destroy $CTID --force 2>/dev/null || true
            echo -e "${GREEN}Container $CTID eliminato${NC}"
            ;;
        3)
            echo -e "${YELLOW}Installazione annullata.${NC}"
            exit 1
            ;;
        *)
            read -p "Nuovo CTID [$NEXT_FREE]: " NEW_CTID
            CTID=${NEW_CTID:-$NEXT_FREE}
            ;;
    esac
done

# =============================================================================
# RIEPILOGO CONFIGURAZIONE
# =============================================================================

echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}                    RIEPILOGO CONFIGURAZIONE              ${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BLUE}Server:${NC}"
echo "    URL Server:    $SERVER_URL"
echo ""
echo -e "  ${BLUE}Agent:${NC}"
echo "    Nome:          $AGENT_NAME"
echo "    Agent ID:      $AGENT_ID"
echo "    Token:         ${AGENT_TOKEN:0:12}..."
echo ""
echo -e "  ${BLUE}Container:${NC}"
echo "    CTID:          $CTID"
echo "    Hostname:      $HOSTNAME"
echo "    Storage:       $STORAGE"
echo "    Memoria:       ${MEMORY}MB"
echo "    Disco:         ${DISK}GB"
echo ""
echo -e "  ${BLUE}Rete:${NC}"
echo "    Bridge:        $BRIDGE"
[ -n "$VLAN" ] && echo "    VLAN:          $VLAN"
if [ "$IP_CONFIG" == "dhcp" ]; then
echo "    IP:            DHCP (automatico)"
else
echo "    IP:            $IP_CONFIG"
echo "    Gateway:       $GATEWAY"
fi
[ -n "$DNS_SERVER" ] && echo "    DNS:           $DNS_SERVER"
echo ""
echo -e "  ${BLUE}Modalità:${NC}          WebSocket mTLS (nativo, no Docker)"
echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"
echo ""

read -p "Procedere con l'installazione? [Y/n] " -n 1 -r
echo
if [[ $REPLY =~ ^[Nn]$ ]]; then
    echo "Installazione annullata."
    exit 1
fi

# =============================================================================
# INSTALLAZIONE
# =============================================================================

# Trova template
log "[1/8] Verifico template..."

# Trova storage per template
TEMPLATE_STORAGE_FOUND=""
for ts in $(pvesm status 2>/dev/null | awk '{print $1}' | tail -n +2); do
    if pvesm status 2>/dev/null | grep "^$ts " | grep -q "active"; then
        if pveam list $ts &>/dev/null; then
            TEMPLATE_STORAGE_FOUND=$ts
            break
        fi
    fi
done
TEMPLATE_STORAGE=${TEMPLATE_STORAGE_FOUND:-local}

# Cerca template Debian
TEMPLATE=""
AVAILABLE_TEMPLATES=$(pveam list $TEMPLATE_STORAGE 2>/dev/null | grep "debian" | head -5)
if [ -n "$AVAILABLE_TEMPLATES" ]; then
    for t in "debian-12-standard" "debian-11-standard"; do
        if echo "$AVAILABLE_TEMPLATES" | grep -q "$t"; then
            TEMPLATE=$(echo "$AVAILABLE_TEMPLATES" | grep "$t" | head -1 | awk '{print $1}')
            break
        fi
    done
fi

if [ -z "$TEMPLATE" ]; then
    warn "Nessun template Debian trovato localmente. Scarico Debian 12..."
    pveam update 2>/dev/null || true
    TEMPLATE_NAME=$(pveam available 2>/dev/null | grep "debian-12-standard" | head -1 | awk '{print $2}')
    if [ -z "$TEMPLATE_NAME" ]; then
        TEMPLATE_NAME=$(pveam available 2>/dev/null | grep "debian-11-standard" | head -1 | awk '{print $2}')
    fi
    if [ -n "$TEMPLATE_NAME" ]; then
        pveam download $TEMPLATE_STORAGE $TEMPLATE_NAME
        TEMPLATE="${TEMPLATE_STORAGE}:vztmpl/${TEMPLATE_NAME}"
    else
        error "Impossibile trovare template Debian"
    fi
fi

echo -e "${GREEN}Template: $TEMPLATE${NC}"

# Configura rete
NET_CONFIG="name=eth0,bridge=${BRIDGE}"
[ -n "$VLAN" ] && NET_CONFIG="${NET_CONFIG},tag=${VLAN}"

if [ "$IP_CONFIG" == "dhcp" ]; then
    NET_CONFIG="${NET_CONFIG},ip=dhcp"
else
    NET_CONFIG="${NET_CONFIG},ip=${IP_CONFIG},gw=${GATEWAY}"
fi

# Crea container
log "[2/8] Creo container LXC..."

CREATE_CMD="pct create $CTID $TEMPLATE \
    --hostname $HOSTNAME \
    --storage $STORAGE \
    --memory $MEMORY \
    --cores 2 \
    --rootfs ${STORAGE}:${DISK} \
    --net0 \"$NET_CONFIG\" \
    --features nesting=1,keyctl=1 \
    --unprivileged 1 \
    --onboot 1 \
    --start 0"

# Aggiungi DNS solo se specificato
[ -n "$DNS_SERVER" ] && CREATE_CMD="$CREATE_CMD --nameserver \"$DNS_SERVER\""

eval $CREATE_CMD

echo -e "${GREEN}Container $CTID creato${NC}"

# Avvia container
log "[3/8] Avvio container..."
pct start $CTID
sleep 5

# Attendi avvio
for i in {1..30}; do
    if pct exec $CTID -- echo "ok" &>/dev/null; then
        break
    fi
    sleep 2
done

# Installa dipendenze sistema
log "[4/8] Installo dipendenze di sistema..."

pct exec $CTID -- bash -c '
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential \
    nmap \
    curl \
    git \
    openssl \
    ca-certificates \
    > /dev/null 2>&1
'

# Clone repository - NUOVA STRUTTURA: direttamente in /opt/dadude-agent
log "[5/8] Clone repository Git..."

pct exec $CTID -- bash -c "
# Pulisci eventuali installazioni precedenti
rm -rf /opt/dadude-agent /opt/dadude-updater
mkdir -p /opt/dadude-agent
mkdir -p /var/log/dadude-agent
mkdir -p /var/lib/dadude-agent

# Clone repository - solo la cartella dadude-agent
cd /tmp
rm -rf DADude3-temp

# Clone con sparse checkout per prendere solo dadude-agent
git clone --depth 1 --filter=blob:none --sparse ${GIT_REPO} DADude3-temp 2>/dev/null || {
    # Fallback: clone completo
    git clone --depth 1 ${GIT_REPO} DADude3-temp
}

cd DADude3-temp
git sparse-checkout set dadude-agent 2>/dev/null || true

# Copia SOLO i file necessari direttamente in /opt/dadude-agent
cp -r dadude-agent/* /opt/dadude-agent/ 2>/dev/null || {
    # Se sparse checkout non funziona, copia manualmente
    if [ -d \"dadude-agent/app\" ]; then
        cp -r dadude-agent/app /opt/dadude-agent/
        cp dadude-agent/requirements.txt /opt/dadude-agent/ 2>/dev/null || true
        # Copia VERSION nella root e nella subdirectory
        if [ -f "dadude-agent/VERSION" ]; then
            cp dadude-agent/VERSION /opt/dadude-agent/VERSION 2>/dev/null || true
            cp dadude-agent/VERSION /opt/dadude-agent/dadude-agent/VERSION 2>/dev/null || true
        fi
        cp dadude-agent/dadude-agent.service /opt/dadude-agent/ 2>/dev/null || true
    fi
}

# Cleanup
cd /
rm -rf /tmp/DADude3-temp

# Verifica struttura
if [ ! -d \"/opt/dadude-agent/app\" ]; then
    echo \"ERRORE: Struttura directory non corretta dopo clone\"
    exit 1
fi

echo \"Struttura installata:\"
ls -la /opt/dadude-agent/ | head -10
"

# Crea virtualenv e installa dipendenze Python
log "[6/8] Creo virtualenv e installo dipendenze Python..."

pct exec $CTID -- bash -c '
cd /opt/dadude-agent
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q
'

# Setup Updater (watchdog)
log "[7/8] Setup Agent Updater..."

pct exec $CTID -- bash -c '
# Crea directory updater
mkdir -p /opt/dadude-updater/logs

# Copia file updater dal repository (se disponibili)
if [ -d "/opt/dadude-agent/updater" ]; then
    cp /opt/dadude-agent/updater/updater.py /opt/dadude-updater/
    cp /opt/dadude-agent/updater/dadude-updater.service /etc/systemd/system/
    chmod +x /opt/dadude-updater/updater.py
else
    # Se non disponibili, scarica direttamente da GitHub
    curl -fsSL https://raw.githubusercontent.com/grandir66/DADude3/main/dadude-agent/updater/updater.py -o /opt/dadude-updater/updater.py
    curl -fsSL https://raw.githubusercontent.com/grandir66/DADude3/main/dadude-agent/updater/dadude-updater.service -o /etc/systemd/system/dadude-updater.service
    chmod +x /opt/dadude-updater/updater.py
fi

# Crea config.env per updater
cat > /opt/dadude-updater/config.env << EOF
AGENT_DIR=/opt/dadude-agent
UPDATER_DIR=/opt/dadude-updater
UPDATE_CHECK_INTERVAL=3600
AGENT_HEALTH_TIMEOUT=120
GIT_REMOTE=origin
GIT_BRANCH=main
EOF
'

# Configura agent
log "[8/8] Configuro agent..."

# Crea .env per agent
pct exec $CTID -- bash -c "cat > /opt/dadude-agent/.env << 'EOF'
# DaDude Agent Configuration
# Generato da install-native.sh il $(date)

DADUDE_SERVER_URL=${SERVER_URL}
DADUDE_AGENT_ID=${AGENT_ID}
DADUDE_AGENT_NAME=${AGENT_NAME}
DADUDE_AGENT_TOKEN=${AGENT_TOKEN}
DADUDE_CONNECTION_MODE=websocket
DADUDE_LOG_LEVEL=INFO
DADUDE_DATA_DIR=/var/lib/dadude-agent
EOF"

# Installa servizi systemd
pct exec $CTID -- bash -c '
# Agent service
cp /opt/dadude-agent/dadude-agent.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable dadude-agent.service

# Updater service
systemctl enable dadude-updater.service
'

# Verifica versione
AGENT_VERSION=$(pct exec $CTID -- cat /opt/dadude-agent/VERSION 2>/dev/null || echo "unknown")

# Ottieni IP
if [ "$IP_CONFIG" == "dhcp" ]; then
    sleep 3
    AGENT_IP=$(pct exec $CTID -- hostname -I 2>/dev/null | awk '{print $1}')
else
    AGENT_IP=$(echo "$IP_CONFIG" | cut -d'/' -f1)
fi

# =============================================================================
# COMPLETATO
# =============================================================================

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           ✅ INSTALLAZIONE COMPLETATA!                   ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}Dettagli Agent:${NC}"
echo "  Versione:      $AGENT_VERSION"
echo "  Container ID:  $CTID"
echo "  Hostname:      $HOSTNAME"
echo "  Agent ID:      $AGENT_ID"
echo "  Agent Name:    $AGENT_NAME"
echo "  Server URL:    $SERVER_URL"
[ -n "$AGENT_IP" ] && echo "  IP:            $AGENT_IP"
echo ""
echo -e "${YELLOW}Token per registrazione sul server:${NC}"
echo -e "  ${CYAN}${AGENT_TOKEN}${NC}"
echo ""
echo -e "${YELLOW}Struttura Directory:${NC}"
echo "  Agent:    /opt/dadude-agent"
echo "  Updater:  /opt/dadude-updater"
echo ""
echo -e "${YELLOW}NOTA: L'agent opera in modalità WebSocket${NC}"
echo "  - Nessuna porta in ascolto"
echo "  - L'agent si connette al server (non viceversa)"
echo "  - Funziona anche dietro NAT/firewall"
echo ""
echo -e "${BLUE}Prossimi passi:${NC}"
echo "  1. Avvia l'agent:    pct exec $CTID -- systemctl start dadude-agent"
echo "  2. Avvia l'updater:  pct exec $CTID -- systemctl start dadude-updater"
echo "  3. Verifica status:  pct exec $CTID -- systemctl status dadude-agent"
echo "  4. Verifica logs:    pct exec $CTID -- journalctl -u dadude-agent -f"
echo "  5. Approva agent:    $SERVER_URL (pannello admin)"
echo ""
echo -e "${BLUE}Comandi utili:${NC}"
echo "  pct enter $CTID                                    # Shell nel container"
echo "  pct exec $CTID -- systemctl restart dadude-agent   # Riavvia agent"
echo "  pct exec $CTID -- journalctl -u dadude-agent -f    # Log in tempo reale"
echo ""

# Chiedi se avviare subito
read -p "Avviare agent e updater adesso? [Y/n] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    pct exec $CTID -- systemctl start dadude-agent
    pct exec $CTID -- systemctl start dadude-updater
    sleep 3
    echo ""
    echo -e "${BLUE}Stato servizi:${NC}"
    pct exec $CTID -- systemctl status dadude-agent --no-pager -l | head -10
    echo ""
    pct exec $CTID -- systemctl status dadude-updater --no-pager -l | head -10
fi
