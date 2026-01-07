#!/bin/bash
#
# DaDude Agent v2.0 - Installazione WebSocket mTLS
# Installa agent in modalità WebSocket (agent-initiated)
#
# Tutti i parametri vengono chiesti interattivamente se non forniti
#

set -e

# Colori
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  DaDude Agent v2.0 - WebSocket mTLS Installer            ║"
echo "║  Modalità: Agent-Initiated (no porte in ascolto)         ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Parametri (tutti vuoti di default)
CTID=""
HOSTNAME=""
STORAGE=""
TEMPLATE_STORAGE="local"
MEMORY=""
DISK=""
BRIDGE=""
VLAN=""
IP=""
GATEWAY=""
DNS=""
SERVER_URL=""
AGENT_NAME=""
AGENT_TOKEN=""

# Parse argomenti da linea di comando (opzionale)
while [[ $# -gt 0 ]]; do
    case $1 in
        --ctid) CTID="$2"; shift 2 ;;
        --hostname) HOSTNAME="$2"; shift 2 ;;
        --storage) STORAGE="$2"; shift 2 ;;
        --memory) MEMORY="$2"; shift 2 ;;
        --disk) DISK="$2"; shift 2 ;;
        --bridge) BRIDGE="$2"; shift 2 ;;
        --vlan) VLAN="$2"; shift 2 ;;
        --ip) IP="$2"; shift 2 ;;
        --gateway) GATEWAY="$2"; shift 2 ;;
        --dns) DNS="$2"; shift 2 ;;
        --server-url) SERVER_URL="$2"; shift 2 ;;
        --agent-name) AGENT_NAME="$2"; shift 2 ;;
        --agent-token) AGENT_TOKEN="$2"; shift 2 ;;
        --help)
            echo "Uso: $0 [opzioni]"
            echo ""
            echo "Se non vengono forniti parametri, lo script li chiederà interattivamente."
            echo ""
            echo "Opzioni:"
            echo "  --ctid ID            ID container LXC"
            echo "  --hostname NAME      Hostname del container"
            echo "  --server-url URL     URL server DaDude (es: http://dadude.esempio.it:8000)"
            echo "  --agent-name NAME    Nome identificativo dell'agent"
            echo "  --agent-token TOK    Token agent (opzionale, auto-generato se vuoto)"
            echo "  --bridge BRIDGE      Bridge di rete (es: vmbr0)"
            echo "  --vlan ID            VLAN tag (opzionale, lascia vuoto se non usi VLAN)"
            echo "  --ip IP/MASK         IP statico con netmask (es: 192.168.1.100/24)"
            echo "  --gateway IP         Gateway di rete"
            echo "  --dns IP             Server DNS"
            echo "  --storage NAME       Storage per il container (default: local-lvm)"
            echo "  --memory MB          Memoria RAM in MB (default: 512)"
            echo "  --disk GB            Spazio disco in GB (default: 4)"
            exit 0
            ;;
        *) echo -e "${RED}Opzione sconosciuta: $1${NC}"; exit 1 ;;
    esac
done

echo -e "${YELLOW}Configurazione Agent DaDude${NC}"
echo "Inserisci i parametri richiesti (premi Invio per accettare i default tra parentesi)"
echo ""

# === CONFIGURAZIONE SERVER ===
echo -e "${BLUE}--- Server DaDude ---${NC}"

DEFAULT_SERVER_URL="https://dadude.domarc.it:8000"

while [ -z "$SERVER_URL" ]; do
    read -p "URL Server DaDude [$DEFAULT_SERVER_URL]: " SERVER_URL
    SERVER_URL=${SERVER_URL:-$DEFAULT_SERVER_URL}
    if [ -z "$SERVER_URL" ]; then
        echo -e "${YELLOW}⚠ URL server è obbligatorio, riprova${NC}"
    fi
done
echo -e "${GREEN}Server: $SERVER_URL${NC}"

# === CONFIGURAZIONE AGENT ===
echo -e "\n${BLUE}--- Identificazione Agent ---${NC}"

while [ -z "$AGENT_NAME" ]; do
    read -p "Nome Agent (es: agent-sede-milano): " AGENT_NAME
    if [ -z "$AGENT_NAME" ]; then
        echo -e "${YELLOW}⚠ Nome agent è obbligatorio, riprova${NC}"
    fi
done

if [ -z "$AGENT_TOKEN" ]; then
    read -p "Token Agent (lascia vuoto per generare automaticamente): " AGENT_TOKEN
    if [ -z "$AGENT_TOKEN" ]; then
        AGENT_TOKEN=$(openssl rand -base64 32 | tr -d '/+=' | head -c 32)
        echo -e "${GREEN}Token generato: ${AGENT_TOKEN}${NC}"
    fi
fi

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
    AVAILABLE_STORAGES=$(pvesm status 2>/dev/null | grep -E "active.*rootdir|active.*images" | awk '{print $1}')
    if [ -z "$AVAILABLE_STORAGES" ]; then
        # Fallback: mostra tutti gli storage attivi
        AVAILABLE_STORAGES=$(pvesm status 2>/dev/null | grep "active" | awk '{print $1}')
    fi
    
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
        echo "  (nessuno trovato, uso default)"
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
        # Cerca info dalla configurazione
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
        while [ -z "$BRIDGE" ]; do
            read -p "Nessun bridge trovato. Inserisci nome bridge: " BRIDGE
            if [ -z "$BRIDGE" ]; then
                echo -e "${YELLOW}⚠ Bridge è obbligatorio, riprova${NC}"
            fi
        done
    elif [ ${#BRIDGE_OPTIONS[@]} -eq 1 ]; then
        BRIDGE="${BRIDGE_OPTIONS[1]}"
        echo -e "${GREEN}Selezionato automaticamente: $BRIDGE${NC}"
    else
        while [ -z "$BRIDGE" ]; do
            read -p "Scegli bridge [1-$((i-1))]: " BRIDGE_CHOICE
            if [ -n "$BRIDGE_CHOICE" ] && [ -n "${BRIDGE_OPTIONS[$BRIDGE_CHOICE]}" ]; then
                BRIDGE="${BRIDGE_OPTIONS[$BRIDGE_CHOICE]}"
            elif [ -z "$BRIDGE_CHOICE" ]; then
                BRIDGE="${BRIDGE_OPTIONS[1]}"
            else
                echo -e "${YELLOW}⚠ Scelta non valida, riprova${NC}"
            fi
        done
    fi
    echo -e "${GREEN}Bridge selezionato: $BRIDGE${NC}"
fi

# Cerca VLAN configurate su questo bridge
if [ -z "$VLAN" ]; then
    echo ""
    # Prova a trovare le VLAN dal file di rete Proxmox
    CONFIGURED_VLANS=$(grep -oP "bridge-vlan-aware.*|bridge-vids \K[\d\s-]+" /etc/network/interfaces 2>/dev/null | tr ' ' '\n' | grep -E "^[0-9]+$" | head -10)
    
    if [ -n "$CONFIGURED_VLANS" ]; then
        echo -e "${YELLOW}VLAN rilevate sul sistema:${NC}"
        echo "  $CONFIGURED_VLANS"
    fi
    read -p "VLAN tag (lascia vuoto se non usi VLAN): " VLAN
fi

# Chiedi se usare DHCP o IP statico
echo ""
echo -e "${YELLOW}Configurazione IP:${NC}"
echo "  1) DHCP (automatico)"
echo "  2) IP Statico"
read -p "Scegli [1]: " IP_MODE
IP_MODE=${IP_MODE:-1}

USE_DHCP=false
if [ "$IP_MODE" == "1" ]; then
    USE_DHCP=true
    IP="dhcp"
    GATEWAY=""
    DNS="8.8.8.8"  # Default DNS per DHCP
    echo -e "${GREEN}Modalità DHCP selezionata${NC}"
else
    # Suggerisci rete basandosi su bridge e VLAN
    SUGGESTED_NETWORK=""
    if [ -n "$VLAN" ]; then
        # Cerca interfaccia VLAN esistente
        VLAN_IF=$(ip link show 2>/dev/null | grep -oP "${BRIDGE}\.\K${VLAN}" | head -1)
        if [ -n "$VLAN_IF" ]; then
            SUGGESTED_NETWORK=$(ip -4 addr show ${BRIDGE}.${VLAN} 2>/dev/null | grep -oP 'inet \K[\d.]+/\d+' | head -1)
        fi
    else
        SUGGESTED_NETWORK=$(ip -4 addr show $BRIDGE 2>/dev/null | grep -oP 'inet \K[\d.]+/\d+' | head -1)
    fi

    # Estrai subnet per suggerimento
    if [ -n "$SUGGESTED_NETWORK" ]; then
        SUGGESTED_PREFIX=$(echo $SUGGESTED_NETWORK | grep -oP '[\d.]+' | head -1 | sed 's/\.[0-9]*$//')
        SUGGESTED_MASK=$(echo $SUGGESTED_NETWORK | grep -oP '/\d+')
        echo ""
        echo -e "${YELLOW}Rete rilevata: ${SUGGESTED_PREFIX}.0${SUGGESTED_MASK}${NC}"
    fi

    while [ -z "$IP" ] || [ "$IP" == "dhcp" ]; do
        if [ -n "$SUGGESTED_PREFIX" ]; then
            read -p "IP/Netmask (es: ${SUGGESTED_PREFIX}.100${SUGGESTED_MASK:-/24}): " IP
        else
            read -p "IP/Netmask (es: 192.168.1.100/24): " IP
        fi
        if [ -z "$IP" ]; then
            echo -e "${YELLOW}⚠ IP è obbligatorio per modalità statica, riprova${NC}"
        fi
    done

    # Suggerisci gateway basandosi sull'IP inserito
    IP_PREFIX=$(echo $IP | grep -oP '[\d.]+' | head -1 | sed 's/\.[0-9]*$//')
    SUGGESTED_GW="${IP_PREFIX}.254"

    while [ -z "$GATEWAY" ]; do
        if [ -n "$SUGGESTED_GW" ]; then
            read -p "Gateway [$SUGGESTED_GW]: " GATEWAY
            GATEWAY=${GATEWAY:-$SUGGESTED_GW}
        else
            read -p "Gateway: " GATEWAY
        fi
        if [ -z "$GATEWAY" ]; then
            echo -e "${YELLOW}⚠ Gateway è obbligatorio, riprova${NC}"
        fi
    done

    # Suggerisci DNS = gateway (comune per reti aziendali)
    while [ -z "$DNS" ]; do
        read -p "Server DNS [$GATEWAY]: " DNS
        DNS=${DNS:-$GATEWAY}
        if [ -z "$DNS" ]; then
            echo -e "${YELLOW}⚠ DNS è obbligatorio, riprova${NC}"
        fi
    done
fi

# Genera agent ID univoco
AGENT_ID="agent-${AGENT_NAME}-$(date +%s | tail -c 5)"

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
            echo -e "${GREEN}Usando CTID: $CTID${NC}"
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
            echo -e "${GREEN}Usando CTID: $CTID${NC}"
            ;;
    esac
done

# Riepilogo configurazione
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
echo "    Token:         ${AGENT_TOKEN:0:8}..."
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
if [ -n "$VLAN" ]; then
echo "    VLAN:          $VLAN"
fi
if [ "$USE_DHCP" = true ]; then
echo "    IP:            DHCP (automatico)"
else
echo "    IP:            $IP"
echo "    Gateway:       $GATEWAY"
fi
echo "    DNS:           $DNS"
echo ""
echo -e "  ${BLUE}Modalità:${NC}          WebSocket mTLS (agent-initiated)"
echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════════${NC}"
echo ""

read -p "Procedere con l'installazione? [y/N] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Installazione annullata."
    exit 1
fi

# === INSTALLAZIONE ===

# Trova template
echo -e "\n${BLUE}[1/6] Verifico template...${NC}"

# Trova storage per template (tipo 'dir' con contenuto 'vztmpl')
TEMPLATE_STORAGE_FOUND=""
for ts in $(pvesm status 2>/dev/null | awk '{print $1}' | tail -n +2); do
    if pvesm status 2>/dev/null | grep "^$ts " | grep -q "active"; then
        # Verifica se supporta vztmpl
        if pvesm list $ts 2>/dev/null | head -1 | grep -q "vztmpl"; then
            TEMPLATE_STORAGE_FOUND=$ts
            break
        fi
    fi
done

# Se non trovato, usa 'local' come fallback
TEMPLATE_STORAGE=${TEMPLATE_STORAGE_FOUND:-local}
echo "Storage template: $TEMPLATE_STORAGE"

# Usa SEMPRE Debian (funziona perfettamente)
TEMPLATE=""
echo -e "${YELLOW}Cerca template Debian...${NC}"

# Cerca template Debian già scaricati (solo Debian, niente Ubuntu)
AVAILABLE_TEMPLATES=$(pveam list $TEMPLATE_STORAGE 2>/dev/null | grep "debian" | head -5)
if [ -n "$AVAILABLE_TEMPLATES" ]; then
    echo "$AVAILABLE_TEMPLATES"
    
    # Prova Debian 12, poi Debian 11
    for t in "debian-12-standard" "debian-11-standard"; do
        if echo "$AVAILABLE_TEMPLATES" | grep -q "$t"; then
            TEMPLATE=$(echo "$AVAILABLE_TEMPLATES" | grep "$t" | head -1 | awk '{print $1}')
            break
        fi
    done
fi

if [ -z "$TEMPLATE" ]; then
    echo -e "${YELLOW}Nessun template Debian trovato localmente. Scarico Debian 12...${NC}"
    pveam update 2>/dev/null || true
    TEMPLATE_NAME=$(pveam available 2>/dev/null | grep "debian-12-standard" | head -1 | awk '{print $2}')
    if [ -z "$TEMPLATE_NAME" ]; then
        # Fallback a Debian 11
        TEMPLATE_NAME=$(pveam available 2>/dev/null | grep "debian-11-standard" | head -1 | awk '{print $2}')
    fi
    if [ -n "$TEMPLATE_NAME" ]; then
        echo "Download: $TEMPLATE_NAME"
        pveam download $TEMPLATE_STORAGE $TEMPLATE_NAME
        TEMPLATE="${TEMPLATE_STORAGE}:vztmpl/${TEMPLATE_NAME}"
    else
        echo -e "${RED}Errore: impossibile trovare template Debian${NC}"
        echo "Template disponibili online:"
        pveam available 2>/dev/null | grep "debian" | head -5
        exit 1
    fi
fi

echo -e "${GREEN}Template selezionato: $TEMPLATE${NC}"

# Configura rete
NET_CONFIG="name=eth0,bridge=${BRIDGE}"
if [ -n "$VLAN" ]; then
    NET_CONFIG="${NET_CONFIG},tag=${VLAN}"
fi

if [ "$USE_DHCP" = true ]; then
    NET_CONFIG="${NET_CONFIG},ip=dhcp"
else
    NET_CONFIG="${NET_CONFIG},ip=${IP},gw=${GATEWAY}"
fi

# Crea container
echo -e "\n${BLUE}[2/6] Creo container LXC...${NC}"

pct create $CTID $TEMPLATE \
    --hostname $HOSTNAME \
    --storage $STORAGE \
    --memory $MEMORY \
    --cores 1 \
    --rootfs ${STORAGE}:${DISK} \
    --net0 "$NET_CONFIG" \
    --nameserver "$DNS" \
    --features nesting=1,keyctl=1 \
    --unprivileged 0 \
    --start 1


# Attendi avvio
echo -e "\n${BLUE}[3/6] Attendo avvio container...${NC}"
for i in {1..30}; do
    if pct exec $CTID -- echo "ok" &>/dev/null; then
        break
    fi
    sleep 2
done

# Installa Docker
echo -e "\n${BLUE}[4/6] Installo Docker...${NC}"

pct exec $CTID -- bash -c '
apt-get update
apt-get install -y ca-certificates curl gnupg git

install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

# Usa sempre Debian (funziona sempre, indipendentemente dalla distribuzione)
DOCKER_REPO="debian"
DOCKER_CODENAME="bookworm"

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${DOCKER_REPO} ${DOCKER_CODENAME} stable" > /etc/apt/sources.list.d/docker.list

apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

systemctl enable docker
systemctl start docker
'

# Clona repository
echo -e "\n${BLUE}[5/6] Clono repository e configuro...${NC}"

pct exec $CTID -- bash -c "
# Clona repo completo in /opt/dadude-agent
cd /opt
git clone --depth 1 https://github.com/grandir66/Dadude.git dadude-agent

# Copia i file dell'agent nella root del repo
cd dadude-agent
cp -r dadude-agent/* .

# Ora /opt/dadude-agent ha:
#   .git/           (per updates)
#   app/            (codice agent)
#   Dockerfile
#   requirements.txt
#   etc.
"

# Crea .env per modalità WebSocket
pct exec $CTID -- bash -c "cat > /opt/dadude-agent/.env << 'EOF'
# DaDude Agent v2.0 - WebSocket Mode
DADUDE_SERVER_URL=${SERVER_URL}
DADUDE_AGENT_ID=${AGENT_ID}
DADUDE_AGENT_NAME=${AGENT_NAME}
DADUDE_AGENT_TOKEN=${AGENT_TOKEN}
DADUDE_CONNECTION_MODE=websocket
DADUDE_LOG_LEVEL=INFO
DADUDE_DNS_SERVERS=${DNS}
DADUDE_DATA_DIR=/var/lib/dadude-agent
EOF"

# Crea docker-compose per modalità WebSocket
pct exec $CTID -- bash -c 'cat > /opt/dadude-agent/docker-compose.yml << '"'"'EOF'"'"'
services:
  agent:
    build: .
    container_name: dadude-agent
    restart: unless-stopped
    env_file: .env
    
    # Network host per accedere alla rete locale e vedere i MAC address
    network_mode: host
    
    # Capability per ARP scan (richiesto per ottenere MAC address)
    cap_add:
      - NET_RAW
      - NET_ADMIN
    
    volumes:
      - ./data:/var/lib/dadude-agent
      # Per auto-update - monta repo git e socket Docker
      - /var/run/docker.sock:/var/run/docker.sock
      - /opt/dadude-agent:/opt/dadude-agent
    
    command: ["python", "-m", "app.agent"]
    
    healthcheck:
      test: ["CMD", "python", "-c", "import sys; sys.exit(0)"]
      interval: 60s
      timeout: 10s
      retries: 3
EOF'

# Crea directory dati
pct exec $CTID -- mkdir -p /opt/dadude-agent/data

# Build e avvia
echo -e "\n${BLUE}[6/6] Build e avvio container Docker...${NC}"

pct exec $CTID -- bash -c "cd /opt/dadude-agent && docker compose build && docker compose up -d"

sleep 5

# Verifica finale
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           ✅ INSTALLAZIONE COMPLETATA!                   ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}Dettagli Agent:${NC}"
echo "  Container ID:  $CTID"
echo "  Hostname:      $HOSTNAME"
echo "  Agent ID:      $AGENT_ID"
echo "  Agent Name:    $AGENT_NAME"
echo "  Agent Token:   $AGENT_TOKEN"
echo "  Server URL:    $SERVER_URL"

if [ "$USE_DHCP" = true ]; then
    # Ottieni IP assegnato via DHCP
    sleep 3
    ASSIGNED_IP=$(pct exec $CTID -- ip -4 addr show eth0 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
    if [ -n "$ASSIGNED_IP" ]; then
        echo "  IP (DHCP):     $ASSIGNED_IP"
    else
        echo "  IP:            DHCP (in attesa di assegnazione)"
    fi
else
    echo "  IP:            $IP"
fi
echo ""
echo -e "${YELLOW}NOTA: L'agent opera in modalità WebSocket${NC}"
echo "  - Nessuna porta in ascolto"
echo "  - L'agent si connette al server (non viceversa)"
echo "  - Funziona anche dietro NAT/firewall"
echo ""
echo -e "${BLUE}Prossimi passi:${NC}"
echo "  1. Verifica i log: pct exec $CTID -- docker logs dadude-agent-ws"
echo "  2. L'agent si registrerà automaticamente al server"
echo "  3. Approva l'agent dal pannello DaDude: ${SERVER_URL}/agents"
echo ""
echo -e "${BLUE}Comandi utili:${NC}"
echo "  pct exec $CTID -- docker logs -f dadude-agent    # Log in tempo reale"
echo "  pct exec $CTID -- docker restart dadude-agent    # Riavvia agent"
echo "  pct exec $CTID -- bash                           # Shell nel container"
echo ""
echo -e "${BLUE}Aggiornamento manuale:${NC}"
echo "  pct exec $CTID -- bash -c 'cd /opt/dadude-agent && git fetch origin && git reset --hard origin/main && cp -r dadude-agent/* . && docker compose build && docker compose up -d'"
echo ""
