#!/bin/bash
#
# DaDude Agent - Installer per Proxmox VE
# Crea un container LXC con Docker e l'agent preconfigurato
#
# Uso: curl -sSL "https://raw.githubusercontent.com/grandir66/dadude/main/dadude-agent/deploy/proxmox/install.sh?v=$(date +%s)" | bash -s -- [OPZIONI]
#
# Opzioni:
#   --server-url URL      URL del server DaDude (richiesto)
#   --agent-token TOKEN   Token autenticazione (richiesto)
#   --agent-id ID         ID univoco agent (default: hostname)
#   --agent-name NAME     Nome descrittivo (default: "DaDude Agent")
#   --dns-server IP       DNS server per reverse lookup
#   --ctid ID             ID container Proxmox (default: prossimo disponibile)
#   --hostname NAME       Hostname container (default: dadude-agent)
#   --ip CIDR             IP statico (es: 192.168.1.100/24)
#   --gateway IP          Gateway (es: 192.168.1.1)
#   --bridge BRIDGE       Bridge Proxmox (default: vmbr0)
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
NC='\033[0m'

# Valori default
CTID=""
HOSTNAME="dadude-agent"
BRIDGE="vmbr0"
VLAN=""
STORAGE="local-lvm"
TEMPLATE_STORAGE="local"  # Storage per template (tipo directory)
MEMORY=512
DISK=4
IP_CONFIG="dhcp"
GATEWAY=""
SERVER_URL=""
AGENT_TOKEN=""
AGENT_ID=""
AGENT_NAME="DaDude Agent"
DNS_SERVER=""
TEMPLATE="debian-12-standard"

# Parse argomenti
while [[ $# -gt 0 ]]; do
    case $1 in
        --server-url) SERVER_URL="$2"; shift 2 ;;
        --agent-token) AGENT_TOKEN="$2"; shift 2 ;;
        --agent-id) AGENT_ID="$2"; shift 2 ;;
        --agent-name) AGENT_NAME="$2"; shift 2 ;;
        --dns-server) DNS_SERVER="$2"; shift 2 ;;
        --ctid) CTID="$2"; shift 2 ;;
        --hostname) HOSTNAME="$2"; shift 2 ;;
        --ip) IP_CONFIG="$2"; shift 2 ;;
        --gateway) GATEWAY="$2"; shift 2 ;;
        --bridge) BRIDGE="$2"; shift 2 ;;
        --vlan) VLAN="$2"; shift 2 ;;
        --storage) STORAGE="$2"; shift 2 ;;
        --memory) MEMORY="$2"; shift 2 ;;
        --disk) DISK="$2"; shift 2 ;;
        *) echo -e "${RED}Opzione sconosciuta: $1${NC}"; exit 1 ;;
    esac
done

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════╗"
echo "║     DaDude Agent - Proxmox Installer     ║"
echo "╚══════════════════════════════════════════╝"
echo -e "${NC}"

# Verifica siamo su Proxmox
if ! command -v pct &> /dev/null; then
    echo -e "${RED}Errore: Questo script deve essere eseguito su un host Proxmox VE${NC}"
    exit 1
fi

# ==========================================
# MODALITÀ INTERATTIVA - Chiedi parametri mancanti
# ==========================================

# Server URL
if [ -z "$SERVER_URL" ]; then
    echo -e "${YELLOW}Configurazione Server${NC}"
    read -p "URL del server DaDude (es: http://192.168.1.100:8000): " SERVER_URL
    if [ -z "$SERVER_URL" ]; then
        echo -e "${RED}Errore: URL server richiesto${NC}"
        exit 1
    fi
fi

# Agent Name
if [ -z "$AGENT_NAME" ] || [ "$AGENT_NAME" == "DaDude Agent" ]; then
    read -p "Nome dell'agent [DaDude Agent]: " input
    AGENT_NAME="${input:-DaDude Agent}"
fi

# Bridge
echo ""
echo -e "${YELLOW}Configurazione Rete${NC}"
echo "Bridge disponibili:"
ip link show type bridge 2>/dev/null | grep -E "^[0-9]+" | awk -F': ' '{print "  - " $2}' || echo "  (nessun bridge trovato)"
brctl show 2>/dev/null | tail -n +2 | awk '{print "  - " $1}' || true
echo ""
if [ "$BRIDGE" == "vmbr0" ]; then
    read -p "Bridge da usare [vmbr0]: " input
    BRIDGE="${input:-vmbr0}"
fi

# VLAN
if [ -z "$VLAN" ]; then
    read -p "VLAN tag (lascia vuoto se non usato): " VLAN
fi

# IP
if [ "$IP_CONFIG" == "dhcp" ]; then
    read -p "Indirizzo IP (es: 192.168.1.100/24, o 'dhcp'): " input
    IP_CONFIG="${input:-dhcp}"
fi

# Gateway (solo se IP statico)
if [ "$IP_CONFIG" != "dhcp" ] && [ -z "$GATEWAY" ]; then
    # Suggerisci gateway basato sull'IP
    suggested_gw=$(echo "$IP_CONFIG" | sed 's|/.*||' | sed 's|\.[0-9]*$|.1|')
    read -p "Gateway [$suggested_gw]: " input
    GATEWAY="${input:-$suggested_gw}"
fi

# DNS Server
if [ -z "$DNS_SERVER" ]; then
    if [ -n "$GATEWAY" ]; then
        read -p "DNS Server [$GATEWAY]: " input
        DNS_SERVER="${input:-$GATEWAY}"
    else
        read -p "DNS Server [8.8.8.8]: " input
        DNS_SERVER="${input:-8.8.8.8}"
    fi
fi

# Token - genera automaticamente
if [ -z "$AGENT_TOKEN" ]; then
    AGENT_TOKEN=$(openssl rand -hex 24)
    echo ""
    echo -e "${GREEN}Token generato automaticamente.${NC}"
    echo -e "${YELLOW}L'agent si registrerà sul server e dovrà essere approvato.${NC}"
fi

# Trova prossimo CTID disponibile se non specificato
if [ -z "$CTID" ]; then
    CTID=$(pvesh get /cluster/nextid)
fi

# Genera agent_id se non specificato
if [ -z "$AGENT_ID" ]; then
    AGENT_ID="agent-$(echo $AGENT_NAME | tr ' ' '-' | tr '[:upper:]' '[:lower:]')-$(date +%s | tail -c 5)"
fi

# Hostname
if [ "$HOSTNAME" == "dadude-agent" ]; then
    suggested_hostname="dadude-agent-$(echo $AGENT_NAME | tr ' ' '-' | tr '[:upper:]' '[:lower:]' | cut -c1-10)"
    HOSTNAME="$suggested_hostname"
fi

echo ""
echo -e "${YELLOW}═══════════════════════════════════════${NC}"
echo -e "${YELLOW}Riepilogo Configurazione:${NC}"
echo -e "${YELLOW}═══════════════════════════════════════${NC}"
echo "  CTID:        $CTID"
echo "  Hostname:    $HOSTNAME"
echo "  Agent Name:  $AGENT_NAME"
echo "  Agent ID:    $AGENT_ID"
echo "  Storage:     $STORAGE"
echo "  Memory:      ${MEMORY}MB"
echo "  Disk:        ${DISK}GB"
echo "  Bridge:      $BRIDGE"
[ -n "$VLAN" ] && echo "  VLAN:        $VLAN"
echo "  IP:          $IP_CONFIG"
[ -n "$GATEWAY" ] && echo "  Gateway:     $GATEWAY"
echo "  DNS:         $DNS_SERVER"
echo "  Server URL:  $SERVER_URL"
echo ""

# Conferma
read -p "Procedere con l'installazione? [y/N] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Installazione annullata"
    exit 0
fi

# Scarica template se non esiste
echo -e "${BLUE}[1/6] Verifico template...${NC}"

# Rileva storage per template (deve essere tipo 'dir', non 'lvm')
# Prova prima 'local', poi cerca altri storage di tipo directory
if pvesm status | grep -q "^local "; then
    TEMPLATE_STORAGE="local"
else
    # Cerca uno storage di tipo 'dir' che supporta template
    TEMPLATE_STORAGE=$(pvesm status 2>/dev/null | grep -E "dir|nfs|cifs" | head -1 | awk '{print $1}')
    if [ -z "$TEMPLATE_STORAGE" ]; then
        TEMPLATE_STORAGE="local"
    fi
fi

echo -e "${YELLOW}Storage template: $TEMPLATE_STORAGE${NC}"
echo -e "${YELLOW}Storage disco: $STORAGE${NC}"

# Cerca template già scaricati (Debian o Ubuntu)
TEMPLATE_PATH=$(pveam list $TEMPLATE_STORAGE 2>/dev/null | grep -iE "debian-12|debian-11|ubuntu-22|ubuntu-24" | head -1 | awk '{print $1}' || true)

if [ -z "$TEMPLATE_PATH" ]; then
    echo -e "${YELLOW}Nessun template trovato. Cerco template disponibili...${NC}"
    pveam update
    
    echo ""
    echo -e "${YELLOW}Template disponibili:${NC}"
    echo "---"
    
    # Lista template Debian e Ubuntu disponibili
    AVAILABLE_TEMPLATES=$(pveam available 2>/dev/null | grep -iE "debian|ubuntu" | grep -E "standard" | head -10)
    echo "$AVAILABLE_TEMPLATES"
    echo "---"
    
    # Cerca prima Debian 12, poi 11, poi Ubuntu
    TEMPLATE_NAME=""
    
    # Prova Debian 12
    TEMPLATE_NAME=$(pveam available 2>/dev/null | grep -i "debian-12-standard" | head -1 | awk '{print $2}')
    
    # Fallback Debian 11
    if [ -z "$TEMPLATE_NAME" ]; then
        TEMPLATE_NAME=$(pveam available 2>/dev/null | grep -i "debian-11-standard" | head -1 | awk '{print $2}')
    fi
    
    # Fallback Ubuntu 22.04
    if [ -z "$TEMPLATE_NAME" ]; then
        TEMPLATE_NAME=$(pveam available 2>/dev/null | grep -i "ubuntu-22.04-standard" | head -1 | awk '{print $2}')
    fi
    
    # Fallback Ubuntu 24.04
    if [ -z "$TEMPLATE_NAME" ]; then
        TEMPLATE_NAME=$(pveam available 2>/dev/null | grep -i "ubuntu-24" | head -1 | awk '{print $2}')
    fi
    
    # Fallback: qualsiasi Debian o Ubuntu
    if [ -z "$TEMPLATE_NAME" ]; then
        TEMPLATE_NAME=$(pveam available 2>/dev/null | grep -iE "debian.*standard|ubuntu.*standard" | head -1 | awk '{print $2}')
    fi
    
    if [ -z "$TEMPLATE_NAME" ]; then
        echo -e "${RED}Errore: Nessun template Debian/Ubuntu trovato!${NC}"
        echo ""
        echo "Template disponibili sul tuo sistema:"
        pveam available | head -20
        echo ""
        echo "Scarica manualmente un template con:"
        echo "  pveam download $TEMPLATE_STORAGE <nome-template>"
        echo ""
        echo "Poi riesegui questo script."
        exit 1
    fi
    
    echo ""
    echo -e "${GREEN}Scarico template: $TEMPLATE_NAME su $TEMPLATE_STORAGE${NC}"
    
    if ! pveam download $TEMPLATE_STORAGE "$TEMPLATE_NAME"; then
        echo -e "${RED}Errore durante il download del template${NC}"
        echo ""
        echo "Prova manualmente:"
        echo "  pveam download $TEMPLATE_STORAGE $TEMPLATE_NAME"
        exit 1
    fi
    
    # Rileggi il path del template scaricato
    TEMPLATE_PATH=$(pveam list $TEMPLATE_STORAGE 2>/dev/null | grep -iE "debian|ubuntu" | head -1 | awk '{print $1}')
fi

if [ -z "$TEMPLATE_PATH" ]; then
    echo -e "${RED}Errore: Template non trovato dopo il download${NC}"
    echo "Verifica con: pveam list $TEMPLATE_STORAGE"
    exit 1
fi

echo -e "${GREEN}Template: $TEMPLATE_PATH${NC}"

# Crea container
echo -e "${BLUE}[2/6] Creo container LXC...${NC}"

NET_CONFIG="name=eth0,bridge=$BRIDGE"

# Aggiungi VLAN tag se specificato
if [ -n "$VLAN" ]; then
    NET_CONFIG="$NET_CONFIG,tag=$VLAN"
fi

if [ "$IP_CONFIG" != "dhcp" ]; then
    NET_CONFIG="$NET_CONFIG,ip=$IP_CONFIG"
    if [ -n "$GATEWAY" ]; then
        NET_CONFIG="$NET_CONFIG,gw=$GATEWAY"
    fi
else
    NET_CONFIG="$NET_CONFIG,ip=dhcp"
fi

pct create $CTID $TEMPLATE_PATH \
    --hostname $HOSTNAME \
    --storage $STORAGE \
    --rootfs ${STORAGE}:${DISK} \
    --memory $MEMORY \
    --swap 256 \
    --cores 2 \
    --net0 "$NET_CONFIG" \
    --features nesting=1,keyctl=1 \
    --unprivileged 1 \
    --onboot 1 \
    --start 0

echo -e "${GREEN}Container $CTID creato${NC}"

# Avvia container
echo -e "${BLUE}[3/6] Avvio container...${NC}"
pct start $CTID
sleep 5

# Attendi che il container sia pronto
echo "Attendo avvio container..."
for i in {1..30}; do
    if pct exec $CTID -- test -f /etc/os-release 2>/dev/null; then
        break
    fi
    sleep 1
done

# Installa Docker nel container
echo -e "${BLUE}[4/6] Installo Docker...${NC}"

pct exec $CTID -- bash -c '
    apt-get update
    apt-get install -y ca-certificates curl gnupg
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    
    # Rileva distribuzione (Ubuntu o Debian), fallback a Debian se non rilevata
    DOCKER_REPO="debian"
    DOCKER_CODENAME="bookworm"
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [ "$ID" = "ubuntu" ]; then
            DOCKER_REPO="ubuntu"
            DOCKER_CODENAME="${VERSION_CODENAME:-jammy}"
        elif [ "$ID" = "debian" ]; then
            DOCKER_REPO="debian"
            DOCKER_CODENAME="${VERSION_CODENAME:-bookworm}"
        fi
    fi
    
    # Debug: mostra cosa è stato rilevato
    echo "Rilevato: DOCKER_REPO=${DOCKER_REPO}, DOCKER_CODENAME=${DOCKER_CODENAME}"
    
    # Prova prima con il repository rilevato
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${DOCKER_REPO} ${DOCKER_CODENAME} stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    # Aggiorna repository
    UPDATE_OUTPUT=$(apt-get update 2>&1)
    UPDATE_STATUS=$?
    
    # Controlla se ci sono errori 404 o Not Found
    if echo "$UPDATE_OUTPUT" | grep -qE "404|Not Found|does not have a Release file"; then
        # Repository non disponibile, usa fallback Debian
        echo "Repository ${DOCKER_REPO} non disponibile per ${DOCKER_CODENAME}, uso fallback Debian..."
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
        apt-get update
        apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    else
        # Repository OK, installa normalmente
        apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    fi
    
    systemctl enable docker
    systemctl start docker
'

echo -e "${GREEN}Docker installato${NC}"

# Crea configurazione agent
echo -e "${BLUE}[5/6] Configuro DaDude Agent...${NC}"

pct exec $CTID -- mkdir -p /opt/dadude-agent/config

# Crea docker-compose.yml
pct exec $CTID -- bash -c "cat > /opt/dadude-agent/docker-compose.yml << 'COMPOSE'
version: '3.8'

services:
  agent:
    image: ghcr.io/dadude/agent:latest
    container_name: dadude-agent
    restart: unless-stopped
    network_mode: host
    environment:
      - DADUDE_SERVER_URL=${SERVER_URL}
      - DADUDE_AGENT_ID=${AGENT_ID}
      - DADUDE_AGENT_NAME=${AGENT_NAME}
      - DADUDE_AGENT_TOKEN=${AGENT_TOKEN}
      - DADUDE_DNS_SERVERS=${DNS_SERVER:-8.8.8.8}
      - DADUDE_API_PORT=8080
      - DADUDE_LOG_LEVEL=INFO
    volumes:
      - ./config:/app/config:ro
    healthcheck:
      test: ['CMD', 'wget', '-q', '--spider', 'http://localhost:8080/health']
      interval: 30s
      timeout: 10s
      retries: 3
COMPOSE"

# Crea config.json
pct exec $CTID -- bash -c "cat > /opt/dadude-agent/config/config.json << 'CONFIG'
{
  \"server_url\": \"${SERVER_URL}\",
  \"agent_token\": \"${AGENT_TOKEN}\",
  \"agent_id\": \"${AGENT_ID}\",
  \"agent_name\": \"${AGENT_NAME}\",
  \"dns_servers\": [\"${DNS_SERVER:-8.8.8.8}\"],
  \"api_port\": 8080,
  \"log_level\": \"INFO\"
}
CONFIG"

# Crea systemd service per avvio automatico
pct exec $CTID -- bash -c 'cat > /etc/systemd/system/dadude-agent.service << SERVICE
[Unit]
Description=DaDude Agent
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/dadude-agent
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
SERVICE'

pct exec $CTID -- systemctl daemon-reload
pct exec $CTID -- systemctl enable dadude-agent

echo -e "${GREEN}Configurazione completata${NC}"

# Avvia agent (prima build se immagine non esiste)
echo -e "${BLUE}[6/6] Avvio DaDude Agent...${NC}"

# Per ora usiamo build locale finché l'immagine non è su registry
pct exec $CTID -- bash -c '
cd /opt/dadude-agent

# Scarica sorgenti agent se immagine non disponibile
if ! docker pull ghcr.io/dadude/agent:latest 2>/dev/null; then
    echo "Immagine non trovata su registry, costruisco localmente..."
    
    # Crea Dockerfile inline con nmap per network scanning (Debian per stabilità)
    cat > Dockerfile << "DOCKERFILE"
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies + nmap
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    iputils-ping \
    dnsutils \
    net-tools \
    iproute2 \
    nmap \
    procps \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && rm -rf /root/.cache/pip

COPY app/ ./app/

EXPOSE 8080

ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
DOCKERFILE

    # Crea requirements.txt
    cat > requirements.txt << "REQUIREMENTS"
fastapi>=0.104.0
uvicorn>=0.24.0
impacket>=0.11.0
paramiko>=3.3.0
pysnmp>=7.0.0
dnspython>=2.4.0
httpx>=0.25.0
pyjwt>=2.8.0
loguru>=0.7.0
pydantic>=2.5.0
pydantic-settings>=2.1.0
REQUIREMENTS

    # Scarica codice agent da git
    apt-get update && apt-get install -y git
    git clone --depth 1 https://github.com/grandir66/dadude.git /tmp/agent-src || true
    
    if [ -d /tmp/agent-src/dadude-agent/app ]; then
        cp -r /tmp/agent-src/dadude-agent/app ./
    else
        # Crea app minimale se git fallisce
        mkdir -p app/probes app/scanners
        
        # main.py minimale
        cat > app/__init__.py << "PY"
# DaDude Agent
PY
        cat > app/config.py << "PY"
import os
from functools import lru_cache
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    server_url: str = "http://localhost:8000"
    agent_id: str = "agent-001"
    agent_name: str = "DaDude Agent"
    agent_token: str = ""
    dns_servers: list = ["8.8.8.8"]
    api_port: int = 8080
    log_level: str = "INFO"
    
    class Config:
        env_prefix = "DADUDE_"

@lru_cache()
def get_settings():
    return Settings()
PY
        cat > app/main.py << "PY"
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime
from .config import get_settings
import asyncio

app = FastAPI(title="DaDude Agent", version="1.0.0")

async def verify_token(authorization: str = Header(None)):
    settings = get_settings()
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing token")
    if authorization[7:] != settings.agent_token:
        raise HTTPException(403, "Invalid token")
    return True

@app.get("/health")
async def health():
    settings = get_settings()
    return {
        "status": "healthy",
        "agent_id": settings.agent_id,
        "agent_name": settings.agent_name,
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "capabilities": ["wmi", "ssh", "snmp", "port_scan", "dns_reverse"]
    }

class ProbeRequest(BaseModel):
    target: str
    username: str = ""
    password: str = ""
    domain: str = ""
    community: str = "public"
    version: str = "2c"
    port: int = 161

@app.post("/probe/wmi")
async def probe_wmi(req: ProbeRequest, auth: bool = Header(None)):
    from concurrent.futures import ThreadPoolExecutor
    executor = ThreadPoolExecutor(max_workers=1)
    loop = asyncio.get_event_loop()
    
    def do_wmi():
        try:
            from impacket.dcerpc.v5.dcom import wmi as dcom_wmi
            from impacket.dcerpc.v5.dcomrt import DCOMConnection
            
            dcom = DCOMConnection(req.target, username=req.username, password=req.password, domain=req.domain)
            iInterface = dcom.CoCreateInstanceEx(dcom_wmi.CLSID_WbemLevel1Login, dcom_wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = dcom_wmi.IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin("//./root/cimv2", dcom_wmi.NULL, dcom_wmi.NULL)
            
            info = {}
            result = iWbemServices.ExecQuery("SELECT Caption, Version FROM Win32_OperatingSystem")
            item = result.Next(0xffffffff, 1)[0]
            props = item.getProperties()
            info["os_name"] = str(props.get("Caption", {}).get("value", ""))
            info["os_version"] = str(props.get("Version", {}).get("value", ""))
            
            result = iWbemServices.ExecQuery("SELECT Name, Domain FROM Win32_ComputerSystem")
            item = result.Next(0xffffffff, 1)[0]
            props = item.getProperties()
            info["hostname"] = str(props.get("Name", {}).get("value", ""))
            info["domain"] = str(props.get("Domain", {}).get("value", ""))
            
            dcom.disconnect()
            return {"success": True, "data": info}
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    return await loop.run_in_executor(executor, do_wmi)

@app.post("/probe/snmp")
async def probe_snmp(req: ProbeRequest, auth: bool = Header(None)):
    try:
        from pysnmp.hlapi.v1arch.asyncio import get_cmd, SnmpDispatcher, CommunityData, UdpTransportTarget, ObjectType, ObjectIdentity
        
        dispatcher = SnmpDispatcher()
        transport = await UdpTransportTarget.create((req.target, req.port), timeout=5, retries=1)
        
        info = {}
        for name, oid in [("sysDescr", "1.3.6.1.2.1.1.1.0"), ("sysName", "1.3.6.1.2.1.1.5.0")]:
            err, status, idx, binds = await get_cmd(dispatcher, CommunityData(req.community), transport, ObjectType(ObjectIdentity(oid)))
            if not err and binds:
                info[name] = str(binds[0][1])
        
        dispatcher.transport_dispatcher.close_dispatcher()
        return {"success": True, "data": info}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/scan/ports")
async def scan_ports(target: str, ports: List[int] = None):
    import socket
    if not ports:
        ports = [22, 80, 443, 3389, 445, 161]
    
    results = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            is_open = sock.connect_ex((target, port)) == 0
            sock.close()
            if is_open:
                results.append({"port": port, "open": True})
        except:
            pass
    return {"success": True, "target": target, "open_ports": results}
PY
    fi
    
    docker build -t dadude-agent:latest .
    
    # Aggiorna compose per usare immagine locale
    sed -i "s|ghcr.io/dadude/agent:latest|dadude-agent:latest|" docker-compose.yml
fi

docker compose up -d
'

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║    ✅ Installazione Completata!          ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "Container ID:  ${BLUE}$CTID${NC}"
echo -e "Hostname:      ${BLUE}$HOSTNAME${NC}"
echo -e "Agent ID:      ${BLUE}$AGENT_ID${NC}"

# Ottieni IP
AGENT_IP=$(pct exec $CTID -- hostname -I 2>/dev/null | awk '{print $1}')
if [ -n "$AGENT_IP" ]; then
    echo -e "Agent IP:      ${BLUE}$AGENT_IP${NC}"
    echo -e "Agent API:     ${BLUE}http://$AGENT_IP:8080${NC}"
fi

echo ""
echo -e "${YELLOW}Prossimi passi:${NC}"
echo "1. Registra l'agent nel pannello DaDude:"
echo "   - Vai su Clienti → [Cliente] → Sonde → Nuova Sonda"
echo "   - Tipo: Docker"
echo "   - Indirizzo: $AGENT_IP"
echo "   - Porta API: 8080"
echo "   - Token: $AGENT_TOKEN"
echo ""
echo "2. Testa la connessione cliccando su 'Test'"
echo ""
echo -e "${YELLOW}Comandi utili:${NC}"
echo "  pct enter $CTID                  # Entra nel container"
echo "  pct exec $CTID -- docker logs -f dadude-agent"
echo "  pct stop $CTID                   # Ferma container"
echo "  pct destroy $CTID                # Elimina container"

