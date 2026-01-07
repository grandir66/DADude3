#!/bin/bash
# Script per rigenerare il file .env per un agent esistente
# Recupera le informazioni dal database del server DaDude

set -e

BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  DaDude Agent - Rigenerazione file .env                 ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Parametri
CTID=""
AGENT_NAME=""
SERVER_URL="https://dadude.domarc.it:8000"

# Leggi parametri
if [ -n "$1" ]; then
    CTID="$1"
fi

if [ -n "$2" ]; then
    AGENT_NAME="$2"
fi

if [ -z "$CTID" ]; then
    read -p "ID Container LXC: " CTID
fi

if [ -z "$AGENT_NAME" ]; then
    read -p "Nome Agent (es: Domarc, OVH-51): " AGENT_NAME
fi

# Verifica che il container esista
if ! pct status $CTID &>/dev/null; then
    echo -e "${RED}Errore: Container $CTID non trovato${NC}"
    exit 1
fi

echo -e "${BLUE}Recupero informazioni agent dal server...${NC}"

# Esegui query Python nel server per ottenere le informazioni agent
AGENT_INFO=$(pct exec 800 -- docker exec dadude python3 << 'PYEOF'
import sys
import json
from app.services.customer_service import get_customer_service
from app.services.encryption_service import get_encryption_service

service = get_customer_service()
encryption = get_encryption_service()

# Cerca agent per nome
agents = service.list_agents()
agent_name = sys.argv[1] if len(sys.argv) > 1 else ""

found_agent = None
for a in agents:
    if a.agent_type == 'docker' and (agent_name.lower() in a.name.lower() or agent_name.lower() in (a.unique_id or "").lower()):
        found_agent = a
        break

if not found_agent:
    print(json.dumps({"error": "Agent not found"}))
    sys.exit(1)

# Ottieni token completo
try:
    # Prova a ottenere il token dal database direttamente
    from app.database import get_db
    from app.models.database import AgentAssignment
    from sqlalchemy.orm import Session
    
    db = next(get_db())
    agent_db = db.query(AgentAssignment).filter(AgentAssignment.id == found_agent.id).first()
    
    token = None
    if agent_db and agent_db.agent_token:
        token = encryption.decrypt(agent_db.agent_token)
    
    result = {
        "agent_id": found_agent.unique_id or found_agent.name,
        "agent_name": found_agent.name,
        "agent_token": token or "NOT_FOUND",
        "server_url": found_agent.agent_url or "https://dadude.domarc.it:8000"
    }
    
    print(json.dumps(result))
except Exception as e:
    print(json.dumps({"error": str(e)}))
PYEOF
"$AGENT_NAME" 2>&1 | tail -1)

# Parse JSON response
if echo "$AGENT_INFO" | grep -q "error"; then
    echo -e "${RED}Errore: ${AGENT_INFO}${NC}"
    echo ""
    echo -e "${YELLOW}Alternativa: Inserisci manualmente le informazioni${NC}"
    read -p "Agent ID (es: agent-Domarc-5193): " AGENT_ID
    read -p "Agent Token: " AGENT_TOKEN
    read -p "Server URL [$SERVER_URL]: " INPUT_SERVER_URL
    SERVER_URL=${INPUT_SERVER_URL:-$SERVER_URL}
    
    AGENT_NAME_FINAL="$AGENT_NAME"
else
    AGENT_ID=$(echo "$AGENT_INFO" | python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('agent_id', ''))" 2>/dev/null)
    AGENT_TOKEN=$(echo "$AGENT_INFO" | python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('agent_token', ''))" 2>/dev/null)
    SERVER_URL=$(echo "$AGENT_INFO" | python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('server_url', 'https://dadude.domarc.it:8000'))" 2>/dev/null)
    AGENT_NAME_FINAL=$(echo "$AGENT_INFO" | python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('agent_name', ''))" 2>/dev/null)
fi

if [ -z "$AGENT_ID" ] || [ -z "$AGENT_TOKEN" ] || [ "$AGENT_TOKEN" = "NOT_FOUND" ]; then
    echo -e "${RED}Errore: Impossibile recuperare le informazioni agent${NC}"
    echo ""
    echo -e "${YELLOW}Inserisci manualmente:${NC}"
    read -p "Agent ID: " AGENT_ID
    read -p "Agent Token: " AGENT_TOKEN
    read -p "Server URL [$SERVER_URL]: " INPUT_SERVER_URL
    SERVER_URL=${INPUT_SERVER_URL:-$SERVER_URL}
fi

# Ottieni DNS dal container
DNS=$(pct exec $CTID -- cat /etc/resolv.conf 2>/dev/null | grep nameserver | head -1 | awk '{print $2}' || echo "8.8.8.8")

# Crea file .env nella root
echo -e "${BLUE}Creo file .env in /opt/dadude-agent/.env${NC}"
pct exec $CTID -- bash -c "cat > /opt/dadude-agent/.env << 'EOF'
# DaDude Agent v2.0 - WebSocket Mode
DADUDE_SERVER_URL=${SERVER_URL}
DADUDE_AGENT_ID=${AGENT_ID}
DADUDE_AGENT_NAME=${AGENT_NAME_FINAL}
DADUDE_AGENT_TOKEN=${AGENT_TOKEN}
DADUDE_CONNECTION_MODE=websocket
DADUDE_LOG_LEVEL=INFO
DADUDE_DNS_SERVERS=${DNS}
DADUDE_DATA_DIR=/var/lib/dadude-agent
EOF"

# Copia anche in dadude-agent/ se esiste
if pct exec $CTID -- test -d /opt/dadude-agent/dadude-agent 2>/dev/null; then
    echo -e "${BLUE}Copia file .env in /opt/dadude-agent/dadude-agent/.env${NC}"
    pct exec $CTID -- cp /opt/dadude-agent/.env /opt/dadude-agent/dadude-agent/.env
fi

echo ""
echo -e "${GREEN}✅ File .env creato con successo!${NC}"
echo ""
echo -e "${BLUE}Informazioni:${NC}"
echo "  Container ID:  $CTID"
echo "  Agent ID:      $AGENT_ID"
echo "  Agent Name:    $AGENT_NAME_FINAL"
echo "  Server URL:    $SERVER_URL"
echo ""
echo -e "${YELLOW}Prossimi passi:${NC}"
echo "  1. Riavvia il container: pct exec $CTID -- docker restart dadude-agent"
echo "  2. Verifica i log: pct exec $CTID -- docker logs -f dadude-agent"
echo ""

