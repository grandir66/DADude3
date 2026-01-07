#!/bin/bash
#
# Script di diagnostica per agent DaDude
# Verifica configurazione, connettività e stato registrazione
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
echo "║  DaDude Agent - Diagnostica Connessione                 ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Funzione per verificare se un comando esiste
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# 1. Verifica configurazione agent
echo -e "\n${BLUE}=== 1. CONFIGURAZIONE AGENT ===${NC}"

# Leggi variabili d'ambiente
if [ -f /opt/dadude-agent/.env ]; then
    echo -e "${GREEN}✓ File .env trovato${NC}"
    source /opt/dadude-agent/.env
else
    echo -e "${YELLOW}⚠ File .env non trovato in /opt/dadude-agent/.env${NC}"
fi

# Verifica variabili critiche
SERVER_URL="${DADUDE_SERVER_URL:-}"
AGENT_ID="${DADUDE_AGENT_ID:-}"
AGENT_TOKEN="${DADUDE_AGENT_TOKEN:-}"
AGENT_NAME="${DADUDE_AGENT_NAME:-}"

if [ -z "$SERVER_URL" ]; then
    echo -e "${RED}✗ DADUDE_SERVER_URL non configurato${NC}"
else
    echo -e "${GREEN}✓ DADUDE_SERVER_URL: $SERVER_URL${NC}"
fi

if [ -z "$AGENT_ID" ]; then
    echo -e "${RED}✗ DADUDE_AGENT_ID non configurato${NC}"
else
    echo -e "${GREEN}✓ DADUDE_AGENT_ID: $AGENT_ID${NC}"
fi

if [ -z "$AGENT_TOKEN" ]; then
    echo -e "${RED}✗ DADUDE_AGENT_TOKEN non configurato${NC}"
else
    echo -e "${GREEN}✓ DADUDE_AGENT_TOKEN: ${AGENT_TOKEN:0:8}...${NC}"
fi

if [ -z "$AGENT_NAME" ]; then
    echo -e "${YELLOW}⚠ DADUDE_AGENT_NAME non configurato${NC}"
else
    echo -e "${GREEN}✓ DADUDE_AGENT_NAME: $AGENT_NAME${NC}"
fi

# Verifica file config.json
if [ -f /app/config/config.json ]; then
    echo -e "${GREEN}✓ File config.json trovato${NC}"
    echo "Contenuto config.json:"
    cat /app/config/config.json | python3 -m json.tool 2>/dev/null || cat /app/config/config.json
elif [ -f /opt/dadude-agent/dadude-agent/config/config.json ]; then
    echo -e "${GREEN}✓ File config.json trovato in /opt/dadude-agent/dadude-agent/config/${NC}"
    echo "Contenuto config.json:"
    cat /opt/dadude-agent/dadude-agent/config/config.json | python3 -m json.tool 2>/dev/null || cat /opt/dadude-agent/dadude-agent/config/config.json
else
    echo -e "${YELLOW}⚠ File config.json non trovato${NC}"
fi

# 2. Verifica connettività di rete
echo -e "\n${BLUE}=== 2. CONNETTIVITÀ RETE ===${NC}"

# Estrai hostname e porta dal server URL
if [ -n "$SERVER_URL" ]; then
    # Rimuovi protocollo
    SERVER_HOST_PORT=$(echo "$SERVER_URL" | sed 's|^https\?://||' | sed 's|^wss\?://||')
    SERVER_HOST=$(echo "$SERVER_HOST_PORT" | cut -d: -f1)
    SERVER_PORT=$(echo "$SERVER_HOST_PORT" | cut -d: -f2)
    
    if [ -z "$SERVER_PORT" ]; then
        if echo "$SERVER_URL" | grep -q "https\|wss"; then
            SERVER_PORT=443
        else
            SERVER_PORT=8000
        fi
    fi
    
    echo "Server: $SERVER_HOST:$SERVER_PORT"
    
    # Test DNS
    if command_exists nslookup; then
        if nslookup "$SERVER_HOST" >/dev/null 2>&1; then
            SERVER_IP=$(nslookup "$SERVER_HOST" 2>/dev/null | grep -A1 "Name:" | grep "Address:" | awk '{print $2}' | head -1)
            echo -e "${GREEN}✓ DNS risolto: $SERVER_HOST -> $SERVER_IP${NC}"
        else
            echo -e "${RED}✗ DNS non risolto per $SERVER_HOST${NC}"
            SERVER_IP="$SERVER_HOST"
        fi
    else
        SERVER_IP="$SERVER_HOST"
    fi
    
    # Test ping
    if command_exists ping; then
        if ping -c 1 -W 2 "$SERVER_IP" >/dev/null 2>&1; then
            echo -e "${GREEN}✓ Ping riuscito a $SERVER_IP${NC}"
        else
            echo -e "${RED}✗ Ping fallito a $SERVER_IP${NC}"
        fi
    fi
    
    # Test connessione TCP
    if command_exists nc || command_exists netcat; then
        NC_CMD=$(command_exists nc && echo "nc" || echo "netcat")
        if timeout 3 $NC_CMD -z "$SERVER_HOST" "$SERVER_PORT" 2>/dev/null; then
            echo -e "${GREEN}✓ Connessione TCP riuscita a $SERVER_HOST:$SERVER_PORT${NC}"
        else
            echo -e "${RED}✗ Connessione TCP fallita a $SERVER_HOST:$SERVER_PORT${NC}"
        fi
    elif command_exists timeout && command_exists bash; then
        if timeout 3 bash -c "echo > /dev/tcp/$SERVER_HOST/$SERVER_PORT" 2>/dev/null; then
            echo -e "${GREEN}✓ Connessione TCP riuscita a $SERVER_HOST:$SERVER_PORT${NC}"
        else
            echo -e "${RED}✗ Connessione TCP fallita a $SERVER_HOST:$SERVER_PORT${NC}"
        fi
    fi
    
    # Test HTTP/HTTPS
    if command_exists curl; then
        echo "Test HTTP al server..."
        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$SERVER_URL/api/v1/agents/pending" 2>/dev/null || echo "000")
        if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
            echo -e "${GREEN}✓ Server raggiungibile via HTTP (codice: $HTTP_CODE)${NC}"
        elif [ "$HTTP_CODE" = "000" ]; then
            echo -e "${RED}✗ Server non raggiungibile via HTTP${NC}"
        else
            echo -e "${YELLOW}⚠ Server risponde con codice: $HTTP_CODE${NC}"
        fi
    elif command_exists wget; then
        echo "Test HTTP al server..."
        if wget -q --spider --timeout=5 "$SERVER_URL/api/v1/agents/pending" 2>/dev/null; then
            echo -e "${GREEN}✓ Server raggiungibile via HTTP${NC}"
        else
            echo -e "${RED}✗ Server non raggiungibile via HTTP${NC}"
        fi
    fi
fi

# 3. Verifica registrazione agent sul server
echo -e "\n${BLUE}=== 3. STATO REGISTRAZIONE ===${NC}"

if [ -n "$SERVER_URL" ] && [ -n "$AGENT_ID" ] && [ -n "$AGENT_TOKEN" ]; then
    if command_exists curl; then
        # Prova a verificare se l'agent è registrato
        echo "Verifica registrazione agent sul server..."
        
        # Test registrazione (richiede token)
        REG_RESPONSE=$(curl -s -w "\n%{http_code}" --max-time 10 \
            -X POST "$SERVER_URL/api/v1/agents/register" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $AGENT_TOKEN" \
            -d "{\"agent_id\":\"$AGENT_ID\",\"agent_name\":\"$AGENT_NAME\",\"agent_type\":\"docker\",\"version\":\"2.3.12\"}" \
            2>/dev/null || echo -e "\n000")
        
        HTTP_CODE=$(echo "$REG_RESPONSE" | tail -1)
        REG_BODY=$(echo "$REG_RESPONSE" | head -n -1)
        
        if [ "$HTTP_CODE" = "200" ]; then
            echo -e "${GREEN}✓ Agent registrato sul server${NC}"
            echo "Risposta server:"
            echo "$REG_BODY" | python3 -m json.tool 2>/dev/null || echo "$REG_BODY"
            
            # Verifica se approvato
            APPROVED=$(echo "$REG_BODY" | python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('approved', False))" 2>/dev/null || echo "false")
            if [ "$APPROVED" = "True" ] || [ "$APPROVED" = "true" ]; then
                echo -e "${GREEN}✓ Agent approvato${NC}"
            else
                echo -e "${YELLOW}⚠ Agent NON approvato - richiede approvazione admin${NC}"
                echo "Vai su $SERVER_URL/agents per approvare l'agent"
            fi
        elif [ "$HTTP_CODE" = "000" ]; then
            echo -e "${RED}✗ Impossibile contattare il server${NC}"
        else
            echo -e "${YELLOW}⚠ Errore registrazione (codice: $HTTP_CODE)${NC}"
            echo "Risposta: $REG_BODY"
        fi
    else
        echo -e "${YELLOW}⚠ curl non disponibile, impossibile verificare registrazione${NC}"
    fi
else
    echo -e "${YELLOW}⚠ Configurazione incompleta, impossibile verificare registrazione${NC}"
fi

# 4. Verifica log agent
echo -e "\n${BLUE}=== 4. LOG AGENT ===${NC}"

LOG_PATHS=(
    "/var/lib/dadude-agent/logs/agent.log"
    "/opt/dadude-agent/dadude-agent/logs/agent.log"
    "/var/log/dadude-agent.log"
)

LOG_FOUND=false
for LOG_PATH in "${LOG_PATHS[@]}"; do
    if [ -f "$LOG_PATH" ]; then
        echo -e "${GREEN}✓ Log trovato: $LOG_PATH${NC}"
        echo "Ultime 20 righe del log:"
        tail -20 "$LOG_PATH" | grep -E "(error|ERROR|warning|WARNING|connected|CONNECTED|registration|REGISTRATION|enrollment|ENROLLMENT)" || tail -20 "$LOG_PATH"
        LOG_FOUND=true
        break
    fi
done

if [ "$LOG_FOUND" = false ]; then
    echo -e "${YELLOW}⚠ Nessun file di log trovato${NC}"
fi

# 5. Verifica stato connessione WebSocket
echo -e "\n${BLUE}=== 5. STATO CONNESSIONE ===${NC}"

STATE_FILE="/var/lib/dadude-agent/connection_state.json"
if [ -f "$STATE_FILE" ]; then
    echo -e "${GREEN}✓ File stato connessione trovato${NC}"
    echo "Stato connessione:"
    cat "$STATE_FILE" | python3 -m json.tool 2>/dev/null || cat "$STATE_FILE"
else
    echo -e "${YELLOW}⚠ File stato connessione non trovato${NC}"
fi

# 6. Verifica processi agent
echo -e "\n${BLUE}=== 6. PROCESSI AGENT ===${NC}"

if pgrep -f "python.*agent" >/dev/null 2>&1 || pgrep -f "app.agent" >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Processo agent in esecuzione${NC}"
    ps aux | grep -E "python.*agent|app.agent" | grep -v grep
else
    echo -e "${RED}✗ Nessun processo agent in esecuzione${NC}"
fi

# 7. Riepilogo e suggerimenti
echo -e "\n${BLUE}=== 7. RIEPILOGO ===${NC}"

ISSUES=0

if [ -z "$SERVER_URL" ]; then
    echo -e "${RED}✗ SERVER_URL non configurato${NC}"
    ((ISSUES++))
fi

if [ -z "$AGENT_ID" ]; then
    echo -e "${RED}✗ AGENT_ID non configurato${NC}"
    ((ISSUES++))
fi

if [ -z "$AGENT_TOKEN" ]; then
    echo -e "${RED}✗ AGENT_TOKEN non configurato${NC}"
    ((ISSUES++))
fi

if [ $ISSUES -eq 0 ]; then
    echo -e "${GREEN}✓ Configurazione base completa${NC}"
    echo ""
    echo "Se l'agent non si connette:"
    echo "1. Verifica che il server sia raggiungibile dalla rete del container"
    echo "2. Verifica che l'agent sia approvato su $SERVER_URL/agents"
    echo "3. Controlla i log per errori specifici"
    echo "4. Riavvia l'agent: systemctl restart dadude-agent (o riavvia container)"
else
    echo -e "${RED}✗ Trovati $ISSUES problemi di configurazione${NC}"
    echo ""
    echo "Per configurare l'agent:"
    echo "1. Modifica /opt/dadude-agent/.env con le variabili corrette"
    echo "2. Oppure usa lo script regenerate-env.sh per rigenerare la configurazione"
fi

echo ""
echo -e "${BLUE}Diagnostica completata${NC}"

