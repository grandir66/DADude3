#!/bin/bash
#
# Script di diagnostica remota per agent DaDude
# Esegui questo script sull'host Proxmox per diagnosticare PCT 601 e 602
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
echo "║  DaDude Agent - Diagnostica Remota PCT 601/602           ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# PCT IDs da verificare
PCT_IDS=(601 602)

# Server DaDude (da configurazione)
SERVER_IP="192.168.4.45"
SERVER_URL="http://${SERVER_IP}:8000"

echo -e "\n${BLUE}=== VERIFICA HOST PROXMOX ===${NC}"
echo "Host: $(hostname)"
echo "IP: $(hostname -I | awk '{print $1}')"
echo "Data: $(date)"

# Funzione per diagnosticare un container
diagnose_pct() {
    local CTID=$1
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}=== DIAGNOSTICA PCT ${CTID} ===${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    
    # Verifica che il container esista
    if ! pct status $CTID &>/dev/null; then
        echo -e "${RED}✗ Container ${CTID} non trovato${NC}"
        return 1
    fi
    
    # Stato container
    echo -e "\n${BLUE}--- Stato Container ---${NC}"
    PCT_STATUS=$(pct status $CTID 2>/dev/null | awk '{print $2}')
    if [ "$PCT_STATUS" = "running" ]; then
        echo -e "${GREEN}✓ Container ${CTID} è in esecuzione${NC}"
    else
        echo -e "${RED}✗ Container ${CTID} non è in esecuzione (stato: ${PCT_STATUS})${NC}"
        echo "Avvio container..."
        pct start $CTID || echo -e "${RED}✗ Impossibile avviare container${NC}"
        sleep 3
    fi
    
    # Configurazione rete
    echo -e "\n${BLUE}--- Configurazione Rete ---${NC}"
    PCT_IP=$(pct config $CTID | grep "ip=" | head -1 | cut -d'=' -f2 | cut -d'/' -f1)
    if [ -n "$PCT_IP" ]; then
        echo -e "${GREEN}✓ IP Container: ${PCT_IP}${NC}"
    else
        echo -e "${YELLOW}⚠ IP non configurato o non rilevabile${NC}"
    fi
    
    # Verifica connettività dal container al server
    echo -e "\n${BLUE}--- Connettività al Server DaDude ---${NC}"
    echo "Server: ${SERVER_IP}:8000"
    
    if pct exec $CTID -- ping -c 2 -W 2 ${SERVER_IP} &>/dev/null; then
        echo -e "${GREEN}✓ Ping al server riuscito${NC}"
    else
        echo -e "${RED}✗ Ping al server fallito${NC}"
    fi
    
    if pct exec $CTID -- timeout 3 bash -c "echo > /dev/tcp/${SERVER_IP}/8000" 2>/dev/null; then
        echo -e "${GREEN}✓ Porta 8000 raggiungibile${NC}"
    else
        echo -e "${RED}✗ Porta 8000 non raggiungibile${NC}"
    fi
    
    # Verifica configurazione agent
    echo -e "\n${BLUE}--- Configurazione Agent ---${NC}"
    
    if pct exec $CTID -- test -f /opt/dadude-agent/.env; then
        echo -e "${GREEN}✓ File .env trovato${NC}"
        echo "Contenuto .env (solo variabili DADUDE_):"
        pct exec $CTID -- grep "^DADUDE_" /opt/dadude-agent/.env 2>/dev/null || echo "Nessuna variabile DADUDE_ trovata"
    else
        echo -e "${RED}✗ File .env non trovato${NC}"
    fi
    
    # Leggi configurazione
    SERVER_URL_CONF=$(pct exec $CTID -- grep "^DADUDE_SERVER_URL=" /opt/dadude-agent/.env 2>/dev/null | cut -d'=' -f2 | tr -d '"' || echo "")
    AGENT_ID=$(pct exec $CTID -- grep "^DADUDE_AGENT_ID=" /opt/dadude-agent/.env 2>/dev/null | cut -d'=' -f2 | tr -d '"' || echo "")
    AGENT_NAME=$(pct exec $CTID -- grep "^DADUDE_AGENT_NAME=" /opt/dadude-agent/.env 2>/dev/null | cut -d'=' -f2 | tr -d '"' || echo "")
    AGENT_TOKEN=$(pct exec $CTID -- grep "^DADUDE_AGENT_TOKEN=" /opt/dadude-agent/.env 2>/dev/null | cut -d'=' -f2 | tr -d '"' || echo "")
    
    if [ -n "$SERVER_URL_CONF" ]; then
        echo -e "${GREEN}✓ SERVER_URL: ${SERVER_URL_CONF}${NC}"
    else
        echo -e "${RED}✗ SERVER_URL non configurato${NC}"
    fi
    
    if [ -n "$AGENT_ID" ]; then
        echo -e "${GREEN}✓ AGENT_ID: ${AGENT_ID}${NC}"
    else
        echo -e "${RED}✗ AGENT_ID non configurato${NC}"
    fi
    
    if [ -n "$AGENT_NAME" ]; then
        echo -e "${GREEN}✓ AGENT_NAME: ${AGENT_NAME}${NC}"
    else
        echo -e "${YELLOW}⚠ AGENT_NAME non configurato${NC}"
    fi
    
    if [ -n "$AGENT_TOKEN" ]; then
        echo -e "${GREEN}✓ AGENT_TOKEN: ${AGENT_TOKEN:0:8}...${NC}"
    else
        echo -e "${RED}✗ AGENT_TOKEN non configurato${NC}"
    fi
    
    # Verifica processo agent
    echo -e "\n${BLUE}--- Processo Agent ---${NC}"
    if pct exec $CTID -- pgrep -f "python.*agent\|app.agent" &>/dev/null; then
        echo -e "${GREEN}✓ Processo agent in esecuzione${NC}"
        echo "Processi:"
        pct exec $CTID -- ps aux | grep -E "python.*agent|app.agent" | grep -v grep || true
    else
        echo -e "${RED}✗ Nessun processo agent in esecuzione${NC}"
    fi
    
    # Verifica log
    echo -e "\n${BLUE}--- Log Agent ---${NC}"
    LOG_PATHS=(
        "/var/lib/dadude-agent/logs/agent.log"
        "/opt/dadude-agent/dadude-agent/logs/agent.log"
    )
    
    LOG_FOUND=false
    for LOG_PATH in "${LOG_PATHS[@]}"; do
        if pct exec $CTID -- test -f "$LOG_PATH"; then
            echo -e "${GREEN}✓ Log trovato: ${LOG_PATH}${NC}"
            echo "Ultime 15 righe (errori/warning/connessioni):"
            pct exec $CTID -- tail -15 "$LOG_PATH" | grep -E "(error|ERROR|warning|WARNING|connected|CONNECTED|registration|REGISTRATION|Connection|Failed)" || pct exec $CTID -- tail -15 "$LOG_PATH"
            LOG_FOUND=true
            break
        fi
    done
    
    if [ "$LOG_FOUND" = false ]; then
        echo -e "${YELLOW}⚠ Nessun file di log trovato${NC}"
    fi
    
    # Verifica stato connessione
    echo -e "\n${BLUE}--- Stato Connessione ---${NC}"
    STATE_FILE="/var/lib/dadude-agent/connection_state.json"
    if pct exec $CTID -- test -f "$STATE_FILE"; then
        echo -e "${GREEN}✓ File stato connessione trovato${NC}"
        pct exec $CTID -- cat "$STATE_FILE" | python3 -m json.tool 2>/dev/null || pct exec $CTID -- cat "$STATE_FILE"
    else
        echo -e "${YELLOW}⚠ File stato connessione non trovato${NC}"
    fi
    
    # Test registrazione sul server (se abbiamo token e ID)
    if [ -n "$AGENT_ID" ] && [ -n "$AGENT_TOKEN" ] && [ -n "$SERVER_URL_CONF" ]; then
        echo -e "\n${BLUE}--- Test Registrazione Server ---${NC}"
        
        # Estrai hostname dalla URL
        SERVER_HOST=$(echo "$SERVER_URL_CONF" | sed 's|^https\?://||' | sed 's|^wss\?://||' | cut -d: -f1)
        SERVER_PORT=$(echo "$SERVER_URL_CONF" | sed 's|^https\?://||' | sed 's|^wss\?://||' | cut -d: -f2)
        
        if [ -z "$SERVER_PORT" ]; then
            if echo "$SERVER_URL_CONF" | grep -q "https\|wss"; then
                SERVER_PORT=443
            else
                SERVER_PORT=8000
            fi
        fi
        
        echo "Test connessione a ${SERVER_HOST}:${SERVER_PORT}..."
        
        # Test HTTP
        if pct exec $CTID -- command -v curl &>/dev/null; then
            HTTP_CODE=$(pct exec $CTID -- curl -s -o /dev/null -w "%{http_code}" --max-time 5 "${SERVER_URL_CONF}/api/v1/agents/pending" 2>/dev/null || echo "000")
            if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
                echo -e "${GREEN}✓ Server raggiungibile via HTTP (codice: ${HTTP_CODE})${NC}"
            else
                echo -e "${RED}✗ Server non raggiungibile (codice: ${HTTP_CODE})${NC}"
            fi
            
            # Test registrazione
            echo "Test registrazione agent..."
            REG_RESPONSE=$(pct exec $CTID -- curl -s -w "\n%{http_code}" --max-time 10 \
                -X POST "${SERVER_URL_CONF}/api/v1/agents/register" \
                -H "Content-Type: application/json" \
                -H "Authorization: Bearer ${AGENT_TOKEN}" \
                -d "{\"agent_id\":\"${AGENT_ID}\",\"agent_name\":\"${AGENT_NAME:-${AGENT_ID}}\",\"agent_type\":\"docker\",\"version\":\"2.3.12\"}" \
                2>/dev/null || echo -e "\n000")
            
            HTTP_CODE=$(echo "$REG_RESPONSE" | tail -1)
            REG_BODY=$(echo "$REG_RESPONSE" | head -n -1)
            
            if [ "$HTTP_CODE" = "200" ]; then
                echo -e "${GREEN}✓ Registrazione riuscita${NC}"
                APPROVED=$(echo "$REG_BODY" | pct exec $CTID -- python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('approved', False))" 2>/dev/null || echo "false")
                if [ "$APPROVED" = "True" ] || [ "$APPROVED" = "true" ]; then
                    echo -e "${GREEN}✓ Agent approvato${NC}"
                else
                    echo -e "${YELLOW}⚠ Agent NON approvato - richiede approvazione admin${NC}"
                    echo "Vai su ${SERVER_URL_CONF}/agents per approvare"
                fi
            else
                echo -e "${YELLOW}⚠ Errore registrazione (codice: ${HTTP_CODE})${NC}"
                echo "Risposta: ${REG_BODY:0:200}"
            fi
        else
            echo -e "${YELLOW}⚠ curl non disponibile nel container${NC}"
        fi
    else
        echo -e "${YELLOW}⚠ Configurazione incompleta, impossibile testare registrazione${NC}"
    fi
    
    # Riepilogo problemi
    echo -e "\n${BLUE}--- Riepilogo Problemi PCT ${CTID} ---${NC}"
    ISSUES=0
    
    if [ "$PCT_STATUS" != "running" ]; then
        echo -e "${RED}✗ Container non in esecuzione${NC}"
        ((ISSUES++))
    fi
    
    if [ -z "$SERVER_URL_CONF" ]; then
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
    
    if ! pct exec $CTID -- pgrep -f "python.*agent\|app.agent" &>/dev/null; then
        echo -e "${RED}✗ Processo agent non in esecuzione${NC}"
        ((ISSUES++))
    fi
    
    if [ $ISSUES -eq 0 ]; then
        echo -e "${GREEN}✓ Nessun problema critico rilevato${NC}"
    else
        echo -e "${RED}✗ Trovati ${ISSUES} problemi${NC}"
    fi
}

# Diagnostica ogni container
for CTID in "${PCT_IDS[@]}"; do
    diagnose_pct $CTID
done

# Riepilogo finale
echo -e "\n${BLUE}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}=== RIEPILOGO FINALE ===${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"

echo ""
echo "Per risolvere i problemi:"
echo "1. Se agent non approvati: vai su ${SERVER_URL}/agents e approva"
echo "2. Se configurazione errata: usa regenerate-env.sh"
echo "3. Se container non avviato: pct start 601 && pct start 602"
echo "4. Se processo non avviato: entra nel container e riavvia il servizio"
echo ""
echo "Script completato!"

