#!/bin/bash
# Script per aggiornare tutti gli agent su tutti i server Proxmox

set -e

# Colori per output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Lista server e container
# Formato: SERVER_IP:CONTAINER_ID:AGENT_NAME
AGENTS=(
    "192.168.40.3:610:DOMARC"
    "192.168.40.3:611:DOMARC-OVH"
    "192.168.99.10:901:DOMARC-RG"
)

echo "=========================================="
echo "AGGIORNAMENTO TUTTI GLI AGENT"
echo "=========================================="
echo ""

TOTAL=${#AGENTS[@]}
SUCCESS=0
FAILED=0

for agent_info in "${AGENTS[@]}"; do
    IFS=':' read -r server_ip container_id agent_name <<< "$agent_info"
    
    echo "----------------------------------------"
    echo "[$((SUCCESS + FAILED + 1))/$TOTAL] Aggiornando $agent_name (Server: $server_ip, Container: $container_id)"
    echo "----------------------------------------"
    
    # Verifica che il container esista e abbia l'agent
    if ! ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@$server_ip "pct exec $container_id -- docker ps --filter name=dadude-agent --format '{{.Names}}' 2>/dev/null | grep -q dadude-agent" 2>/dev/null; then
        echo -e "${YELLOW}⚠️  Container $container_id su $server_ip non ha agent Docker, saltando...${NC}"
        ((FAILED++))
        continue
    fi
    
    # Esegui update
    if ssh -o StrictHostKeyChecking=no root@$server_ip "pct exec $container_id -- bash -c '
        cd /opt/dadude-agent && \
        echo \"1. Fetching latest changes...\" && \
        git fetch origin main 2>&1 && \
        echo \"2. Checking current version...\" && \
        CURRENT=\$(git rev-parse HEAD) && \
        LATEST=\$(git rev-parse origin/main) && \
        echo \"   Current: \${CURRENT:0:8}\" && \
        echo \"   Latest:  \${LATEST:0:8}\" && \
        if [ \"\$CURRENT\" != \"\$LATEST\" ]; then
            echo \"3. Update available! Applying...\" && \
            git reset --hard origin/main 2>&1 && \
            echo \"4. Restarting container...\" && \
            docker restart dadude-agent && \
            echo \"✅ Update completed\"
        else
            echo \"3. Already up to date\"
        fi
    '" 2>&1; then
        echo -e "${GREEN}✅ $agent_name aggiornato con successo${NC}"
        ((SUCCESS++))
    else
        echo -e "${RED}❌ Errore aggiornando $agent_name${NC}"
        ((FAILED++))
    fi
    
    echo ""
    sleep 2
done

echo "=========================================="
echo "RIEPILOGO"
echo "=========================================="
echo -e "${GREEN}✅ Successi: $SUCCESS${NC}"
echo -e "${RED}❌ Falliti: $FAILED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}Tutti gli agent aggiornati con successo!${NC}"
    exit 0
else
    echo -e "${YELLOW}Alcuni agent non sono stati aggiornati. Controlla i log sopra.${NC}"
    exit 1
fi

