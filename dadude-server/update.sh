#!/bin/bash
#
# DaDude Server - Script di aggiornamento standalone
# Uso: ./update.sh [--restart]
#
# Questo script è indipendente dal codice del server
# e può essere usato anche quando il sistema di update della UI non funziona
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo -e "${YELLOW}=== DaDude Server Update ===${NC}"
echo "Directory: $SCRIPT_DIR"
echo ""

# Verifica git
if ! command -v git &> /dev/null; then
    echo -e "${RED}Errore: git non installato${NC}"
    exit 1
fi

# Mostra versione corrente
CURRENT_VERSION=$(grep -oP 'SERVER_VERSION\s*=\s*"\K[^"]+' app/routers/agents.py 2>/dev/null || echo "unknown")
echo -e "Versione corrente: ${YELLOW}v${CURRENT_VERSION}${NC}"

# Fetch updates
echo -e "${YELLOW}Verifico aggiornamenti...${NC}"
git fetch origin main

# Mostra differenze
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)

if [ "$LOCAL" = "$REMOTE" ]; then
    echo -e "${GREEN}✓ Già aggiornato${NC}"
    exit 0
fi

# Conta commit da scaricare
COMMITS=$(git rev-list HEAD..origin/main --count)
echo -e "Trovati ${GREEN}${COMMITS}${NC} nuovi commit"
echo ""

# Mostra changelog
echo -e "${YELLOW}Changelog:${NC}"
git log HEAD..origin/main --oneline | head -10
echo ""

# Pull
echo -e "${YELLOW}Scarico aggiornamenti...${NC}"
git pull --rebase origin main

# Nuova versione
NEW_VERSION=$(grep -oP 'SERVER_VERSION\s*=\s*"\K[^"]+' app/routers/agents.py 2>/dev/null || echo "unknown")
echo -e "Nuova versione: ${GREEN}v${NEW_VERSION}${NC}"
echo ""

# Se in Docker, rebuild
if [ -f "/.dockerenv" ] || [ -f "docker-compose-dual.yml" ] || [ -f "docker-compose-postgres.yml" ]; then
    if [ "$1" = "--restart" ]; then
        echo -e "${YELLOW}Ricostruisco container...${NC}"
        if [ -f "docker-compose-dual.yml" ]; then
            docker compose -f docker-compose-dual.yml build --quiet
            echo -e "${YELLOW}Riavvio...${NC}"
            docker compose -f docker-compose-dual.yml up -d
        elif [ -f "docker-compose-postgres.yml" ]; then
            docker compose -f docker-compose-postgres.yml build --quiet
            echo -e "${YELLOW}Riavvio...${NC}"
            docker compose -f docker-compose-postgres.yml up -d
        fi
        echo -e "${GREEN}✓ Container riavviato${NC}"
    else
        echo -e "${YELLOW}Per applicare le modifiche:${NC}"
        echo "  docker compose -f docker-compose-dual.yml build && docker compose -f docker-compose-dual.yml up -d"
        echo ""
        echo "Oppure esegui: ./update.sh --restart"
    fi
fi

echo ""
echo -e "${GREEN}✓ Aggiornamento completato${NC}"

