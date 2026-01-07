#!/bin/bash
# Script per riavviare DaDude Agent su Proxmox/OVH
# Esegui questo script su ogni server dove è installato l'agent

set -e

AGENT_DIR="/opt/dadude-agent"
COMPOSE_DIR="$AGENT_DIR/dadude-agent"

echo "=========================================="
echo "DaDude Agent Restart Script"
echo "=========================================="

# Verifica che la directory esista
if [ ! -d "$COMPOSE_DIR" ]; then
    echo "ERRORE: Directory $COMPOSE_DIR non trovata!"
    echo "L'agent potrebbe non essere installato qui."
    exit 1
fi

# Verifica che docker-compose.yml esista
if [ ! -f "$COMPOSE_DIR/docker-compose.yml" ]; then
    echo "ERRORE: docker-compose.yml non trovato in $COMPOSE_DIR"
    exit 1
fi

echo "Directory agent trovata: $COMPOSE_DIR"
echo ""

# Controlla stato corrente
echo "Stato corrente:"
cd "$COMPOSE_DIR"
docker compose ps

echo ""
echo "Riavvio agent..."
docker compose restart

echo ""
echo "Attendi 5 secondi per verifica..."
sleep 5

echo ""
echo "Stato dopo riavvio:"
docker compose ps

echo ""
echo "=========================================="
echo "Riavvio completato!"
echo "=========================================="
echo ""
echo "Verifica connessione su: https://dadude.domarc.it:8001/agents"

