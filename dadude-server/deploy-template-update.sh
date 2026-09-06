#!/bin/bash
# Script per copiare il template agents.html sul server PCT 1600

SERVER_HOST="192.168.40.4"
CONTAINER_ID="1600"
TEMPLATE_FILE="app/templates/agents.html"
REMOTE_PATH="/opt/dadude-server/app/templates/agents.html"

echo "📤 Copio agents.html sul server..."
echo "Host: $SERVER_HOST"
echo "Container: $CONTAINER_ID"
echo ""

# Copia il file sul server host
scp "$TEMPLATE_FILE" root@$SERVER_HOST:/tmp/agents.html

# Copia il file nel container
ssh root@$SERVER_HOST "pct push $CONTAINER_ID /tmp/agents.html $REMOTE_PATH"

# Riavvia il servizio per applicare le modifiche
echo ""
echo "🔄 Riavvio servizio dadude-server..."
ssh root@$SERVER_HOST "pct exec $CONTAINER_ID -- systemctl restart dadude-server"

echo ""
echo "✅ File aggiornato e servizio riavviato!"
echo ""
echo "💡 Suggerimento: fai hard refresh nel browser (Ctrl+Shift+R o Cmd+Shift+R)"
