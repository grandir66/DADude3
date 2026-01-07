#!/bin/bash
# Script per aggiornare l'UI moderna sul server attivo
# Aggiorna il repository e riavvia il container

set -e

echo "🔄 Aggiornamento UI moderna DaDude v3.0..."

# Verifica se siamo nel container o sul server
if [ -f /.dockerenv ]; then
    echo "⚠️  Eseguito dentro il container Docker"
    echo "📦 Aggiorno repository..."
    cd /app/repo || cd /app/dadude || exit 1
    git pull origin main || echo "⚠️  Git pull fallito, verificare connessione"
    
    echo "🔄 Riavvia il container dall'esterno con: docker restart dadude"
    exit 0
fi

# Se siamo sul server Proxmox
if [ -d "/opt/dadude" ] || [ -d "/app/dadude" ]; then
    echo "📦 Aggiorno repository..."
    cd /opt/dadude/dadude || cd /app/dadude || exit 1
    git pull origin main
    
    echo "🔄 Riavvio container Docker..."
    docker restart dadude || docker-compose restart dadude
    
    echo "✅ Aggiornamento completato!"
    echo "🌐 Verifica su: http://192.168.4.45:8001"
    exit 0
fi

# Se siamo in locale (Mac)
echo "📝 Istruzioni per aggiornare il server remoto:"
echo ""
echo "1. Connettiti al server Proxmox:"
echo "   ssh root@192.168.4.45"
echo ""
echo "2. Vai nella directory del repository:"
echo "   cd /opt/dadude/dadude  # o dove è montato il volume"
echo ""
echo "3. Aggiorna da Git:"
echo "   git pull origin main"
echo ""
echo "4. Riavvia il container:"
echo "   docker restart dadude"
echo "   # oppure"
echo "   cd /path/to/docker-compose && docker compose restart dadude"
echo ""
echo "5. Verifica i file statici sono accessibili:"
echo "   curl http://localhost:8001/static/js/app.js"
echo ""

