#!/bin/bash
# Script di diagnostica per capire perché alcuni agent non si aggiornano

set -e

CONTAINER_ID="${1:-}"
if [ -z "$CONTAINER_ID" ]; then
    echo "Usage: $0 <container_id>"
    echo "Example: $0 901"
    exit 1
fi

echo "=========================================="
echo "DIAGNOSTICA UPDATE AGENT - Container $CONTAINER_ID"
echo "=========================================="
echo ""

# Entra nel container
echo "1. Verifica struttura directory..."
pct exec $CONTAINER_ID -- bash -c "
    echo 'AGENT_DIR: /opt/dadude-agent'
    echo 'Git directory exists:'
    ls -la /opt/dadude-agent/.git 2>&1 | head -5 || echo '  ❌ .git non trovato'
    echo ''
    echo 'Directory structure:'
    ls -la /opt/dadude-agent/ | head -10
    echo ''
    echo 'Mounted code directory:'
    ls -la /opt/agent-code/app/ 2>&1 | head -5 || echo '  ❌ /opt/agent-code/app non trovato'
"

echo ""
echo "2. Verifica repository git..."
pct exec $CONTAINER_ID -- bash -c "
    cd /opt/dadude-agent && \
    echo 'Current commit:'
    git rev-parse HEAD 2>&1 || echo '  ❌ Errore git rev-parse HEAD'
    echo ''
    echo 'Current branch:'
    git branch --show-current 2>&1 || echo '  ❌ Errore git branch'
    echo ''
    echo 'Remote origin:'
    git remote -v 2>&1 || echo '  ❌ Errore git remote'
    echo ''
    echo 'Last fetch:'
    git log origin/main -1 --oneline 2>&1 || echo '  ⚠️  origin/main non disponibile (fetch necessario)'
"

echo ""
echo "3. Test git fetch..."
pct exec $CONTAINER_ID -- bash -c "
    cd /opt/dadude-agent && \
    echo 'Eseguendo git fetch origin main...'
    timeout 30 git fetch origin main 2>&1
    FETCH_EXIT=\$?
    if [ \$FETCH_EXIT -eq 0 ]; then
        echo '  ✅ Git fetch successful'
        echo ''
        echo 'Latest commit on origin/main:'
        git rev-parse origin/main 2>&1 || echo '  ❌ Errore git rev-parse origin/main'
        echo ''
        echo 'Compare with current:'
        CURRENT=\$(git rev-parse HEAD 2>&1)
        LATEST=\$(git rev-parse origin/main 2>&1)
        if [ \"\$CURRENT\" = \"\$LATEST\" ]; then
            echo '  ✅ Already up to date'
        else
            echo '  ⚠️  Update available!'
            echo '  Current: '\$CURRENT
            echo '  Latest:  '\$LATEST
        fi
    else
        echo '  ❌ Git fetch failed (exit code: '\$FETCH_EXIT')'
        echo '  Possibili cause:'
        echo '    - Nessun accesso alla rete'
        echo '    - Problemi di DNS'
        echo '    - Firewall blocca git'
        echo '    - Repository non accessibile'
    fi
"

echo ""
echo "4. Verifica versione agent nel codice..."
pct exec $CONTAINER_ID -- bash -c "
    echo 'Versione nel file montato:'
    grep 'AGENT_VERSION' /opt/agent-code/app/agent.py 2>&1 | head -1 || echo '  ❌ File non trovato'
    echo ''
    echo 'Versione nel codice git:'
    grep 'AGENT_VERSION' /opt/dadude-agent/dadude-agent/app/agent.py 2>&1 | head -1 || echo '  ❌ File non trovato'
    echo ''
    echo 'Versione nel container Docker:'
    docker exec dadude-agent python -c 'import app.agent; print(\"Version:\", app.agent.AGENT_VERSION)' 2>&1 || echo '  ❌ Errore esecuzione Python'
"

echo ""
echo "5. Verifica container Docker..."
pct exec $CONTAINER_ID -- bash -c "
    echo 'Container status:'
    docker ps --filter name=dadude-agent --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}' 2>&1 || echo '  ❌ Container non trovato'
    echo ''
    echo 'Container logs (last 20 lines):'
    docker logs dadude-agent --tail 20 2>&1 | grep -E 'DaDude Agent|AGENT_VERSION|Checking for updates|Update available|No updates' || echo '  ⚠️  Nessun messaggio di update nei log'
"

echo ""
echo "6. Verifica VersionManager..."
pct exec $CONTAINER_ID -- bash -c "
    echo 'VersionManager files:'
    ls -la /opt/dadude-agent/.current_version 2>&1 || echo '  ⚠️  .current_version non trovato'
    ls -la /opt/dadude-agent/.bad_versions 2>&1 || echo '  ⚠️  .bad_versions non trovato'
    ls -la /opt/dadude-agent/backups/ 2>&1 | head -5 || echo '  ⚠️  Directory backups non trovata'
    echo ''
    if [ -f /opt/dadude-agent/.current_version ]; then
        echo 'Current version info:'
        cat /opt/dadude-agent/.current_version 2>&1 | head -10
    fi
"

echo ""
echo "7. Verifica connettività di rete..."
pct exec $CONTAINER_ID -- bash -c "
    echo 'Test DNS:'
    nslookup github.com 2>&1 | head -3 || echo '  ❌ DNS non funziona'
    echo ''
    echo 'Test connessione GitHub:'
    timeout 5 curl -s -o /dev/null -w 'HTTP Status: %{http_code}\n' https://github.com 2>&1 || echo '  ❌ Connessione GitHub fallita'
"

echo ""
echo "=========================================="
echo "DIAGNOSTICA COMPLETATA"
echo "=========================================="
echo ""
echo "Possibili problemi trovati:"
echo "  - Se .git non esiste: il repository non è montato correttamente"
echo "  - Se git fetch fallisce: problemi di rete/DNS/firewall"
echo "  - Se le versioni non corrispondono: il codice non è stato aggiornato"
echo "  - Se VersionManager non trova update: potrebbe essere già aggiornato o git fetch fallito"
echo ""

