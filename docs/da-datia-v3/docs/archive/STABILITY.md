# Guida alla Stabilità degli Agent DaDude

## Problema

Gli agent DaDude devono rimanere stabili e funzionanti senza dover essere rigenerati ogni due giorni a causa di modifiche al codice.

## Soluzione: Versioning Stabile

### Tag Git Stabili

Ogni versione funzionante viene marcata con un tag Git stabile:
- Formato: `v2.3.X-stable`
- Esempio: `v2.3.13-stable`

### Come Mantenere la Stabilità

1. **NON modificare codice funzionante** senza conferma esplicita dell'utente
2. **Creare un tag stabile** prima di modifiche critiche
3. **Testare** su ambiente di sviluppo prima di applicare modifiche
4. **REVERT immediatamente** se una modifica rompe gli agent

## Configurazione Agent per Stabilità

### Opzione 1: Disabilitare Auto-Update (Consigliato)

Per disabilitare l'auto-update degli agent e mantenerli su una versione stabile:

```bash
# Nel container agent, crea/modifica .env
echo "DADUDE_AUTO_UPDATE=false" >> /opt/dadude-agent/.env
```

### Opzione 2: Usare un Tag Specifico

Per forzare gli agent a usare un tag specifico:

```bash
# Nel container agent
cd /opt/dadude-agent
git fetch --tags
git checkout v2.3.13-stable
docker compose build
docker compose up -d --force-recreate
```

### Opzione 3: Bloccare su Commit Specifico

Per bloccare gli agent su un commit specifico:

```bash
# Nel container agent
cd /opt/dadude-agent
git checkout <commit-hash>
# Salva il commit hash nel file .current_version
echo '{"version": "<commit-hash>"}' > .current_version
```

## Sezioni Critiche - NON Modificare

Le seguenti sezioni di codice funzionano correttamente e NON devono essere modificate senza conferma esplicita:

1. **WebSocket Connection** (`dadude-agent/app/connection/ws_client.py`)
   - `_create_ssl_context()`: Gestisce SSL/mTLS
   - `_reconnect()`: Auto-reconnect

2. **Agent Restart** (`dadude-agent/app/commands/handler.py`)
   - `_update_agent_internal()`: Supporta docker compose v1 e v2
   - `_daily_restart()`: Riavvio giornaliero

3. **Server WebSocket Hub** (`dadude/app/services/websocket_hub.py`)
   - Gestione connessioni agent
   - Auto-disconnect handling

4. **Agent Auto-Probe** (`dadude/app/services/agent_service.py`)
   - Prova SSH anche senza porta 22 rilevata

## Workflow per Modifiche Future

Prima di modificare codice critico:

1. ✅ Verificare che il problema sia reale
2. ✅ Chiedere conferma esplicita all'utente
3. ✅ Creare un tag stabile PRIMA di modificare
4. ✅ Testare su ambiente di sviluppo
5. ✅ Documentare la modifica nelle cursorrules

Se una modifica rompe gli agent:

1. ⚠️ REVERT immediatamente alle modifiche
2. ⚠️ Verificare che il tag stabile funzioni ancora
3. ⚠️ Non aggiungere "fix" su "fix" - meglio revert completo

## Tag Stabili Disponibili

- `v2.3.13-stable`: Versione stabile con fix SSL e docker compose compatibility
- `v2.3.12-stable`: Versione stabile precedente

## Verifica Stabilità Agent

Per verificare che un agent sia stabile:

```bash
# Controlla i log per connessioni riuscite
docker logs dadude-agent 2>&1 | grep -E "(Connected|Connection state.*connected)"

# Controlla la versione corrente
docker exec dadude-agent cat /opt/dadude-agent/.current_version

# Controlla se ci sono errori di connessione
docker logs dadude-agent 2>&1 | grep -i error | tail -20
```

## Troubleshooting

### Agent si disconnette dopo modifiche

1. Verifica quale commit/tag è in uso: `git log --oneline -1`
2. Ripristina tag stabile: `git checkout v2.3.13-stable`
3. Riavvia container: `docker compose up -d --force-recreate`
4. Verifica connessione: `docker logs dadude-agent | grep Connected`

### Agent non si riconnette dopo riavvio server

1. Verifica che il server sia raggiungibile
2. Verifica che SSL/mTLS sia configurato correttamente
3. Controlla i log agent per errori SSL
4. Se necessario, ripristina tag stabile

## Note Importanti

- **MAI modificare codice funzionante** senza conferma esplicita
- **SEMPRE creare un tag stabile** prima di modifiche critiche
- **REVERT immediatamente** se qualcosa si rompe
- **Testare** sempre su ambiente di sviluppo prima di produzione

