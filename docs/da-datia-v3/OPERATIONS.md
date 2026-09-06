# DaDude - Guida Operativa

## Infrastruttura

### Server DaDude
- **Host Proxmox**: 192.168.40.1
- **Container LXC**: 600 (PCT 600)
- **URL Agent API**: https://dadude.domarc.it:8000 (porta 8000 - Agent API)
- **URL Admin UI**: https://dadude.domarc.it:8001 (porta 8001 - Admin UI)
- **Architettura**: Dual-port (separazione sicurezza)

### Agent Domarc
- **Host Proxmox**: 192.168.40.1
- **Container LXC**: 601 (PCT 601)
- **Agent ID**: agent-Domarc-5193
- **Agent Name**: Domarc

---

## Repository Git

- **URL**: https://github.com/grandir66/Dadude
- **Branch principale**: main
- **Struttura**:
  - `dadude/` - Server FastAPI
  - `dadude-agent/` - Agent Docker

---

## Comandi Log

### Server DaDude
```bash
# Ultimi 50 log
ssh root@192.168.40.1 "pct exec 600 -- docker logs dadude --tail 50"

# Log in tempo reale
ssh root@192.168.40.1 "pct exec 600 -- docker logs dadude -f"

# Solo errori
ssh root@192.168.40.1 "pct exec 600 -- docker logs dadude 2>&1 | grep -i error"

# Solo connessioni agent
ssh root@192.168.40.1 "pct exec 600 -- docker logs dadude 2>&1 | grep -i connected"
```

### Agent Domarc (601)
```bash
# Ultimi 50 log
ssh root@192.168.40.1 "pct exec 601 -- docker logs dadude-agent --tail 50"

# Log in tempo reale
ssh root@192.168.40.1 "pct exec 601 -- docker logs dadude-agent -f"
```

---

## Deploy e Aggiornamenti

### ⚠️ IMPORTANTE: Procedura Corretta

Il codice è montato come **volume** dal filesystem dell'host. Per aggiornare:

1. `git pull` nel repository
2. `docker restart` (NON serve rebuild)

### Aggiornare il Server (PCT 600)
```bash
ssh root@192.168.40.1 "pct exec 600 -- bash -c '
cd /opt/dadude && 
git pull origin main && 
docker restart dadude
'"
```

### Aggiornare Agent Domarc (PCT 601)
```bash
ssh root@192.168.40.1 "pct exec 601 -- bash -c '
cd /opt/dadude-agent/dadude-agent && 
git pull origin main && 
docker restart dadude-agent
'"
```

### Rebuild completo (solo se necessario)
```bash
# Agent
ssh root@192.168.40.1 "pct exec 601 -- bash -c '
cd /opt/dadude-agent/dadude-agent && 
git pull origin main && 
docker compose down && 
docker compose up -d --build
'"

# Server
ssh root@192.168.40.1 "pct exec 600 -- bash -c '
cd /opt/dadude/dadude && 
git pull origin main && 
docker compose -f docker-compose-dual.yml down && 
docker compose -f docker-compose-dual.yml up -d --build
'"
```

---

## Gestione Container

### Stato container
```bash
# Server
ssh root@192.168.40.1 "pct exec 600 -- docker ps"

# Agent 601
ssh root@192.168.40.1 "pct exec 601 -- docker ps"
```

### Riavvio container
```bash
# Server
ssh root@192.168.40.1 "pct exec 600 -- docker restart dadude"

# Agent
ssh root@192.168.40.1 "pct exec 601 -- docker restart dadude-agent"
```

### Stop e rimozione
```bash
# Server
ssh root@192.168.40.1 "pct exec 600 -- bash -c 'cd /opt/dadude/dadude && docker compose -f docker-compose-dual.yml down'"

# Agent
ssh root@192.168.40.1 "pct exec 601 -- bash -c 'cd /opt/dadude-agent/dadude-agent && docker compose down'"
```

---

## Configurazione Agent (.env)

Il file `.env` deve trovarsi in `/opt/dadude-agent/dadude-agent/.env`

```env
# DaDude Agent v3.0.0 - WebSocket Mode
DADUDE_SERVER_URL=https://dadude.domarc.it:8000
DADUDE_AGENT_ID=agent-Domarc-5193
DADUDE_AGENT_NAME=Domarc
DADUDE_AGENT_TOKEN=<token-dal-server>
DADUDE_CONNECTION_MODE=websocket
DADUDE_LOG_LEVEL=INFO
DADUDE_DATA_DIR=/var/lib/dadude-agent
```

**Importante**: Dopo aver modificato il `.env`, ricreare il container:
```bash
ssh root@192.168.40.1 "pct exec 601 -- bash -c 'cd /opt/dadude-agent/dadude-agent && docker compose down && docker compose up -d'"
```

---

## Versioning

Le versioni sono definite in:
- **Server**: `dadude/app/config.py` → `VERSION`
- **Agent**: `dadude-agent/app/agent.py` → `AGENT_VERSION`
- **File VERSION**: `dadude/VERSION` e `dadude-agent/VERSION`

**Regola**: Ogni modifica deve incrementare la versione e fare commit+push su Git.

---

## API Utili

### Verifica stato agent
```bash
curl -s -k "https://dadude.domarc.it:8001/api/v1/agents/status" | python3 -m json.tool
```

### Test unified scan
```bash
curl -s -k -X POST "https://dadude.domarc.it:8001/api/v1/unified-scanner/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "device_id": "test",
    "target_address": "192.168.40.254",
    "customer_id": "CUSTOMER_ID",
    "protocols": ["auto"],
    "timeout": 180
  }'
```

---

## Troubleshooting

### Agent non si connette
1. Verificare il .env abbia token corretto
2. Verificare connettività: `curl -k https://dadude.domarc.it:8000/health`
3. Controllare log agent: `docker logs dadude-agent --tail 50`

### Agent usa configurazione sbagliata
Verificare le variabili d'ambiente nel container:
```bash
ssh root@192.168.40.1 "pct exec 601 -- docker exec dadude-agent env | grep DADUDE"
```

### Codice non aggiornato dopo git pull
Il container Docker monta il codice dal volume. Verificare:
```bash
# Verificare che il volume sia montato correttamente
ssh root@192.168.40.1 "pct exec 601 -- docker exec dadude-agent ls -la /opt/dadude-agent/app/probes/"
```

Se il codice non è aggiornato, ricreare il container:
```bash
ssh root@192.168.40.1 "pct exec 601 -- bash -c 'cd /opt/dadude-agent/dadude-agent && docker compose down && docker compose up -d'"
```

### Scansione non trova device
1. Verificare che l'agent sia connesso (log server)
2. Testare manualmente con curl (vedi sezione API Utili)

---

## DNS Interno

- **Server DNS**: 192.168.4.1
- Configurato in `dadude/docker-compose-dual.yml`:
```yaml
dns:
  - 192.168.4.1
  - 8.8.8.8
```

---

## Backup

### Backup dati
```bash
ssh root@192.168.40.1 "pct exec 600 -- docker cp dadude:/app/repo/data /tmp/dadude-data-backup"
```

### Ripristino
```bash
ssh root@192.168.40.1 "pct exec 600 -- docker cp /tmp/dadude-data-backup dadude:/app/repo/data"
ssh root@192.168.40.1 "pct exec 600 -- docker restart dadude"
```
