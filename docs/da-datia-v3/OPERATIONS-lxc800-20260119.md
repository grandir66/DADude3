> ⚠️ **Documento storico — non è l'infrastruttura di oggi.**
> Descrive l'installazione DaDude dell'era **LXC 800** (rete 192.168.4.45,
> host Proxmox 192.168.40.3, sottorete 99.x), aggiornato il 2026-01-19.
> L'installazione attuale è documentata in [`OPERATIONS.md`](OPERATIONS.md)
> accanto a questo file: **PCT 600/601**, host 192.168.40.1. Sono due
> sistemi diversi, non due versioni dello stesso documento.
> Rientrato dal Desktop il 2026-09-03: verificare ogni IP prima di usarlo.

# DaDude - Guida Operativa

## Infrastruttura

### Server DaDude
- **Host Proxmox**: 192.168.40.3
- **Container LXC**: 800
- **IP Container**: 192.168.4.45
- **URL**: http://dadude.domarc.it:8000
- **Porta interna**: 8000

### Agent Domarc
- **Host Proxmox**: 192.168.40.3
- **Container LXC**: 610
- **IP Container**: 192.168.4.193
- **Agent ID**: agent-Domarc

### Agent Rete 99
- **Host Proxmox**: 192.168.99.10
- **Container LXC**: 903
- **IP Container**: 192.168.99.14
- **Agent ID**: agent-rete99

### Agent Test2
- **Host Proxmox**: 192.168.99.10
- **Container LXC**: 901
- **IP Container**: 192.168.99.74
- **Agent ID**: agent-test2

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
ssh root@192.168.40.3 "pct exec 800 -- docker logs dadude --tail 50"

# Log in tempo reale
ssh root@192.168.40.3 "pct exec 800 -- docker logs dadude -f"

# Solo errori
ssh root@192.168.40.3 "pct exec 800 -- docker logs dadude 2>&1 | grep -i error"

# Solo connessioni agent
ssh root@192.168.40.3 "pct exec 800 -- docker logs dadude 2>&1 | grep -i connected"
```

### Agent Domarc (610)
```bash
# Ultimi 50 log
ssh root@192.168.40.3 "pct exec 610 -- docker logs dadude-agent --tail 50"

# Log in tempo reale
ssh root@192.168.40.3 "pct exec 610 -- docker logs dadude-agent -f"
```

### Agent Rete 99 (903)
```bash
# Ultimi 50 log
ssh root@192.168.99.10 "pct exec 903 -- docker logs dadude-agent --tail 50"

# Log in tempo reale
ssh root@192.168.99.10 "pct exec 903 -- docker logs dadude-agent -f"
```

---

## Deploy e Aggiornamenti

### Aggiornare il Server
```bash
ssh root@192.168.40.3 "pct exec 800 -- bash -c '
cd /opt/dadude && 
git pull origin main && 
cd dadude && 
docker compose build --quiet && 
docker compose up -d
'"
```

### Aggiornare Agent Domarc (610)
```bash
ssh root@192.168.40.3 "pct exec 610 -- bash -c '
cd /opt/dadude-agent && 
git pull origin main && 
cd dadude-agent && 
docker compose build --quiet && 
docker compose up -d
'"
```

### Aggiornare Agent Rete 99 (903)
```bash
ssh root@192.168.99.10 "pct exec 903 -- bash -c '
cd /opt/dadude-agent && 
git pull origin main && 
cd dadude-agent && 
docker compose build --quiet && 
docker compose up -d
'"
```

### Rebuild con cache pulita (se necessario)
```bash
docker compose build --no-cache && docker compose up -d
```

---

## Gestione Container

### Stato container
```bash
# Server
ssh root@192.168.40.3 "pct exec 800 -- docker ps"

# Agent 610
ssh root@192.168.40.3 "pct exec 610 -- docker ps"

# Agent 903
ssh root@192.168.99.10 "pct exec 903 -- docker ps"
```

### Riavvio container
```bash
docker compose restart
```

### Stop e rimozione
```bash
docker compose down
```

### Rimozione container orfani
```bash
docker compose down --remove-orphans
```

---

## Configurazione Agent (.env)

Il file `.env` deve trovarsi in `/opt/dadude-agent/dadude-agent/.env`

```env
DADUDE_AGENT_ID=agent-nome
DADUDE_SERVER_URL=http://dadude.domarc.it:8000
DADUDE_AGENT_NAME=Nome Agent
```

**Importante**: Dopo aver modificato il `.env`, ricreare il container:
```bash
docker compose down && docker compose up -d
```

---

## Versioning

Le versioni sono definite in:
- **Server**: `dadude/app/routers/agents.py` → `SERVER_VERSION` e `AGENT_VERSION`
- **Agent**: `dadude-agent/app/agent.py` → `AGENT_VERSION`
- **Agent (legacy)**: `dadude-agent/app/main.py` → `AGENT_VERSION`

**Regola**: Ogni modifica deve incrementare la versione e fare commit+push su Git.

---

## Database

### Accesso SQLite
```bash
ssh root@192.168.40.3 "pct exec 800 -- docker exec dadude python3 -c '
import sqlite3
conn = sqlite3.connect(\"/app/data/dadude.db\")
c = conn.cursor()
c.execute(\"SELECT name FROM sqlite_master WHERE type=table\")
for r in c.fetchall():
    print(r[0])
'"
```

### Query agent
```bash
ssh root@192.168.40.3 "pct exec 800 -- docker exec dadude python3 -c '
import sqlite3
conn = sqlite3.connect(\"/app/data/dadude.db\")
c = conn.cursor()
c.execute(\"SELECT id, name, address, agent_type, active FROM agent_assignments\")
for r in c.fetchall():
    print(r)
'"
```

### Query reti
```bash
ssh root@192.168.40.3 "pct exec 800 -- docker exec dadude python3 -c '
import sqlite3
conn = sqlite3.connect(\"/app/data/dadude.db\")
c = conn.cursor()
c.execute(\"SELECT id, name, ip_network, gateway_snmp_address FROM networks\")
for r in c.fetchall():
    print(r)
'"
```

---

## Troubleshooting

### Agent non si connette (403 Forbidden)
1. Verificare che l'agent esista nel DB con `active = 1`
2. Rimuovere il token se c'è mismatch:
```bash
docker exec dadude python3 -c "
import sqlite3
conn = sqlite3.connect('/app/data/dadude.db')
c = conn.cursor()
c.execute('UPDATE agent_assignments SET agent_token = NULL WHERE name = \"NomeAgent\"')
conn.commit()
"
```

### Agent usa configurazione sbagliata
Verificare le variabili d'ambiente nel container:
```bash
docker exec dadude-agent env | grep DADUDE
```

### Docker CLI troppo vecchio nell'agent
L'immagine deve avere Docker CLI v27+. Rebuild con `--no-cache`:
```bash
docker compose build --no-cache && docker compose up -d
```

### Scansione non trova device
1. Verificare che l'agent sia connesso (log server)
2. Testare manualmente:
```bash
curl -X POST "http://localhost:8000/api/v1/customers/agents/AGENT_ID/scan-customer-networks?customer_id=CUSTOMER_ID&network_ids=NETWORK_ID"
```

---

## DNS Interno

- **Server DNS**: 192.168.4.1
- Configurato in `dadude/docker-compose.yml`:
```yaml
dns:
  - 192.168.4.1
```

---

## Backup Database

```bash
# Copia backup
ssh root@192.168.40.3 "pct exec 800 -- docker cp dadude:/app/data/dadude.db /tmp/dadude.db.backup"

# Ripristino
ssh root@192.168.40.3 "pct exec 800 -- docker cp /tmp/dadude.db.backup dadude:/app/data/dadude.db"
ssh root@192.168.40.3 "pct exec 800 -- docker compose restart"
```

