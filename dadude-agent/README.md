# DaDude Agent

Agent nativo per scansioni di rete remote, progettato per essere deployato su Proxmox LXC o qualsiasi server Linux.

## Funzionalità

- **WMI Probe**: Scansione dispositivi Windows (CPU, RAM, disco, OS, seriale)
- **SSH Probe**: Scansione dispositivi Linux/Unix con supporto vendor-specific
- **SNMP Probe**: Scansione dispositivi di rete (switch, router, AP, NAS)
- **Port Scan**: Scansione porte TCP/UDP configurabile
- **Reverse DNS**: Risoluzione nomi tramite DNS locale
- **Ping Check**: Verifica raggiungibilità host
- **Auto-Update**: Aggiornamento automatico via Git con watchdog indipendente

## Architettura

```
┌─────────────────┐         ┌──────────────────┐
│  DaDude Server  │◄───────►│  DaDude Agent    │
│  (Central)      │ WebSocket│  (Proxmox LXC)   │
│  dadude.domarc.it│  mTLS  │  /opt/dadude-agent│
└─────────────────┘         └──────────────────┘
                                    │
                                    ▼
                            ┌───────────────┐
                            │ Rete Cliente  │
                            │ - Windows     │
                            │ - Linux      │
                            │ - Switch/AP   │
                            └───────────────┘
```

## Struttura Directory

```
/opt/dadude-agent/          # Repository Git clonato direttamente qui
├── app/                    # Codice agent (unico, non duplicato)
├── config/                 # File di configurazione
├── VERSION                 # Versione corrente
├── requirements.txt        # Dipendenze Python
├── .env                    # Configurazione agent
└── venv/                   # Python virtualenv

/opt/dadude-updater/        # Watchdog aggiornamenti (separato)
├── updater.py              # Script watchdog
├── config.env              # Configurazione updater
├── logs/                   # Log updater
└── state.json              # Stato persistente
```

## Installazione

### Proxmox LXC (Consigliata)

#### Installazione Automatica con installer nativo

**Comando base** (wizard interattivo):

**Comando base** (wizard interattivo):

```bash
curl -fsSL https://raw.githubusercontent.com/grandir66/DADude3/main/dadude-agent/deploy/proxmox/install-native.sh | bash
```

**Con parametri predefiniti** (non interattivo):

```bash
curl -fsSL https://raw.githubusercontent.com/grandir66/DADude3/main/dadude-agent/deploy/proxmox/install-native.sh | bash -s -- \
  --server-url https://dadude.domarc.it:8000 \
  --agent-name "sede-milano" \
  --agent-token "your-secure-token-here" \
  --ctid 1601 \
  --bridge vmbr0 \
  --ip 192.168.1.100/24 \
  --gateway 192.168.1.1 \
  --storage local-lvm \
  --memory 512 \
  --disk 4
```

### Parametri Installazione

| Parametro | Default | Descrizione |
|-----------|---------|-------------|
| `--server-url` | `https://dadude.domarc.it:8000` | URL server DaDude (HTTPS, porta 8000) |
| `--agent-name` | *(obbligatorio)* | Nome descrittivo agent (es: "sede-milano") |
| `--agent-token` | auto-generato | Token autenticazione (24 caratteri esadecimali) |
| `--ctid` | prossimo disponibile | ID container Proxmox LXC |
| `--hostname` | `dadude-agent-{name}` | Hostname del container |
| `--bridge` | *(interattivo)* | Bridge Proxmox (es: vmbr0) |
| `--vlan` | *(opzionale)* | VLAN tag se necessario |
| `--ip` | `dhcp` | IP statico (es: `192.168.1.100/24`) o `dhcp` |
| `--gateway` | suggerito | Gateway di rete (solo se IP statico) |
| `--dns` | da DHCP/gateway | Server DNS |
| `--storage` | *(interattivo)* | Storage Proxmox (es: local-lvm) |
| `--memory` | `512` | RAM in MB |
| `--disk` | `4` | Spazio disco in GB |

### Cosa fa l'installer

1. ✅ Verifica ambiente Proxmox
2. ✅ Wizard interattivo con valori suggeriti
3. ✅ Crea container LXC Debian 12
4. ✅ Installa dipendenze sistema (Python3, nmap, git)
5. ✅ Clone repository Git direttamente in `/opt/dadude-agent`
6. ✅ Setup Python virtualenv
7. ✅ Configura file `.env`
8. ✅ Installa servizi systemd (agent + updater)
9. ✅ Avvia e verifica connessione

#### Installazione con install-from-git.sh (metodo alternativo)

Metodo alternativo che usa `install-from-git.sh`:

```bash
curl -fsSL https://raw.githubusercontent.com/grandir66/DADude3/main/dadude-agent/deploy/proxmox/install-from-git.sh | bash
```

**Opzioni disponibili**:

```bash
bash install-from-git.sh \
  --server-url https://dadude.domarc.it:8000 \
  --agent-name "sede-milano" \
  --ctid 1601 \
  --bridge vmbr0 \
  --ip 192.168.1.100/24 \
  --gateway 192.168.1.1
```

| Opzione | Default | Descrizione |
|---------|---------|-------------|
| `--server-url` | `https://dadude.domarc.it:8000` | URL server DaDude |
| `--agent-name` | (interattivo) | Nome descrittivo agent |
| `--agent-token` | auto-generato | Token autenticazione |
| `--ctid` | prossimo disponibile | ID container Proxmox |
| `--hostname` | `dadude-agent-{name}` | Hostname container |
| `--bridge` | (interattivo) | Bridge Proxmox |
| `--vlan` | (opzionale) | VLAN tag |
| `--ip` | `dhcp` | IP statico o DHCP |
| `--gateway` | suggerito | Gateway rete |
| `--dns` | da DHCP/gateway | Server DNS |
| `--storage` | (interattivo) | Storage Proxmox |
| `--memory` | `512` | RAM in MB |
| `--disk` | `4` | Disco in GB |

#### Pulizia installazione esistente

Se hai un agent con file superflui:

```bash
# Dry-run (mostra cosa verrebbe eliminato)
curl -fsSL https://raw.githubusercontent.com/grandir66/DADude3/main/dadude-agent/deploy/proxmox/cleanup-agent.sh | bash -s -- --dry-run

# Esegui pulizia
curl -fsSL https://raw.githubusercontent.com/grandir66/DADude3/main/dadude-agent/deploy/proxmox/cleanup-agent.sh | bash
```

### MikroTik RouterOS 7

**⚠️ IMPORTANTE**: L'agent ora usa **WebSocket mTLS** invece di API REST. La configurazione è cambiata.

#### Requisiti MikroTik

- RouterOS 7.x con supporto Container
- Almeno 256MB RAM libera
- Storage per immagine Docker (~100MB)

#### Quick Start

1. **Abilita Container Support**:
   ```routeros
   /system/device-mode/update container=yes
   ```
   Riavvia il router.

2. **Configura Variabili d'Ambiente**:
   ```routeros
   /container/envs/add list=dadude-env key=DADUDE_SERVER_URL value=https://dadude.domarc.it:8000
   /container/envs/add list=dadude-env key=DADUDE_AGENT_ID value=agent-NOME-ROUTER
   /container/envs/add list=dadude-env key=DADUDE_AGENT_NAME value=NOME-ROUTER
   /container/envs/add list=dadude-env key=DADUDE_AGENT_TOKEN value=TOKEN-SICURO
   /container/envs/add list=dadude-env key=DADUDE_CONNECTION_MODE value=websocket
   ```

3. **Esegui Script Installazione**:
   Usa lo script `mikrotik-install.rsc` incluso nel repository.

Per dettagli completi, vedi la [guida completa MikroTik](../docs/deployment/MIKROTIK_CONTAINER_SETUP.md).

### Docker Standalone

Installazione su qualsiasi host Docker:

```bash
docker run -d \
  --name dadude-agent \
  --network host \
  -e DADUDE_SERVER_URL=https://dadude.domarc.it:8000 \
  -e DADUDE_AGENT_TOKEN=your-token \
  -e DADUDE_AGENT_ID=agent-001 \
  -e DADUDE_AGENT_NAME="My Agent" \
  -e DADUDE_CONNECTION_MODE=websocket \
  ghcr.io/dadude/agent:latest
```

**Con docker-compose**:

```yaml
version: '3.8'
services:
  agent:
    image: ghcr.io/dadude/agent:latest
    container_name: dadude-agent
    restart: unless-stopped
    network_mode: host
    environment:
      - DADUDE_SERVER_URL=https://dadude.domarc.it:8000
      - DADUDE_AGENT_TOKEN=your-token
      - DADUDE_AGENT_ID=agent-001
      - DADUDE_AGENT_NAME=My Agent
      - DADUDE_CONNECTION_MODE=websocket
    cap_add:
      - NET_RAW
      - NET_ADMIN
```

## Architettura WebSocket

L'agent usa **WebSocket mTLS** per comunicare con il server (agent-initiated):

- ✅ **Nessuna porta in ascolto**: L'agent si connette al server, non viceversa
- ✅ **NAT-friendly**: Funziona dietro firewall senza port forwarding
- ✅ **Sicuro**: mTLS per autenticazione reciproca
- ✅ **Resiliente**: Riconnessione automatica con exponential backoff
- ✅ **Real-time**: Comandi e risultati bidirezionali

### Comandi Supportati

L'agent riceve comandi dal server via WebSocket:

- `scan`: Scansione rete/dispositivi
- `probe`: Probe SSH/SNMP/WMI
- `update`: Auto-update agent
- `restart`: Riavvio agent
- `ping`: Health check

## Monitoraggio e Logging

### Verifica Stato Servizi

**Da host Proxmox** (esempio container 1601):

```bash
# Stato agent
ssh root@192.168.40.4 "pct exec 1601 -- systemctl status dadude-agent --no-pager"

# Stato updater (watchdog)
ssh root@192.168.40.4 "pct exec 1601 -- systemctl status dadude-updater --no-pager"

# Verifica entrambi i servizi attivi
ssh root@192.168.40.4 "pct exec 1601 -- systemctl is-active dadude-agent dadude-updater"
```

### Log Agent

**Ultime 50 righe**:

```bash
ssh root@192.168.40.4 "pct exec 1601 -- journalctl -u dadude-agent -n 50 --no-pager"
```

**Monitoraggio in tempo reale**:

```bash
ssh root@192.168.40.4 "pct exec 1601 -- journalctl -u dadude-agent -f"
```

Premi `Ctrl+C` per uscire dal monitoraggio in tempo reale.

**Log con filtri**:

```bash
# Solo errori
ssh root@192.168.40.4 "pct exec 1601 -- journalctl -u dadude-agent -p err --no-pager"

# Ultime 100 righe con timestamp
ssh root@192.168.40.4 "pct exec 1601 -- journalctl -u dadude-agent -n 100 --no-pager"

# Log da oggi
ssh root@192.168.40.4 "pct exec 1601 -- journalctl -u dadude-agent --since today --no-pager"
```

### Log Updater (Watchdog)

**Monitoraggio in tempo reale**:

```bash
ssh root@192.168.40.4 "pct exec 1601 -- journalctl -u dadude-updater -f"
```

**Ultime righe**:

```bash
ssh root@192.168.40.4 "pct exec 1601 -- journalctl -u dadude-updater -n 50 --no-pager"
```

**Log file diretto**:

```bash
ssh root@192.168.40.4 "pct exec 1601 -- tail -f /opt/dadude-updater/logs/updater.log"
```

### Verifica Connessione WebSocket

**Cerca messaggi di connessione nei log**:

```bash
ssh root@192.168.40.4 "pct exec 1601 -- journalctl -u dadude-agent --no-pager | grep -i 'connected\|websocket\|connection'"
```

Messaggi attesi:
- `Connected to DaDude server`
- `WebSocket connected`
- `Connection established`
- `Heartbeat sent`

### Verifica Versione

**Versione corrente**:

```bash
ssh root@192.168.40.4 "pct exec 1601 -- cat /opt/dadude-agent/VERSION"
```

**Versione nel codice**:

```bash
ssh root@192.168.40.4 "pct exec 1601 -- bash -c 'source /opt/dadude-agent/venv/bin/activate && cd /opt/dadude-agent && python3 -c \"from app.agent import AGENT_VERSION; print(AGENT_VERSION)\"'"
```

## Gestione Aggiornamenti

### Auto-Update (Automatico)

L'updater controlla Git ogni ora e aggiorna automaticamente se trova nuove versioni.

**Configurazione updater** (`/opt/dadude-updater/config.env`):

```bash
AGENT_DIR=/opt/dadude-agent
UPDATER_DIR=/opt/dadude-updater
UPDATE_CHECK_INTERVAL=3600        # Controllo ogni ora
AGENT_HEALTH_TIMEOUT=120          # Timeout health check (secondi)
GIT_REMOTE=origin
GIT_BRANCH=main
```

### Aggiornamento Manuale

**Forza controllo immediato**:

```bash
ssh root@192.168.40.4 "pct exec 1601 -- python3 /opt/dadude-updater/updater.py --once"
```

**Forza aggiornamento** (anche se già aggiornato):

```bash
ssh root@192.168.40.4 "pct exec 1601 -- python3 /opt/dadude-updater/updater.py --once --force"
```

**Riavvia updater**:

```bash
ssh root@192.168.40.4 "pct exec 1601 -- systemctl restart dadude-updater"
```

### Verifica Aggiornamenti Disponibili

**Controlla commit locale vs remoto**:

```bash
ssh root@192.168.40.4 "pct exec 1601 -- bash -c 'cd /opt/dadude-agent && git fetch origin main && git log HEAD..origin/main --oneline'"
```

## Gestione Container

### Accesso Shell Container

```bash
ssh root@192.168.40.4 "pct enter 1601"
```

### Riavvio Servizi

**Riavvia agent**:

```bash
ssh root@192.168.40.4 "pct exec 1601 -- systemctl restart dadude-agent"
```

**Riavvia updater**:

```bash
ssh root@192.168.40.4 "pct exec 1601 -- systemctl restart dadude-updater"
```

**Riavvia entrambi**:

```bash
ssh root@192.168.40.4 "pct exec 1601 -- systemctl restart dadude-agent dadude-updater"
```

### Riavvio Container

```bash
ssh root@192.168.40.4 "pct restart 1601"
```

### Stop/Start Container

```bash
# Stop
ssh root@192.168.40.4 "pct stop 1601"

# Start
ssh root@192.168.40.4 "pct start 1601"
```

## Troubleshooting

### Agent non si connette

**1. Verifica configurazione**:

```bash
ssh root@192.168.40.4 "pct exec 1601 -- cat /opt/dadude-agent/.env"
```

Verifica:
- `DADUDE_SERVER_URL` corretto (HTTPS, porta 8000)
- `DADUDE_AGENT_TOKEN` presente
- `DADUDE_AGENT_ID` univoco

**2. Verifica connessione di rete**:

```bash
ssh root@192.168.40.4 "pct exec 1601 -- curl -k https://dadude.domarc.it:8000/api/v1/health"
```

**3. Verifica certificati mTLS**:

```bash
ssh root@192.168.40.4 "pct exec 1601 -- ls -la /opt/dadude-agent/certs/"
```

**4. Log errori**:

```bash
ssh root@192.168.40.4 "pct exec 1601 -- journalctl -u dadude-agent -p err --no-pager"
```

### Updater non funziona

**1. Verifica repository Git**:

```bash
ssh root@192.168.40.4 "pct exec 1601 -- bash -c 'cd /opt/dadude-agent && git remote -v'"
```

Dovrebbe mostrare: `origin  https://github.com/grandir66/DADude3.git`

**2. Verifica permessi**:

```bash
ssh root@192.168.40.4 "pct exec 1601 -- ls -la /opt/dadude-agent/.git"
```

**3. Test updater manualmente**:

```bash
ssh root@192.168.40.4 "pct exec 1601 -- python3 /opt/dadude-updater/updater.py --once"
```

### Versione non aggiornata nel frontend

**1. Verifica versione nel codice**:

```bash
ssh root@192.168.40.4 "pct exec 1601 -- bash -c 'source /opt/dadude-agent/venv/bin/activate && cd /opt/dadude-agent && python3 -c \"from app.agent import AGENT_VERSION; print(AGENT_VERSION)\"'"
```

**2. Riavvia agent** (per inviare nuova versione al server):

```bash
ssh root@192.168.40.4 "pct exec 1601 -- systemctl restart dadude-agent"
```

**3. Verifica nel log che la versione sia corretta**:

```bash
ssh root@192.168.40.4 "pct exec 1601 -- journalctl -u dadude-agent --no-pager | grep -i version"
```

## Comandi Rapidi

### Riepilogo Stato Completo

```bash
CTID=1601
PROXMOX_HOST=192.168.40.4

echo "=== Container Status ==="
ssh root@${PROXMOX_HOST} "pct status ${CTID}"

echo ""
echo "=== Services Status ==="
ssh root@${PROXMOX_HOST} "pct exec ${CTID} -- systemctl status dadude-agent dadude-updater --no-pager"

echo ""
echo "=== Agent Version ==="
ssh root@${PROXMOX_HOST} "pct exec ${CTID} -- cat /opt/dadude-agent/VERSION"

echo ""
echo "=== Last Agent Logs ==="
ssh root@${PROXMOX_HOST} "pct exec ${CTID} -- journalctl -u dadude-agent -n 10 --no-pager"

echo ""
echo "=== Last Updater Logs ==="
ssh root@${PROXMOX_HOST} "pct exec ${CTID} -- journalctl -u dadude-updater -n 10 --no-pager"
```

### Backup Configurazione

```bash
CTID=1601
PROXMOX_HOST=192.168.40.4

# Backup .env
ssh root@${PROXMOX_HOST} "pct exec ${CTID} -- cat /opt/dadude-agent/.env" > agent-${CTID}-env-backup.txt

# Backup config updater
ssh root@${PROXMOX_HOST} "pct exec ${CTID} -- cat /opt/dadude-updater/config.env" > updater-${CTID}-config-backup.txt

echo "Backup salvati in:"
ls -lh *-backup.txt
```

### Pulizia Cache Python

```bash
ssh root@192.168.40.4 "pct exec 1601 -- bash -c 'find /opt/dadude-agent -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true && find /opt/dadude-agent -name \"*.pyc\" -delete 2>/dev/null || true'"
```

## Sicurezza

- **mTLS**: Mutual TLS per autenticazione reciproca server-agent
- **Token**: Autenticazione via token segreto
- **Agent-initiated**: L'agent si connette al server (non viceversa)
- **Credenziali**: Mai salvate su disco (solo in memoria durante esecuzione)
- **Offline Mode**: Coda locale persistente quando server irraggiungibile

## Requisiti Sistema

- **OS**: Debian 11/12 o Ubuntu 22.04/24.04
- **RAM**: Minimo 512MB (consigliato 1GB)
- **Disco**: Minimo 4GB
- **Python**: 3.9+
- **Rete**: Connessione HTTPS al server (porta 8000)

## Licenza

MIT
