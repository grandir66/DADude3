# DaDude Native - v3.1.0

Versione nativa (senza Docker) di DaDude per esecuzione diretta su Proxmox LXC containers.

## Architettura

```
┌─────────────────────────────────────────────────────────────────┐
│                    Proxmox VE (192.168.40.1/4)                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────┐    ┌─────────────────────────┐    │
│  │     PCT 1600            │    │     PCT 1601            │    │
│  │   dadude-server         │    │   dadude-agent          │    │
│  │   IP: 192.168.4.45      │    │   IP: 192.168.4.101     │    │
│  │                         │    │                         │    │
│  │   Port 8000: Agent API  │◄───│   WebSocket Client      │    │
│  │   Port 8001: Admin UI   │    │                         │    │
│  │                         │    │   - Network Scanner     │    │
│  │   - PostgreSQL DB       │    │   - SSH/SNMP/WMI Probes │    │
│  │   - WebSocket Hub       │    │   - Device Discovery    │    │
│  │   - REST API            │    │                         │    │
│  └─────────────────────────┘    └─────────────────────────┘    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Requisiti

- Debian 12 (Bookworm) o Ubuntu 22.04+
- Python 3.11+
- PostgreSQL 15+ (solo server)
- Systemd

## Installazione Rapida

### Server (PCT 1600)

```bash
# Clona repository
git clone https://github.com/grandir66/dadude-native.git /opt/dadude-server

# Esegui installer
cd /opt/dadude-server
chmod +x install-server-native.sh
./install-server-native.sh

# Configura .env
nano /opt/dadude-server/dadude-server/data/.env

# Avvia servizio
systemctl start dadude-server
systemctl enable dadude-server
```

### Agent (PCT 1601)

```bash
# Clona repository
git clone https://github.com/grandir66/dadude-native.git /opt/dadude-agent

# Esegui installer
cd /opt/dadude-agent
chmod +x install-agent-native.sh
./install-agent-native.sh

# Configura .env con URL server
nano /opt/dadude-agent/dadude-agent/.env

# Avvia servizio
systemctl start dadude-agent
systemctl enable dadude-agent
```

## Struttura Repository

```
dadude-native/
├── README.md                      # Questo file
├── QUICK_START.md                 # Guida rapida
├── DEPLOYMENT_PCT_1600_1601.md    # Guida deployment completa
├── MIGRATION_DB.md                # Migrazione database
├── install-server-native.sh       # Script installazione server
├── install-agent-native.sh        # Script installazione agent
├── dadude-server/                 # Codice server
│   ├── app/                       # Applicazione FastAPI
│   ├── data/                      # Directory dati (.env, certs, db)
│   ├── requirements.txt           # Dipendenze Python
│   └── dadude-server.service      # Unit systemd
└── dadude-agent/                  # Codice agent
    ├── app/                       # Applicazione agent
    ├── config/                    # Configurazione
    ├── requirements.txt           # Dipendenze Python
    └── dadude-agent.service       # Unit systemd
```

## Aggiornamento

```bash
# Server
cd /opt/dadude-server
git pull origin main
systemctl restart dadude-server

# Agent
cd /opt/dadude-agent
git pull origin main
systemctl restart dadude-agent
```

## Configurazione

### Server (.env)

```env
DATABASE_URL=postgresql://dadude:password@localhost:5432/dadude
SSL_ENABLED=true
SSL_CERT_PATH=/opt/dadude-server/dadude-server/data/certs/server.crt
SSL_KEY_PATH=/opt/dadude-server/dadude-server/data/certs/server.key
ENCRYPTION_KEY=your-secure-encryption-key
```

### Agent (.env)

```env
DADUDE_SERVER_URL=https://192.168.4.45:8000
AGENT_NAME=Native-Agent-1601
AGENT_ID=agent-native-1601
```

## Porte

| Servizio | Porta | Protocollo | Descrizione |
|----------|-------|------------|-------------|
| Agent API | 8000 | HTTPS | API per agent WebSocket |
| Admin UI | 8001 | HTTPS | Interfaccia web admin |
| PostgreSQL | 5432 | TCP | Database (solo locale) |

## Log e Troubleshooting

```bash
# Log server
journalctl -u dadude-server -f

# Log agent
journalctl -u dadude-agent -f

# Status servizi
systemctl status dadude-server
systemctl status dadude-agent
```

## Differenze da versione Docker

| Aspetto | Docker | Native |
|---------|--------|--------|
| Avvio | `docker-compose up` | `systemctl start` |
| Aggiornamento | `docker pull && restart` | `git pull && restart` |
| Log | `docker logs` | `journalctl` |
| Config | `.env` in root | `.env` in data/ |
| Isolamento | Container | Processo diretto |
| Performance | Overhead container | Nativo |

## Versione

- **Server**: 3.1.0-native
- **Agent**: 3.1.0-native
- **Data**: Gennaio 2026

## Licenza

Proprietario - DOMARC SRL
