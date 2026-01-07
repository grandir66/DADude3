# DaDude Native Architecture

Fork del progetto DaDude ottimizzato per esecuzione nativa su Systemd (NO Docker).

## Architettura

- **Server**: Esecuzione diretta Python con Systemd su Debian/Ubuntu LXC
- **Agent**: Esecuzione diretta Python con Systemd su Debian/Ubuntu LXC
- **Database**: PostgreSQL nativo (non containerizzato)

## Installazione

### Server

```bash
# Clone repository
git clone <repository-url> /opt/dadude-native
cd /opt/dadude-native

# Esegui installer
bash install-server-native.sh
```

### Agent

```bash
# Clone repository
git clone <repository-url> /opt/dadude-agent-native
cd /opt/dadude-agent-native

# Esegui installer
bash install-agent-native.sh
```

## Migrazione da Docker

Vedi [MIGRATION_DB.md](MIGRATION_DB.md) per la procedura completa di migrazione dei dati.

## Gestione Servizi

### Server

```bash
# Avvia
systemctl start dadude-server

# Ferma
systemctl stop dadude-server

# Riavvia
systemctl restart dadude-server

# Log
journalctl -u dadude-server -f

# Status
systemctl status dadude-server
```

### Agent

```bash
# Avvia
systemctl start dadude-agent

# Ferma
systemctl stop dadude-agent

# Riavvia
systemctl restart dadude-agent

# Log
journalctl -u dadude-agent -f

# Status
systemctl status dadude-agent
```

## Aggiornamento

```bash
# Server
cd /opt/dadude-server
git pull
systemctl restart dadude-server

# Agent
cd /opt/dadude-agent
git pull
systemctl restart dadude-agent
```

## Configurazione

- Server: `/opt/dadude-server/dadude-server/data/.env`
- Agent: `/opt/dadude-agent/dadude-agent/.env`

## Vantaggi Architettura Nativa

- ✅ Nessun overhead Docker
- ✅ Gestione semplificata con Systemd
- ✅ Log centralizzati con journalctl
- ✅ Debug più semplice (processi diretti)
- ✅ Nessun problema di mount/volume
- ✅ Aggiornamenti più rapidi (git pull + restart)
