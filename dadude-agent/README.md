# DaDude Agent

Agent Docker per scansioni di rete remote, progettato per essere deployato su MikroTik RouterOS 7 (container) o qualsiasi host Docker nella rete del cliente.

## Funzionalità

- **WMI Probe**: Scansione dispositivi Windows (CPU, RAM, disco, OS, seriale)
- **SSH Probe**: Scansione dispositivi Linux/Unix
- **SNMP Probe**: Scansione dispositivi di rete (switch, router, AP, NAS)
- **Port Scan**: Scansione porte TCP/UDP
- **Reverse DNS**: Risoluzione nomi tramite DNS locale
- **Ping Check**: Verifica raggiungibilità host

## Architettura

```
┌─────────────────┐         ┌──────────────────┐
│  DaDude Server  │◄───────►│  DaDude Agent    │
│  (Central)      │  HTTPS  │  (Docker/MikroTik)│
└─────────────────┘         └──────────────────┘
                                    │
                                    ▼
                            ┌───────────────┐
                            │ Rete Cliente  │
                            │ - Windows     │
                            │ - Linux       │
                            │ - Switch/AP   │
                            └───────────────┘
```

## Requisiti MikroTik

- RouterOS 7.x con supporto Container
- Almeno 256MB RAM libera
- Storage per immagine Docker (~100MB)

## Installazione su MikroTik RouterOS

**⚠️ IMPORTANTE**: L'agent ora usa **WebSocket mTLS** invece di API REST. La configurazione è cambiata.

### Guida Completa

Vedi la guida completa in: **[docs/deployment/MIKROTIK_CONTAINER_SETUP.md](../docs/deployment/MIKROTIK_CONTAINER_SETUP.md)**

### Quick Start

1. **Abilita Container Support**:
   ```routeros
   /system/device-mode/update container=yes
   ```
   Riavvia il router.

2. **Configura Variabili d'Ambiente**:
   ```routeros
   /container/envs/add list=dadude-env key=DADUDE_SERVER_URL value=http://dadude.domarc.it:8000
   /container/envs/add list=dadude-env key=DADUDE_AGENT_ID value=agent-NOME-ROUTER
   /container/envs/add list=dadude-env key=DADUDE_AGENT_NAME value=NOME-ROUTER
   /container/envs/add list=dadude-env key=DADUDE_AGENT_TOKEN value=TOKEN-SICURO
   /container/envs/add list=dadude-env key=DADUDE_CONNECTION_MODE value=websocket
   ```

3. **Esegui Script Installazione**:
   Usa lo script `mikrotik-install.rsc` incluso nel repository.

Per dettagli completi, vedi la [guida completa MikroTik](../docs/deployment/MIKROTIK_CONTAINER_SETUP.md).

## Installazione Docker Standalone

```bash
docker run -d \
  --name dadude-agent \
  --network host \
  -e DADUDE_SERVER_URL=https://your-server.com \
  -e DADUDE_AGENT_TOKEN=your-token \
  -e DADUDE_AGENT_ID=agent-001 \
  ghcr.io/dadude/agent:latest
```

## Architettura WebSocket

L'agent ora usa **WebSocket mTLS** per comunicare con il server (agent-initiated):

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

Per dettagli, vedi `dadude-agent/app/commands/handler.py`.

## Sicurezza

- **mTLS**: Mutual TLS per autenticazione reciproca server-agent
- **Token**: Autenticazione via token segreto
- **Agent-initiated**: L'agent si connette al server (non viceversa)
- **Credenziali**: Mai salvate su disco (solo in memoria durante esecuzione)
- **Offline Mode**: Coda locale persistente quando server irraggiungibile

## Build

```bash
cd dadude-agent
docker build -t dadude-agent .
```

## Licenza

MIT

