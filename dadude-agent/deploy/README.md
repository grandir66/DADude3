# DaDude Agent - Deployment

## Installazione Rapida su Proxmox VE

### One-liner (SSH su host Proxmox)

```bash
bash <(curl -sSL https://raw.githubusercontent.com/grandir66/dadude/main/dadude-agent/deploy/proxmox/install.sh) \
  --server-url https://dadude.tuodominio.com \
  --agent-token TUO_TOKEN_SEGRETO \
  --agent-name "Agent Sede Milano" \
  --ip 192.168.1.100/24 \
  --gateway 192.168.1.1 \
  --dns-server 192.168.1.1
```

### Opzioni disponibili

| Opzione | Descrizione | Default |
|---------|-------------|---------|
| `--server-url` | URL server DaDude (obbligatorio) | - |
| `--agent-token` | Token autenticazione (obbligatorio) | - |
| `--agent-id` | ID univoco agent | auto-generato |
| `--agent-name` | Nome descrittivo | "DaDude Agent" |
| `--dns-server` | DNS per reverse lookup | 8.8.8.8 |
| `--ctid` | ID container Proxmox | prossimo disponibile |
| `--hostname` | Hostname container | dadude-agent |
| `--ip` | IP statico (es: 192.168.1.100/24) | DHCP |
| `--gateway` | Gateway | - |
| `--bridge` | Bridge Proxmox | vmbr0 |
| `--storage` | Storage Proxmox | local-lvm |
| `--memory` | RAM in MB | 512 |
| `--disk` | Disco in GB | 4 |

### Esempi

**Installazione con DHCP:**
```bash
bash <(curl -sSL https://raw.githubusercontent.com/grandir66/dadude/main/dadude-agent/deploy/proxmox/install.sh) \
  --server-url https://dadude.example.com \
  --agent-token abc123xyz
```

**Installazione con IP statico e DNS personalizzato:**
```bash
bash <(curl -sSL https://raw.githubusercontent.com/grandir66/dadude/main/dadude-agent/deploy/proxmox/install.sh) \
  --server-url https://dadude.example.com \
  --agent-token abc123xyz \
  --agent-name "Agent Filiale Roma" \
  --ip 10.0.0.50/24 \
  --gateway 10.0.0.1 \
  --dns-server 10.0.0.1 \
  --ctid 200 \
  --memory 1024
```

## Cosa viene installato

Lo script crea:

1. **Container LXC Debian 12** con:
   - Docker CE
   - Docker Compose
   - DaDude Agent container

2. **Struttura in `/opt/dadude-agent/`:**
   ```
   /opt/dadude-agent/
   ├── docker-compose.yml
   └── config/
       └── config.json
   ```

3. **Servizio systemd** `dadude-agent.service` per avvio automatico

## Requisiti

- Proxmox VE 7.x o 8.x
- Accesso SSH come root all'host Proxmox
- Connettività internet per download template e pacchetti
- Bridge di rete configurato (default: vmbr0)

## Post-installazione

### 1. Registra l'agent in DaDude

1. Accedi al pannello DaDude
2. Vai su **Clienti** → seleziona cliente → **Sonde**
3. Clicca **Nuova Sonda**
4. Configura:
   - **Tipo Agent**: Docker
   - **Indirizzo**: IP del container
   - **Porta API**: 8080
   - **Token**: stesso token usato nell'installazione
5. Clicca **Crea Sonda**
6. Testa la connessione con il pulsante **Test**

### 2. Verifica funzionamento

```bash
# Dall'host Proxmox
pct exec <CTID> -- docker logs dadude-agent

# Test API
curl http://<AGENT_IP>:8080/health
```

### 3. Aggiorna l'agent

```bash
pct exec <CTID> -- bash -c "cd /opt/dadude-agent && docker compose pull && docker compose up -d"
```

## Troubleshooting

### Container non si avvia

```bash
pct start <CTID>
pct exec <CTID> -- journalctl -u docker
```

### Agent non risponde

```bash
pct exec <CTID> -- docker ps
pct exec <CTID> -- docker logs dadude-agent
```

### Problemi di rete

```bash
pct exec <CTID> -- ip addr
pct exec <CTID> -- ping -c 3 8.8.8.8
```

## Disinstallazione

```bash
# Ferma e rimuovi container
pct stop <CTID>
pct destroy <CTID>
```

## Architettura

```
┌─────────────────────────────────────────────────────────┐
│                    Proxmox VE Host                       │
│  ┌───────────────────────────────────────────────────┐  │
│  │            LXC Container (Debian 12)              │  │
│  │  ┌─────────────────────────────────────────────┐  │  │
│  │  │              Docker Engine                  │  │  │
│  │  │  ┌───────────────────────────────────────┐  │  │  │
│  │  │  │         DaDude Agent Container        │  │  │  │
│  │  │  │                                       │  │  │  │
│  │  │  │  • WMI Probe (Windows)               │  │  │  │
│  │  │  │  • SSH Probe (Linux)                 │  │  │  │
│  │  │  │  • SNMP Probe (Network devices)      │  │  │  │
│  │  │  │  • Port Scanner                      │  │  │  │
│  │  │  │  • DNS Resolver                      │  │  │  │
│  │  │  │                                       │  │  │  │
│  │  │  │  API: http://0.0.0.0:8080            │  │  │  │
│  │  │  └───────────────────────────────────────┘  │  │  │
│  │  └─────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────┘  │
│                          │                               │
│                     vmbr0 (bridge)                       │
└──────────────────────────┼───────────────────────────────┘
                           │
                    ┌──────┴──────┐
                    │ Rete Locale │
                    └─────────────┘
```

