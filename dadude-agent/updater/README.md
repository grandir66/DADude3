# DaDude Agent Updater

Servizio indipendente per aggiornamento automatico dell'agent via Git.

## Caratteristiche

- **Completamente indipendente dall'agent** - Funziona anche se l'agent è corrotto
- **Auto-riparante** - Può aggiornare anche se stesso
- **Controllo periodico** - Verifica Git ogni ora (configurabile)
- **Rollback automatico** - Torna alla versione precedente se l'update fallisce
- **Health check** - Verifica che l'agent sia connesso dopo l'aggiornamento
- **Bad commits tracking** - Ricorda i commit problematici

## Installazione

### Durante installazione agent

L'updater viene installato automaticamente dallo script `install-native.sh`.

### Installazione manuale

```bash
# Copia file updater
mkdir -p /opt/dadude-updater/logs
cp updater/updater.py /opt/dadude-updater/
cp updater/dadude-updater.service /etc/systemd/system/

# Configurazione
cp updater/config.env.example /opt/dadude-updater/config.env
# Modifica config.env se necessario

# Abilita e avvia
systemctl daemon-reload
systemctl enable dadude-updater.service
systemctl start dadude-updater.service
```

## Configurazione

File: `/opt/dadude-updater/config.env`

```bash
# Directory dell'agent da aggiornare
AGENT_DIR=/opt/dadude-agent

# Directory dell'updater
UPDATER_DIR=/opt/dadude-updater

# Intervallo di controllo in secondi (default: 3600 = 1 ora)
UPDATE_CHECK_INTERVAL=3600

# Timeout per verifica salute agent (default: 120 secondi)
AGENT_HEALTH_TIMEOUT=120

# Remote e branch Git
GIT_REMOTE=origin
GIT_BRANCH=main
```

## Uso

### Controllo manuale

```bash
# Controllo singolo
python3 /opt/dadude-updater/updater.py --once

# Forza aggiornamento
python3 /opt/dadude-updater/updater.py --once --force
```

### Servizio systemd

```bash
# Stato
systemctl status dadude-updater

# Log
journalctl -u dadude-updater -f

# Riavvia
systemctl restart dadude-updater
```

## Struttura Directory

```
/opt/dadude-updater/
├── updater.py          # Script principale
├── config.env          # Configurazione
├── state.json          # Stato persistente
└── logs/
    └── updater.log     # Log file
```

## Come Funziona

1. **Controllo Git** - Ogni ora fa `git fetch origin main`
2. **Confronto commit** - Confronta commit locale vs remoto
3. **Backup** - Salva file `.env` prima dell'update
4. **Git reset** - Esegue `git reset --hard origin/main`
5. **Ripristino** - Ripristina file `.env`
6. **Riavvio agent** - Riavvia il servizio systemd
7. **Health check** - Verifica connessione WebSocket
8. **Rollback** - Se fallisce, torna alla versione precedente

## Troubleshooting

### Updater non trova il repository Git

Verifica che `/opt/dadude-agent/.git` esista:

```bash
ls -la /opt/dadude-agent/.git
```

Se non esiste, inizializza:

```bash
cd /opt/dadude-agent
git init
git remote add origin https://github.com/grandir66/DADude3.git
git fetch origin main
git checkout -b main origin/main
```

### Updater non riavvia l'agent

Verifica che il servizio systemd esista:

```bash
systemctl status dadude-agent
```

Se non esiste, installalo:

```bash
cp /opt/dadude-agent/dadude-agent.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable dadude-agent
```

### Log per debug

```bash
# Log updater
journalctl -u dadude-updater -n 100

# Log file
tail -f /opt/dadude-updater/logs/updater.log
```
