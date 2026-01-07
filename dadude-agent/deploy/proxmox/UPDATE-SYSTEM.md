# Sistema di Update Agent DaDude

## Panoramica

Il sistema di update degli agent è stato completamente rifatto per essere più robusto e affidabile. Il nuovo sistema utilizza uno script esterno che viene eseguito FUORI dal container Docker per evitare problemi di mount e permessi.

## Architettura

```
┌─────────────────┐
│  DaDude Server  │
│  (WebSocket)    │
└────────┬────────┘
         │ Comando UPDATE_AGENT
         ▼
┌─────────────────┐
│  Agent Container│
│  (riceve cmd)   │
└────────┬────────┘
         │ Esegue script esterno
         ▼
┌─────────────────┐
│ update-agent.sh │
│ (fuori Docker)  │
└─────────────────┘
```

## Componenti

### 1. Script di Update (`update-agent.sh`)

Script bash robusto che:
- Esegue FUORI dal container Docker
- Preserva sempre il file `.env`
- Gestisce errori in modo affidabile
- Verifica ogni step prima di procedere
- Ripristina automaticamente in caso di errore

**Posizione**: `/opt/dadude-agent/dadude-agent/deploy/proxmox/update-agent.sh`

**Uso manuale**:
```bash
# Sul server Proxmox
bash /opt/dadude-agent/dadude-agent/deploy/proxmox/update-agent.sh <container_id>
```

### 2. Handler Update nell'Agent (`handler.py`)

L'handler nell'agent:
1. Prova prima a eseguire lo script esterno (se disponibile)
2. Se non disponibile, usa il metodo interno migliorato
3. Gestisce errori e ripristina `.env` automaticamente

## Processo di Update

### Step 1: Backup `.env`
- Backup del file `.env` principale (`/opt/dadude-agent/.env`)
- Backup del file `.env` subdirectory (`/opt/dadude-agent/dadude-agent/.env`)

### Step 2: Verifica Repository Git
- Verifica che `/opt/dadude-agent/.git` esista
- Se non esiste, prova a inizializzarlo

### Step 3: Fetch Aggiornamenti
- `git fetch origin main`
- Verifica errori di rete

### Step 4: Verifica Aggiornamenti Disponibili
- Confronta commit corrente con `origin/main`
- Se già aggiornato, termina

### Step 5: Stop Container
- Arresta il container Docker prima del reset

### Step 6: Reset Git
- `git reset --hard origin/main`
- Preserva file locali importanti

### Step 7: Ripristina `.env`
- Ripristina entrambi i file `.env` dopo il reset
- Assicura che esistano in entrambe le posizioni

### Step 8: Verifica Struttura Directory
- Verifica che `dadude-agent/` esista
- Crea se necessario

### Step 9: Verifica `docker-compose.yml`
- Verifica che esista e sia corretto
- Crea se necessario con configurazione corretta

### Step 10: Build Immagine Docker
- `docker compose build --quiet`
- Verifica errori di build

### Step 11: Avvia Container
- `docker compose up -d`
- Verifica avvio corretto

### Step 12: Verifica Stato
- Controlla che il container sia in esecuzione
- Verifica healthcheck

## Gestione Errori

Il sistema gestisce automaticamente:
- **Git fetch fallito**: Ripristina `.env` e termina
- **Git reset fallito**: Ripristina `.env` e termina
- **Docker build fallito**: Ripristina `.env` e termina
- **Container non avviato**: Mostra stato e suggerimenti

## Preservazione File `.env`

Il file `.env` viene SEMPRE preservato:
1. Backup prima di qualsiasi operazione git
2. Ripristino dopo ogni operazione git
3. Copia automatica in entrambe le posizioni necessarie

## Configurazione Docker Compose

Il `docker-compose.yml` deve montare correttamente:
```yaml
volumes:
  - ../:/opt/dadude-agent  # Monta directory parent con .git
```

Questo permette al container di accedere al repository git.

## Troubleshooting

### Errore: "Agent directory is not a git repository"
- Verifica che `/opt/dadude-agent/.git` esista
- Se non esiste, esegui manualmente:
  ```bash
  cd /opt/dadude-agent
  git init
  git remote add origin https://github.com/grandir66/Dadude.git
  git fetch origin main
  git reset --hard origin/main
  ```

### Errore: "File .env not found"
- Verifica che il file `.env` esista in `/opt/dadude-agent/.env`
- Se non esiste, usa lo script `regenerate-env.sh` per crearlo

### Container non si avvia dopo update
- Verifica i log: `docker logs dadude-agent`
- Verifica che il file `.env` esista in `dadude-agent/.env`
- Verifica che `docker-compose.yml` sia corretto

## Update Manuale

Se l'update automatico fallisce, puoi eseguirlo manualmente:

```bash
# Sul server Proxmox
pct exec <container_id> -- bash /opt/dadude-agent/dadude-agent/deploy/proxmox/update-agent.sh <container_id>
```

Oppure passo per passo:

```bash
# 1. Backup .env
pct exec <container_id> -- cp /opt/dadude-agent/.env /opt/dadude-agent/.env.backup

# 2. Fetch e reset
pct exec <container_id> -- bash -c "cd /opt/dadude-agent && git fetch origin main && git reset --hard origin/main"

# 3. Ripristina .env
pct exec <container_id> -- cp /opt/dadude-agent/.env.backup /opt/dadude-agent/.env
pct exec <container_id> -- cp /opt/dadude-agent/.env /opt/dadude-agent/dadude-agent/.env

# 4. Rebuild e restart
pct exec <container_id> -- bash -c "cd /opt/dadude-agent/dadude-agent && docker compose build && docker compose up -d"
```

## Best Practices

1. **Sempre backup prima di update**: Il sistema lo fa automaticamente
2. **Verifica connessione**: Assicurati che l'agent sia connesso prima di aggiornare
3. **Monitora i log**: Controlla i log durante l'update
4. **Test in staging**: Prova sempre l'update su un agent di test prima

## Miglioramenti Futuri

- [ ] Update incrementale (solo file modificati)
- [ ] Rollback automatico in caso di errore
- [ ] Notifiche di stato update via WebSocket
- [ ] Update batch per più agent contemporaneamente

