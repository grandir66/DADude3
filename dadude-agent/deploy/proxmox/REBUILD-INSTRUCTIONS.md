# Istruzioni per Ricostruire Immagini Docker Agent

## Metodo 1: Script Automatico (Consigliato)

Sul server Proxmox, esegui:

```bash
# Scarica lo script
curl -fsSL https://raw.githubusercontent.com/grandir66/Dadude/main/dadude-agent/deploy/proxmox/rebuild-agent.sh -o rebuild-agent.sh
chmod +x rebuild-agent.sh

# Esegui lo script (sostituisci 901 con l'ID del tuo container)
bash rebuild-agent.sh 901
```

Lo script:
1. Aggiorna il codice da git
2. Pulisce immagini Docker vecchie
3. Ricostruisce l'immagine
4. Riavvia il container
5. Verifica lo stato

## Metodo 2: Comandi Manuali

Se preferisci eseguire i comandi manualmente:

```bash
# 1. Connettiti al container LXC
pct exec <container_id> -- bash

# 2. Vai nella directory agent
cd /opt/dadude-agent

# 3. Aggiorna codice git
git fetch origin main
git reset --hard origin/main

# 4. Vai nella directory docker-compose
cd dadude-agent

# 5. (Opzionale) Pulisci spazio Docker
docker system prune -f --volumes

# 6. Ricostruisci immagine
docker compose build --quiet

# 7. Riavvia container
docker restart dadude-agent

# Oppure usa docker compose per forzare ricreazione
docker compose up -d --force-recreate
```

## Metodo 3: Via SSH Remoto

Se hai accesso SSH al server Proxmox:

```bash
# Dal tuo computer
ssh root@<proxmox_ip> "pct exec <container_id> -- bash -c 'cd /opt/dadude-agent && git pull origin main && cd dadude-agent && docker compose build --quiet && docker restart dadude-agent'"
```

## Verifica

Dopo il rebuild, verifica che tutto funzioni:

```bash
# Controlla stato container
pct exec <container_id> -- docker ps --filter name=dadude-agent

# Controlla log
pct exec <container_id> -- docker logs dadude-agent --tail 50

# Verifica versione
pct exec <container_id> -- docker logs dadude-agent | grep "DaDude Agent"
```

## Troubleshooting

### Errore "no space left on device"
```bash
# Pulisci spazio Docker
pct exec <container_id> -- docker system prune -a -f --volumes
```

### Container non si riavvia
```bash
# Forza ricreazione
pct exec <container_id> -- bash -c "cd /opt/dadude-agent/dadude-agent && docker compose up -d --force-recreate"
```

### Git non aggiornato
```bash
# Verifica commit corrente
pct exec <container_id> -- bash -c "cd /opt/dadude-agent && git log --oneline -1"

# Forza reset
pct exec <container_id> -- bash -c "cd /opt/dadude-agent && git fetch origin main && git reset --hard origin/main"
```

