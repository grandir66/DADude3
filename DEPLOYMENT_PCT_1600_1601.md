# Deployment Guide: PCT 1600 (Server) e PCT 1601 (Agent)

Guida completa per l'installazione del sistema DaDude Native sui nuovi container Proxmox.

## Infrastruttura Target

- **PCT 1600**: Server DaDude (IP temporaneo durante setup, poi 192.168.4.45)
- **PCT 1601**: Agent DaDude (IP temporaneo durante setup)

## Prerequisiti

1. Accesso SSH ai nuovi PCT
2. Accesso SSH al vecchio PCT 600 (per backup database)
3. Repository `dadude-native` disponibile (git clone o trasferimento file)

## Fase 1: Preparazione PCT 1600 (Server)

### 1.1 Verifica Container

```bash
# Verifica che il container esista
ssh root@192.168.40.4 "pct status 1600"

# Se non esiste, crealo (esempio configurazione)
# ssh root@192.168.40.4 "pct create 1600 ..."
```

### 1.2 Configurazione Rete Temporanea

```bash
# Assegna IP temporaneo (es. 192.168.4.100)
ssh root@192.168.40.4 "pct set 1600 --net0 name=eth0,bridge=vmbr0,ip=192.168.4.100/24,gw=192.168.4.1"

# Avvia container
ssh root@192.168.40.4 "pct start 1600"

# Verifica connettività
ssh root@192.168.40.4 "pct exec 1600 -- ping -c 2 8.8.8.8"
```

### 1.3 Trasferimento Codice

**Opzione A: Git Clone (se repository remoto disponibile)**
```bash
ssh root@192.168.40.4 "pct exec 1600 -- bash -c '
apt-get update && apt-get install -y git
cd /opt
git clone <repository-url> dadude-native
'"
```

**Opzione B: Trasferimento File**
```bash
# Dal tuo PC locale
cd /Users/riccardo/Progetti/dadude-native
tar czf dadude-native.tar.gz dadude-server/ install-server-native.sh MIGRATION_DB.md README.md

# Trasferisci sul PCT
scp dadude-native.tar.gz root@192.168.40.4:/tmp/

# Estrai sul PCT
ssh root@192.168.40.4 "pct exec 1600 -- bash -c '
cd /opt
tar xzf /tmp/dadude-native.tar.gz -C /opt
mv dadude-native/dadude-server .
mv dadude-native/install-server-native.sh .
'"
```

### 1.4 Esecuzione Installer

```bash
ssh root@192.168.40.4 "pct exec 1600 -- bash -c '
cd /opt
bash install-server-native.sh
'"
```

### 1.5 Configurazione Database

Dopo l'installazione, modifica la password PostgreSQL:

```bash
ssh root@192.168.40.4 "pct exec 1600 -- bash -c '
# Cambia password PostgreSQL
sudo -u postgres psql <<EOF
ALTER USER dadude WITH PASSWORD '\''password_sicura_qui'\'';
\q
EOF

# Aggiorna .env
sed -i \"s/dadude_temp_password_change_me/password_sicura_qui/g\" /opt/dadude-server/dadude-server/data/.env
'"
```

## Fase 2: Backup e Migrazione Database

### 2.1 Backup dal Vecchio Sistema (PCT 600)

```bash
# Backup database dal container Docker
ssh root@192.168.40.4 "pct exec 600 -- docker exec dadude-postgres pg_dump -U dadude -d dadude -F c -f /tmp/dadude_backup.dump"

# Copia fuori dal container
ssh root@192.168.40.4 "pct exec 600 -- docker cp dadude-postgres:/tmp/dadude_backup.dump /tmp/dadude_backup.dump"

# Trasferisci sul nuovo server
scp root@192.168.40.4:/tmp/dadude_backup.dump /tmp/
scp /tmp/dadude_backup.dump root@192.168.40.4:/tmp/
```

### 2.2 Restore sul Nuovo Sistema (PCT 1600)

```bash
# Trasferisci dump nel container
ssh root@192.168.40.4 "pct exec 1600 -- bash -c '
# Copia dump nel container (se necessario)
# pct push 1600 /tmp/dadude_backup.dump /tmp/dadude_backup.dump

# Restore database
pg_restore -U dadude -d dadude -c /tmp/dadude_backup.dump

# Verifica restore
psql -U dadude -d dadude -c \"SELECT COUNT(*) FROM customers;\"
psql -U dadude -d dadude -c \"SELECT COUNT(*) FROM inventory_devices;\"
'"
```

## Fase 3: Avvio e Test Server (PCT 1600)

```bash
# Avvia servizio
ssh root@192.168.40.4 "pct exec 1600 -- systemctl start dadude-server"

# Verifica log
ssh root@192.168.40.4 "pct exec 1600 -- journalctl -u dadude-server -f"

# Test API (da altro host)
curl -k https://192.168.4.100:8000/health
curl -k https://192.168.4.100:8001/health
```

## Fase 4: Preparazione PCT 1601 (Agent)

### 4.1 Configurazione Rete Temporanea

```bash
# Assegna IP temporaneo (es. 192.168.4.101)
ssh root@192.168.40.4 "pct set 1601 --net0 name=eth0,bridge=vmbr0,ip=192.168.4.101/24,gw=192.168.4.1"
ssh root@192.168.40.4 "pct start 1601"
```

### 4.2 Trasferimento Codice

```bash
# Stesso processo del server, ma per dadude-agent
scp dadude-native.tar.gz root@192.168.40.4:/tmp/
ssh root@192.168.40.4 "pct exec 1601 -- bash -c '
cd /opt
tar xzf /tmp/dadude-native.tar.gz -C /opt
mv dadude-native/dadude-agent .
mv dadude-native/install-agent-native.sh .
'"
```

### 4.3 Esecuzione Installer

```bash
ssh root@192.168.40.4 "pct exec 1601 -- bash -c '
cd /opt
bash install-agent-native.sh
'"
```

Durante l'installazione, inserisci:
- **Server URL**: `https://192.168.4.100:8000` (IP temporaneo del server)
- **Agent Name**: `Native-Agent-1601`
- **Agent Token**: (genera dal server o usa token esistente)

### 4.4 Avvio e Test Agent

```bash
# Avvia servizio
ssh root@192.168.40.4 "pct exec 1601 -- systemctl start dadude-agent"

# Verifica log
ssh root@192.168.40.4 "pct exec 1601 -- journalctl -u dadude-agent -f"

# Verifica connessione sul server
ssh root@192.168.40.4 "pct exec 1600 -- journalctl -u dadude-server | grep -i connected"
```

## Fase 5: Cutover - Swap IP (DOWNTIME)

### 5.1 Stop Vecchio Sistema

```bash
# Stop vecchio server Docker
ssh root@192.168.40.4 "pct exec 600 -- docker stop dadude"
```

### 5.2 Cambio IP PCT 1600

```bash
# Ferma container
ssh root@192.168.40.4 "pct stop 1600"

# Cambia IP a 192.168.4.45
ssh root@192.168.40.4 "pct set 1600 --net0 name=eth0,bridge=vmbr0,ip=192.168.4.45/24,gw=192.168.4.1"

# Riavvia
ssh root@192.168.40.4 "pct start 1600"

# Verifica IP
ssh root@192.168.40.4 "pct exec 1600 -- ip addr show eth0"
```

### 5.3 Aggiorna Configurazione Agent (PCT 1601)

```bash
# Aggiorna URL server nel .env
ssh root@192.168.40.4 "pct exec 1601 -- bash -c '
sed -i \"s|192.168.4.100|192.168.4.45|g\" /opt/dadude-agent/dadude-agent/.env
systemctl restart dadude-agent
'"
```

### 5.4 Verifica Riconnessione

```bash
# Verifica che gli agent esistenti si riconnettano
curl -k https://192.168.4.45:8001/api/v1/agents/status

# Verifica log server
ssh root@192.168.40.4 "pct exec 1600 -- journalctl -u dadude-server | tail -20"
```

## Fase 6: Cleanup

Dopo verifica completa:

```bash
# Archivia vecchio PCT 600 (opzionale)
ssh root@192.168.40.4 "pct stop 600"
# ssh root@192.168.40.4 "pct destroy 600"  # ATTENZIONE: Solo se sicuro!
```

## Troubleshooting

### Server non si avvia
```bash
# Verifica log
journalctl -u dadude-server -n 50

# Verifica database
psql -U dadude -d dadude -c "\conninfo"

# Verifica permessi
ls -la /opt/dadude-server/
```

### Agent non si connette
```bash
# Verifica configurazione
cat /opt/dadude-agent/dadude-agent/.env

# Test connettività
curl -k https://192.168.4.45:8000/health

# Verifica certificati (se mTLS)
ls -la /opt/dadude-agent/dadude-agent/data/pki/
```

### Database restore fallisce
```bash
# Verifica formato dump
file /tmp/dadude_backup.dump

# Prova restore SQL invece di custom format
pg_dump -U dadude -d dadude > backup.sql
psql -U dadude -d dadude < backup.sql
```
