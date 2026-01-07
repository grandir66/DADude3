# Procedura Migrazione Database: Docker → Native PostgreSQL

Questa guida descrive come migrare i dati dal database PostgreSQL containerizzato (Docker) al PostgreSQL nativo.

## Prerequisiti

- Accesso SSH al vecchio server (PCT 600 con Docker)
- Accesso SSH al nuovo server (PCT con PostgreSQL nativo)
- Utente con privilegi sudo su entrambi i sistemi

## Step 1: Backup Database dal Sistema Docker

Sul vecchio server (PCT 600):

```bash
# Entra nel container PostgreSQL
ssh root@192.168.40.1 "pct exec 600 -- docker exec dadude-postgres pg_dump -U dadude -d dadude -F c -f /tmp/dadude_backup.dump"

# Copia il dump fuori dal container
ssh root@192.168.40.1 "pct exec 600 -- docker cp dadude-postgres:/tmp/dadude_backup.dump /tmp/dadude_backup.dump"

# Scarica il dump sul tuo PC
scp root@192.168.40.1:/tmp/dadude_backup.dump ./dadude_backup.dump
```

**Alternativa (se pg_dump non disponibile nel container):**

```bash
# Dump diretto dal container
ssh root@192.168.40.1 "pct exec 600 -- docker exec dadude-postgres pg_dump -U dadude dadude" > dadude_backup.sql
```

## Step 2: Preparazione Nuovo Database

Sul nuovo server (PCT con PostgreSQL nativo):

```bash
# Verifica che PostgreSQL sia in esecuzione
systemctl status postgresql

# Crea utente e database (se non già fatto dallo script install-server-native.sh)
sudo -u postgres psql <<EOF
CREATE USER dadude WITH PASSWORD 'password_sicura';
CREATE DATABASE dadude OWNER dadude;
GRANT ALL PRIVILEGES ON DATABASE dadude TO dadude;
\q
EOF
```

## Step 3: Restore Database

Sul nuovo server:

```bash
# Carica il dump (se formato custom)
pg_restore -U dadude -d dadude -c dadude_backup.dump

# Oppure (se formato SQL)
psql -U dadude -d dadude < dadude_backup.sql
```

**Se il dump è su un altro host:**

```bash
# Trasferisci il dump
scp dadude_backup.sql root@<nuovo_server_ip>:/tmp/

# Sul nuovo server
ssh root@<nuovo_server_ip>
psql -U dadude -d dadude < /tmp/dadude_backup.sql
```

## Step 4: Verifica Restore

```bash
# Connetti al database
psql -U dadude -d dadude

# Verifica tabelle principali
\dt

# Conta record
SELECT COUNT(*) FROM customers;
SELECT COUNT(*) FROM inventory_devices;
SELECT COUNT(*) FROM agents;

# Esci
\q
```

## Step 5: Aggiorna Configurazione Server

Modifica `/opt/dadude-server/dadude-server/data/.env`:

```env
DATABASE_URL=postgresql://dadude:password_sicura@localhost:5432/dadude
```

## Step 6: Riavvia Server

```bash
systemctl restart dadude-server
journalctl -u dadude-server -f
```

## Troubleshooting

### Errore "permission denied"
```bash
# Verifica permessi utente postgres
sudo -u postgres psql -c "\du"
```

### Errore "database does not exist"
```bash
# Crea database manualmente
sudo -u postgres createdb -O dadude dadude
```

### Errore "connection refused"
```bash
# Verifica che PostgreSQL sia in ascolto
sudo netstat -tlnp | grep 5432
# Se non in ascolto, modifica /etc/postgresql/*/main/postgresql.conf
# listen_addresses = 'localhost'
```

## Rollback

Se qualcosa va storto, puoi sempre tornare al sistema Docker:

```bash
# Sul vecchio server
ssh root@192.168.40.1 "pct exec 600 -- docker restart dadude"
```
