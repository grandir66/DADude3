# Migrazione Container Proxmox 600 - SQLite → PostgreSQL

## Panoramica

Questa guida descrive la migrazione del container DaDude (CTID 600) su Proxmox da SQLite a PostgreSQL.

## Prerequisiti

- Accesso root a Proxmox (192.168.40.1)
- Accesso al container 600
- Backup completo del database SQLite esistente
- Docker e Docker Compose installati nel container

## Procedura

### 1. Preparazione

```bash
# Connetti a Proxmox
ssh root@192.168.40.1

# Entra nel container
pct enter 600
```

### 2. Backup Database SQLite

```bash
# Crea backup
mkdir -p /tmp/dadude-backup-$(date +%Y%m%d)
docker exec dadude cp /app/data/dadude.db /tmp/dadude.db.backup
docker cp dadude:/app/data/dadude.db /tmp/dadude-backup-$(date +%Y%m%d)/dadude.db

# Backup configurazione
docker exec dadude cp /app/data/.env /tmp/.env.backup
docker cp dadude:/app/data/.env /tmp/dadude-backup-$(date +%Y%m%d)/.env
```

### 3. Aggiorna Repository

```bash
# Trova path repository montato
REPO_PATH=$(docker inspect dadude --format '{{range .Mounts}}{{if eq .Destination "/app/repo"}}{{.Source}}{{end}}{{end}}')

# Aggiorna codice
cd "$REPO_PATH"
git pull

# Oppure se il repository è montato da host:
cd /opt/dadude  # o percorso corretto
git pull
```

### 4. Ferma Container Attuale

```bash
docker stop dadude
```

### 5. Configura PostgreSQL

```bash
# Genera password PostgreSQL
export POSTGRES_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
echo "Password PostgreSQL: $POSTGRES_PASSWORD"

# Crea file .env per docker-compose
cat > /tmp/.env.postgres <<EOF
POSTGRES_DB=dadude
POSTGRES_USER=dadude
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
DADUDE_REPO_PATH=/opt/dadude
EOF
```

### 6. Avvia PostgreSQL e Applicazione

```bash
# Vai nella directory del progetto
cd /opt/dadude/dadude  # o percorso corretto

# Carica variabili ambiente
export $(cat /tmp/.env.postgres | xargs)

# Avvia con docker-compose PostgreSQL
docker-compose -f docker-compose-postgres.yml up -d
```

### 7. Verifica PostgreSQL Attivo

```bash
# Attendi che PostgreSQL sia pronto
sleep 10

# Verifica
docker exec dadude-postgres pg_isready -U dadude

# Entra in PostgreSQL
docker exec -it dadude-postgres psql -U dadude -d dadude
```

### 8. Migra Dati SQLite → PostgreSQL

```bash
# Esegui migrazione
docker exec dadude python /app/migrate_sqlite_to_postgres.py \
    --sqlite "sqlite:///./data/dadude.db" \
    --postgres "postgresql+psycopg2://dadude:${POSTGRES_PASSWORD}@postgres:5432/dadude" \
    --force

# Verifica migrazione
docker exec dadude python /app/migrate_sqlite_to_postgres.py \
    --sqlite "sqlite:///./data/dadude.db" \
    --postgres "postgresql+psycopg2://dadude:${POSTGRES_PASSWORD}@postgres:5432/dadude" \
    --verify-only
```

### 9. Verifica Funzionamento

```bash
# Verifica container attivi
docker ps | grep -E "dadude|postgres"

# Verifica API
curl http://localhost:8000/health
curl http://localhost:8001/health

# Verifica log
docker-compose -f docker-compose-postgres.yml logs -f
```

## Script Automatico

Per semplificare, puoi usare lo script automatico:

```bash
# Dal container Proxmox
cd /opt/dadude/dadude
./deploy/proxmox/migrate-to-postgres.sh
```

Lo script esegue automaticamente tutti i passaggi sopra.

## Rollback (se necessario)

Se qualcosa va storto, puoi tornare a SQLite:

```bash
# Ferma container PostgreSQL
docker-compose -f docker-compose-postgres.yml down

# Ripristina backup SQLite
docker cp /tmp/dadude-backup-YYYYMMDD/dadude.db dadude:/app/data/dadude.db

# Avvia con docker-compose originale
docker-compose -f docker-compose-dual.yml up -d
```

## Accesso PostgreSQL

Dopo la migrazione, puoi accedere ai dati direttamente:

```bash
# Entra in PostgreSQL
docker exec -it dadude-postgres psql -U dadude -d dadude

# Query utili
\dt                    # Lista tabelle
\d customers          # Struttura tabella
SELECT COUNT(*) FROM customers;
SELECT COUNT(*) FROM device_assignments;
SELECT COUNT(*) FROM agent_assignments;
```

## Backup PostgreSQL

```bash
# Backup completo
docker exec dadude-postgres pg_dump -U dadude -d dadude | gzip > /tmp/dadude-postgres-$(date +%Y%m%d).sql.gz

# Restore
gunzip -c /tmp/dadude-postgres-YYYYMMDD.sql.gz | docker exec -i dadude-postgres psql -U dadude -d dadude
```

## Troubleshooting

### PostgreSQL non si avvia
```bash
docker logs dadude-postgres
docker exec dadude-postgres pg_isready -U dadude
```

### Errore connessione database
- Verifica che PostgreSQL sia attivo: `docker ps | grep postgres`
- Verifica variabili ambiente: `docker exec dadude env | grep DATABASE_URL`
- Verifica log applicazione: `docker logs dadude`

### Errore migrazione dati
- Verifica che il database SQLite esista: `docker exec dadude ls -la /app/data/dadude.db`
- Verifica permessi: `docker exec dadude-postgres psql -U dadude -d dadude -c "\dt"`
- Esegui migrazione con --force: `--force`

## Note Importanti

1. **Password PostgreSQL**: Salva la password generata in un posto sicuro
2. **Backup**: Mantieni sempre un backup del database SQLite originale
3. **Downtime**: La migrazione richiede qualche minuto di downtime
4. **Volume PostgreSQL**: I dati PostgreSQL sono salvati nel volume `postgres_data`
5. **Compatibilità**: Il codice è retrocompatibile, ma PostgreSQL è ora il default

## Vantaggi PostgreSQL

- ✅ Accesso diretto ai dati via SQL
- ✅ Performance migliori per query complesse
- ✅ Backup/restore più robusti
- ✅ Integrazione con tool esterni
- ✅ Supporto transazioni avanzate

