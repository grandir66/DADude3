# DaDude - Installazione con PostgreSQL

## Panoramica

DaDude supporta ora PostgreSQL come database principale, permettendo accesso diretto ai dati per integrazioni e reporting avanzati.

## Opzione 1: Container Docker (Proxmox)

### Prerequisiti
- Docker e Docker Compose installati
- Porte 8000 e 8001 disponibili

### Installazione

1. **Configura variabili ambiente**:
```bash
export POSTGRES_DB=dadude
export POSTGRES_USER=dadude
export POSTGRES_PASSWORD=$(openssl rand -base64 32)
export DADUDE_REPO_PATH=/path/to/Dadude
```

2. **Avvia con docker-compose**:
```bash
cd dadude
docker-compose -f docker-compose-postgres.yml up -d
```

3. **Verifica**:
```bash
docker-compose -f docker-compose-postgres.yml ps
docker-compose -f docker-compose-postgres.yml logs -f
```

### Accesso PostgreSQL

```bash
# Entra nel container PostgreSQL
docker exec -it dadude-postgres psql -U dadude -d dadude

# Oppure da host (se esponi porta):
docker-compose -f docker-compose-postgres.yml exec postgres psql -U dadude -d dadude
```

## Opzione 2: VM Linux

### Installazione automatica

```bash
# Scarica script
curl -sSL https://raw.githubusercontent.com/grandir66/Dadude/main/dadude/deploy/vm-linux/install.sh | sudo bash

# Oppure con parametri personalizzati
export POSTGRES_PASSWORD="mia_password_sicura"
curl -sSL https://raw.githubusercontent.com/grandir66/Dadude/main/dadude/deploy/vm-linux/install.sh | sudo bash
```

### Installazione manuale

1. **Installa dipendenze**:
```bash
# Ubuntu/Debian
apt-get install python3.11 python3.11-venv postgresql postgresql-contrib git

# CentOS/RHEL
yum install python3.11 postgresql-server postgresql-contrib git
```

2. **Configura PostgreSQL**:
```bash
sudo -u postgres psql <<EOF
CREATE USER dadude WITH PASSWORD 'password_sicura';
CREATE DATABASE dadude OWNER dadude;
GRANT ALL PRIVILEGES ON DATABASE dadude TO dadude;
\c dadude
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
EOF
```

3. **Installa applicazione**:
```bash
git clone https://github.com/grandir66/Dadude.git /opt/dadude
cd /opt/dadude/dadude
python3.11 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install psycopg2-binary
```

4. **Configura ambiente**:
```bash
cat > /var/lib/dadude/.env <<EOF
DATABASE_URL=postgresql+psycopg2://dadude:password_sicura@localhost:5432/dadude
DADUDE_HOST=0.0.0.0
DADUDE_AGENT_PORT=8000
DADUDE_ADMIN_PORT=8001
EOF
```

5. **Inizializza database**:
```bash
cd /opt/dadude/dadude
python -c "from app.models.database import init_db; from app.config import Settings; init_db(Settings().database_url)"
```

6. **Crea systemd service** (vedi script install.sh)

## Migrazione dati SQLite → PostgreSQL

Se hai un database SQLite esistente:

### Container
```bash
docker exec -it dadude python migrate_sqlite_to_postgres.py \
    --sqlite sqlite:///./data/dadude.db \
    --postgres postgresql+psycopg2://dadude:password@postgres:5432/dadude
```

### VM Linux
```bash
python /opt/dadude/dadude/migrate_sqlite_to_postgres.py \
    --sqlite sqlite:///./data/dadude.db \
    --postgres postgresql+psycopg2://dadude:password@localhost:5432/dadude
```

## Accesso diretto ai dati PostgreSQL

### Container
```bash
docker exec -it dadude-postgres psql -U dadude -d dadude
```

### VM Linux
```bash
sudo -u postgres psql -d dadude
# oppure
psql -U dadude -d dadude -h localhost
```

### Query utili
```sql
-- Lista tabelle
\dt

-- Conta record per tabella
SELECT 'customers' as table, COUNT(*) FROM customers
UNION ALL SELECT 'devices', COUNT(*) FROM device_assignments
UNION ALL SELECT 'agents', COUNT(*) FROM agent_assignments;

-- Backup
pg_dump -U dadude -d dadude > backup.sql

-- Restore
psql -U dadude -d dadude < backup.sql

-- Verifica connessioni attive
SELECT * FROM pg_stat_activity WHERE datname = 'dadude';

-- Dimensioni tabelle
SELECT 
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
```

## Troubleshooting

### PostgreSQL non si avvia
```bash
# Verifica log
journalctl -u postgresql -f  # VM Linux
docker logs dadude-postgres   # Container
```

### Connessione rifiutata
- Verifica che PostgreSQL sia in ascolto: `netstat -tlnp | grep 5432`
- Verifica `pg_hba.conf` per permessi connessione
- Verifica firewall

### Errori migrazione
- Verifica che PostgreSQL sia vuoto o usa `--force`
- Controlla log per dettagli errori
- Verifica che tutte le dipendenze siano installate

### Verifica migrazione
```bash
python migrate_sqlite_to_postgres.py \
    --sqlite sqlite:///./data/dadude.db \
    --postgres postgresql+psycopg2://dadude:password@localhost:5432/dadude \
    --verify-only
```

## Configurazione avanzata

### Performance tuning PostgreSQL

Modifica `/etc/postgresql/16/main/postgresql.conf`:
```conf
shared_buffers = 256MB
effective_cache_size = 1GB
maintenance_work_mem = 64MB
checkpoint_completion_target = 0.9
wal_buffers = 16MB
default_statistics_target = 100
random_page_cost = 1.1
effective_io_concurrency = 200
work_mem = 4MB
min_wal_size = 1GB
max_wal_size = 4GB
```

### Backup automatico

Crea `/etc/cron.daily/dadude-backup`:
```bash
#!/bin/bash
BACKUP_DIR="/var/backups/dadude"
mkdir -p "$BACKUP_DIR"
pg_dump -U dadude -d dadude | gzip > "$BACKUP_DIR/dadude-$(date +%Y%m%d).sql.gz"
find "$BACKUP_DIR" -name "*.gz" -mtime +30 -delete
```

## Vantaggi PostgreSQL

- ✅ Accesso diretto ai dati via SQL
- ✅ Performance migliori per query complesse
- ✅ Supporto transazioni avanzate
- ✅ Backup/restore più robusti
- ✅ Integrazione con tool esterni (Grafana, Metabase, etc.)
- ✅ Supporto JSON nativo avanzato
- ✅ Full-text search integrato
- ✅ Replicazione e high availability

