# 🐳 Deployment Device Backup Module su Docker (Proxmox CT 800)

**Server:** 192.168.40.3
**Container:** Docker CT/VM ID 800
**Porta:** 800
**Branch:** main
**Commit:** `0ae6936` - "feat: Integrate Device Backup Module"

---

## 📋 Checklist Pre-Deployment

- [x] Commit locale creato
- [x] Push su repository Git remoto (https://github.com/grandir66/Dadude.git)
- [ ] Backup database esistente sul server
- [ ] Pull modifiche nel container
- [ ] Installazione dipendenza `apscheduler`
- [ ] Esecuzione migrazione database
- [ ] Restart container
- [ ] Verifica funzionamento

---

## 🚀 Procedura di Deployment

### Step 1: Connessione al Server Proxmox

```bash
ssh root@192.168.40.3
```

### Step 2: Identificare il Container Docker

```bash
# Se è un container LXC
pct list | grep 800
pct enter 800

# Se è una VM, connettiti e poi:
docker ps
docker ps -a | grep -i dadude
# Prendi nota del CONTAINER_ID
```

### Step 3: Backup Database Esistente (IMPORTANTE!)

```bash
# Entra nel container
docker exec -it <CONTAINER_ID> bash

# Oppure se sei in LXC:
cd /path/to/dadude

# Backup del database
cp ./data/dadude.db ./data/dadude.db.backup-$(date +%Y%m%d-%H%M%S)

# Verifica backup creato
ls -lh ./data/*.backup-*
```

### Step 4: Pull delle Modifiche da Git

```bash
# All'interno del container o nella directory montata
cd /app  # o percorso appropriato

# Pull delle modifiche
git fetch origin
git pull origin main

# Verifica commit corrente
git log -1 --oneline
# Dovrebbe mostrare: 0ae6936 feat: Integrate Device Backup Module

# Verifica file modificati
ls -l app/main_dual.py app/routers/device_backup.py app/services/backup_scheduler.py
```

### Step 5: Installazione Dipendenze

```bash
# Installa APScheduler (richiesto)
pip install apscheduler

# Opzionale: Installa Anthropic per AI validation
pip install anthropic

# Verifica installazione
pip list | grep -E "apscheduler|anthropic"
```

### Step 6: Esecuzione Migrazione Database

```bash
# Esegui lo script di migrazione
python3 migrate_backup_tables.py --seed-templates

# Output atteso:
# ✅ 4 tabelle create: device_backups, backup_schedules, backup_jobs, backup_templates
# ✅ 2 template default creati: HP/Aruba, MikroTik

# Verifica tabelle create
python3 -c "
from sqlalchemy import create_engine, inspect
engine = create_engine('sqlite:///./data/dadude.db')
inspector = inspect(engine)
backup_tables = [t for t in inspector.get_table_names() if 'backup' in t]
print('Tabelle backup:', backup_tables)
"
```

### Step 7: Verifica Sintassi (Opzionale ma Consigliato)

```bash
# Test import moduli
python3 -c "from app.routers import device_backup; print('✓ Router OK')"
python3 -c "from app.services.backup_scheduler import BackupScheduler; print('✓ Scheduler OK')"
python3 -c "from app.main import app; print('✓ App OK')"
```

### Step 8: Restart Container/Applicazione

```bash
# Esci dal container
exit

# Restart del container Docker
docker restart <CONTAINER_ID>

# Oppure se usi docker-compose
docker-compose restart

# Oppure se è systemd service dentro LXC
systemctl restart dadude
```

### Step 9: Verifica Logs Startup

```bash
# Visualizza logs del container
docker logs -f <CONTAINER_ID> --tail 100

# Cerca questi messaggi chiave:
# ✅ "Backup Scheduler started"
# ✅ "WebSocket Hub started"
# ✅ "DaDude - The Dude MikroTik Connector"
# ✅ Nessun errore di import

# Se vedi errori, controlla:
# - Dipendenze installate
# - File presenti
# - Permessi file
```

### Step 10: Test Funzionalità API

```bash
# Test endpoint health
curl http://192.168.40.3:800/health

# Test endpoint backup templates (no auth required per testing)
curl http://192.168.40.3:800/api/v1/device-backup/templates

# Output atteso:
# [
#   {
#     "name": "HP ProCurve / Aruba Default",
#     "device_type": "hp_aruba",
#     "vendor": "HP/Aruba",
#     ...
#   },
#   {
#     "name": "MikroTik RouterOS Default",
#     "device_type": "mikrotik",
#     "vendor": "MikroTik",
#     ...
#   }
# ]

# Verifica documentazione Swagger
curl http://192.168.40.3:800/docs
# Oppure apri in browser: http://192.168.40.3:800/docs
# Cerca la sezione "Device Backup"
```

---

## 🔍 Verifica Post-Deployment

### Check Database

```bash
docker exec -it <CONTAINER_ID> python3 -c "
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import sys
sys.path.insert(0, '.')
from app.models.backup_models import BackupTemplate

engine = create_engine('sqlite:///./data/dadude.db')
Session = sessionmaker(bind=engine)
session = Session()

templates = session.query(BackupTemplate).all()
print(f'✓ Template creati: {len(templates)}')
for t in templates:
    print(f'  - {t.name} ({t.device_type})')
session.close()
"
```

### Check API Routes

```bash
docker exec -it <CONTAINER_ID> python3 -c "
from app.routers import device_backup
print(f'✓ Router loaded with {len(device_backup.router.routes)} routes')
print(f'✓ Prefix: {device_backup.router.prefix}')
"
```

### Check Scheduler

```bash
# Nei logs cerca:
docker logs <CONTAINER_ID> 2>&1 | grep -i "backup scheduler"
# Dovrebbe mostrare: "Backup Scheduler started"
```

---

## 🧪 Test Funzionale Completo

### Test 1: Backup Manuale HP/Aruba Switch

```bash
curl -X POST http://192.168.40.3:800/api/v1/device-backup/device \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "device_ip": "192.168.1.10",
    "device_type": "hp_aruba",
    "backup_type": "config",
    "customer_id": "CUSTOMER_ID"
  }'
```

### Test 2: Backup Manuale MikroTik Router

```bash
curl -X POST http://192.168.40.3:800/api/v1/device-backup/device \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "device_ip": "192.168.1.1",
    "device_type": "mikrotik",
    "backup_type": "both",
    "customer_id": "CUSTOMER_ID"
  }'
```

### Test 3: Lista Storico Backup

```bash
curl -X GET http://192.168.40.3:800/api/v1/device-backup/history/customer/{customer_id} \
  -H "X-API-Key: YOUR_API_KEY"
```

### Test 4: Crea Schedule Automatico

```bash
curl -X POST http://192.168.40.3:800/api/v1/device-backup/schedule \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "customer_id": "CUSTOMER_ID",
    "enabled": true,
    "schedule_type": "daily",
    "schedule_time": "03:00",
    "retention_days": 30,
    "backup_types": ["config"]
  }'
```

---

## 📁 Verifica File Backup Creati

```bash
# Entra nel container
docker exec -it <CONTAINER_ID> bash

# Controlla directory backups
ls -lah ./data/backups/

# Dovrebbe mostrare struttura:
# ./data/backups/
#   └── {CUSTOMER_CODE}/
#       └── {DEVICE_HOSTNAME}/
#           └── config/
#               └── YYYY-MM-DD_HH-MM-SS_config.txt
```

---

## ⚠️ Troubleshooting

### Problema: "Module 'device_backup' not found"

```bash
# Verifica file presente
docker exec -it <CONTAINER_ID> ls -l /app/app/routers/device_backup.py

# Se manca, verifica git pull
docker exec -it <CONTAINER_ID> bash -c "cd /app && git status"
```

### Problema: "No module named 'apscheduler'"

```bash
# Installa dipendenza
docker exec -it <CONTAINER_ID> pip install apscheduler

# Restart container
docker restart <CONTAINER_ID>
```

### Problema: "Table 'device_backups' doesn't exist"

```bash
# Esegui migrazione
docker exec -it <CONTAINER_ID> python3 migrate_backup_tables.py --seed-templates
```

### Problema: "Backup Scheduler not started"

```bash
# Verifica logs dettagliati
docker logs <CONTAINER_ID> 2>&1 | grep -A5 "Backup Scheduler"

# Possibili cause:
# 1. apscheduler non installato
# 2. Errore import moduli
# 3. Errore database connection
```

### Problema: Container non si riavvia

```bash
# Check logs errori
docker logs <CONTAINER_ID>

# Ripristina backup se necessario
docker exec -it <CONTAINER_ID> bash
cp ./data/dadude.db.backup-XXXXXX ./data/dadude.db

# Verifica sintassi Python
python3 -m py_compile app/main_dual.py
```

---

## 🔄 Rollback (Se Necessario)

### Rollback Git

```bash
# Entra nel container
docker exec -it <CONTAINER_ID> bash
cd /app

# Torna al commit precedente
git log --oneline -5
git checkout <PREVIOUS_COMMIT_HASH>

# Restart
exit
docker restart <CONTAINER_ID>
```

### Rollback Database

```bash
# Ripristina backup database
docker exec -it <CONTAINER_ID> bash
cd /data
cp dadude.db.backup-YYYYMMDD-HHMMSS dadude.db

# Drop tabelle backup (opzionale)
python3 -c "
from sqlalchemy import create_engine, MetaData
engine = create_engine('sqlite:///./data/dadude.db')
metadata = MetaData()
metadata.reflect(bind=engine)
for table in ['device_backups', 'backup_schedules', 'backup_jobs', 'backup_templates']:
    if table in metadata.tables:
        metadata.tables[table].drop(engine)
        print(f'Dropped {table}')
"
```

---

## 📊 Monitoring Post-Deployment

### Verifica Giornaliera (primi 7 giorni)

```bash
# Check logs errori
docker logs <CONTAINER_ID> --since 24h 2>&1 | grep -i error

# Check backup eseguiti
docker exec -it <CONTAINER_ID> python3 -c "
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import sys
sys.path.insert(0, '.')
from app.models.backup_models import DeviceBackup
from datetime import datetime, timedelta

engine = create_engine('sqlite:///./data/dadude.db')
Session = sessionmaker(bind=engine)
session = Session()

yesterday = datetime.now() - timedelta(days=1)
recent = session.query(DeviceBackup).filter(DeviceBackup.created_at >= yesterday).count()
print(f'Backup eseguiti ultime 24h: {recent}')
session.close()
"

# Check spazio disco
docker exec -it <CONTAINER_ID> du -sh ./data/backups/
```

---

## ✅ Deployment Completato

Una volta completati tutti gli step e verificato il funzionamento:

- [x] Git pull completato
- [x] Dipendenze installate
- [x] Migrazione database eseguita
- [x] Container riavviato
- [x] Logs verificati (no errori)
- [x] API endpoints funzionanti
- [x] Template caricati
- [x] Test backup manuale eseguito
- [x] Schedule configurato (opzionale)

**Il Device Backup Module è ora LIVE su produzione!** 🎉

---

## 📞 Contatti

Per supporto o problemi:
- Verifica documentazione: `INTEGRATION_COMPLETE.md`
- Controlla logs: `docker logs <CONTAINER_ID>`
- API docs: http://192.168.40.3:800/docs

---

*Deployment guide - Device Backup Module v1.0*
*Last updated: 16 Dicembre 2025*
