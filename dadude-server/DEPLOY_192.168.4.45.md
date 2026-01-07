# 🐳 Deploy su Docker Server 192.168.4.45

**Server Docker:** 192.168.4.45
**Porta Admin (HTTPS):** 8001
**Porta Agenti:** 8000
**Repository:** https://github.com/grandir66/Dadude.git

---

## 🚀 Procedura Deploy Rapida

### Step 1: Connetti al Server Docker

```bash
ssh root@192.168.4.45
```

### Step 2: Trova il Container DaDude

```bash
docker ps
```

Output esempio:
```
CONTAINER ID   IMAGE          PORTS                    NAMES
abc123def456   dadude:latest  0.0.0.0:8000-8001->...  dadude
```

**Prendi nota del CONTAINER_ID** (es: `abc123def456`)

### Step 3A: Deploy Automatico (CONSIGLIATO)

Dalla tua macchina locale:

```bash
cd /Users/riccardo/Progetti/DATIA-inventtory/dadude
./quick-deploy.sh <CONTAINER_ID> 192.168.4.45
```

Esempio:
```bash
./quick-deploy.sh abc123def456 192.168.4.45
```

Lo script eseguirà automaticamente:
- ✅ Backup database
- ✅ Git pull da GitHub
- ✅ Verifica file presenti
- ✅ Installazione apscheduler
- ✅ Migrazione database
- ✅ Verifica import Python
- ✅ Restart container
- ✅ Verifica startup logs

### Step 3B: Deploy Manuale

Se preferisci fare tutto manualmente:

```bash
# 1. Sei già connesso al server
ssh root@192.168.4.45

# 2. Entra nel container
CONTAINER_ID="<IL_TUO_CONTAINER_ID>"
docker exec -it $CONTAINER_ID bash

# 3. IMPORTANTE: Backup database
cp ./data/dadude.db ./data/dadude.db.backup-$(date +%Y%m%d-%H%M%S)
ls -lh ./data/*.backup-*

# 4. Vai nella directory app e pull da Git
cd /app
git fetch origin
git pull origin main

# 5. Verifica commit corrente
git log -1 --oneline
# Deve mostrare: 26643a9 docs: Add deployment readiness checklist

# 6. Verifica file presenti
ls -l app/main_dual.py
ls -l app/routers/device_backup.py
ls -l app/services/backup_scheduler.py
ls -l app/models/backup_models.py
ls -l migrate_backup_tables.py

# 7. Installa dipendenza richiesta
pip install apscheduler

# 8. (Opzionale) Installa Anthropic per AI validation
pip install anthropic

# 9. Esegui migrazione database
python3 migrate_backup_tables.py --seed-templates

# 10. Verifica import (opzionale)
python3 -c "from app.routers import device_backup; print('✓ Router OK')"
python3 -c "from app.services.backup_scheduler import BackupScheduler; print('✓ Scheduler OK')"

# 11. Esci dal container
exit

# 12. Restart container
docker restart $CONTAINER_ID

# 13. Verifica logs startup
docker logs -f $CONTAINER_ID --tail 100

# Cerca questi messaggi:
# ✅ "Backup Scheduler started"
# ✅ "WebSocket Hub started"
# ✅ "DaDude - The Dude MikroTik Connector"
# ❌ Nessun errore di import

# CTRL+C per uscire
```

---

## ✅ Verifica Post-Deploy

### Test 1: Health Check

```bash
curl -k https://192.168.4.45:8001/health
```

### Test 2: Verifica Template Backup

```bash
curl -k https://192.168.4.45:8001/api/v1/device-backup/templates
```

Output atteso (JSON):
```json
[
  {
    "id": "...",
    "name": "HP ProCurve / Aruba Default",
    "device_type": "hp_aruba",
    "vendor": "HP/Aruba"
  },
  {
    "id": "...",
    "name": "MikroTik RouterOS Default",
    "device_type": "mikrotik",
    "vendor": "MikroTik"
  }
]
```

### Test 3: Swagger Docs

Apri in browser:
```
https://192.168.4.45:8001/docs
```

Cerca la sezione **"Device Backup"** - dovrebbe mostrare 10 endpoint:
- POST /api/v1/device-backup/device
- POST /api/v1/device-backup/customer
- POST /api/v1/device-backup/schedule
- GET /api/v1/device-backup/templates
- GET /api/v1/device-backup/history/device/{id}
- GET /api/v1/device-backup/history/customer/{id}
- ... e altri

### Test 4: Verifica Database

```bash
ssh root@192.168.4.45
docker exec <CONTAINER_ID> python3 -c "
from sqlalchemy import create_engine, inspect
engine = create_engine('sqlite:///./data/dadude.db')
inspector = inspect(engine)
backup_tables = [t for t in inspector.get_table_names() if 'backup' in t]
print('Tabelle backup:', backup_tables)
"
```

Output atteso:
```
Tabelle backup: ['backup_jobs', 'backup_schedules', 'backup_templates', 'device_backups']
```

### Test 5: Verifica Template nel Database

```bash
docker exec <CONTAINER_ID> python3 -c "
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import sys
sys.path.insert(0, '.')
from app.models.backup_models import BackupTemplate

engine = create_engine('sqlite:///./data/dadude.db')
Session = sessionmaker(bind=engine)
session = Session()

templates = session.query(BackupTemplate).all()
print(f'Template creati: {len(templates)}')
for t in templates:
    print(f'  - {t.name} ({t.device_type}, {t.vendor})')
session.close()
"
```

Output atteso:
```
Template creati: 2
  - HP ProCurve / Aruba Default (hp_aruba, HP/Aruba)
  - MikroTik RouterOS Default (mikrotik, MikroTik)
```

---

## 🧪 Test Funzionale Completo

### Test Backup Manuale HP Switch

```bash
curl -k -X POST https://192.168.4.45:8001/api/v1/device-backup/device \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "device_ip": "192.168.1.10",
    "device_type": "hp_aruba",
    "backup_type": "config",
    "customer_id": "CUSTOMER_ID"
  }'
```

### Test Backup Manuale MikroTik

```bash
curl -k -X POST https://192.168.4.45:8001/api/v1/device-backup/device \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "device_ip": "192.168.1.1",
    "device_type": "mikrotik",
    "backup_type": "both",
    "customer_id": "CUSTOMER_ID"
  }'
```

### Verifica File Backup Creati

```bash
ssh root@192.168.4.45
docker exec <CONTAINER_ID> bash

# Controlla directory backup
ls -lah ./data/backups/

# Struttura attesa:
# ./data/backups/
#   └── {CUSTOMER_CODE}/
#       └── {DEVICE_HOSTNAME}/
#           ├── config/
#           │   └── 2025-12-16_18-30-00_config.txt
#           └── binary/  (solo MikroTik)
#               └── 2025-12-16_18-30-00_backup.backup
```

---

## ⚠️ Troubleshooting

### Problema: Non riesci a connetterti al server

```bash
# Verifica connettività
ping 192.168.4.45

# Verifica SSH
ssh root@192.168.4.45 'echo "Connessione OK"'
```

### Problema: Container non trovato

```bash
ssh root@192.168.4.45
docker ps -a  # Mostra anche container fermati
docker ps | grep -i dadude
```

### Problema: Git pull fallisce

```bash
# Entra nel container
docker exec -it <CONTAINER_ID> bash

# Verifica stato Git
cd /app
git status
git remote -v

# Se necessario, reset forzato
git fetch origin
git reset --hard origin/main
```

### Problema: Modulo non caricato

```bash
# Verifica file presenti
docker exec <CONTAINER_ID> ls -l /app/app/routers/device_backup.py

# Verifica import
docker exec <CONTAINER_ID> python3 -c "from app.routers import device_backup"

# Se fallisce, controlla logs
docker logs <CONTAINER_ID> | grep -i error
```

### Problema: Database migration fallisce

```bash
# Controlla permessi
docker exec <CONTAINER_ID> ls -la ./data/

# Verifica database esistente
docker exec <CONTAINER_ID> ls -la ./data/dadude.db

# Esegui migrazione con verbose
docker exec <CONTAINER_ID> python3 migrate_backup_tables.py --seed-templates
```

---

## 🔄 Rollback (Se Necessario)

### Rollback Database

```bash
ssh root@192.168.4.45
docker exec -it <CONTAINER_ID> bash

# Lista backup disponibili
ls -lh ./data/*.backup-*

# Ripristina backup
cp ./data/dadude.db.backup-YYYYMMDD-HHMMSS ./data/dadude.db

# Restart
exit
docker restart <CONTAINER_ID>
```

### Rollback Git

```bash
docker exec -it <CONTAINER_ID> bash
cd /app

# Torna al commit precedente
git log --oneline -5
git checkout fe34461  # Commit prima dell'integrazione

exit
docker restart <CONTAINER_ID>
```

---

## 📊 Monitoring Post-Deploy

### Check Logs Giornaliero

```bash
# Errori ultime 24h
ssh root@192.168.4.45 \
  'docker logs <CONTAINER_ID> --since 24h 2>&1 | grep -i error'

# Backup eseguiti
ssh root@192.168.4.45 \
  'docker logs <CONTAINER_ID> --since 24h 2>&1 | grep -i backup'
```

### Check Spazio Disco

```bash
ssh root@192.168.4.45
docker exec <CONTAINER_ID> du -sh ./data/backups/
```

### Check Backup Recenti

```bash
docker exec <CONTAINER_ID> python3 -c "
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta
import sys
sys.path.insert(0, '.')
from app.models.backup_models import DeviceBackup

engine = create_engine('sqlite:///./data/dadude.db')
Session = sessionmaker(bind=engine)
session = Session()

yesterday = datetime.now() - timedelta(days=1)
recent = session.query(DeviceBackup).filter(
    DeviceBackup.created_at >= yesterday
).count()

print(f'Backup eseguiti ultime 24h: {recent}')
session.close()
"
```

---

## ✅ Checklist Deploy Completato

- [ ] SSH al server funzionante
- [ ] Container ID identificato
- [ ] Backup database creato
- [ ] Git pull completato (commit: 26643a9)
- [ ] File verificati presenti
- [ ] Dipendenza apscheduler installata
- [ ] Migrazione database eseguita
- [ ] 4 tabelle create
- [ ] 2 template creati
- [ ] Import Python verificato
- [ ] Container riavviato
- [ ] Logs senza errori
- [ ] Endpoint /health risponde
- [ ] Endpoint /templates ritorna 2 template
- [ ] Swagger docs mostra "Device Backup"
- [ ] Test backup manuale eseguito

---

## 🎉 Deploy Completato!

Una volta completati tutti gli step, il Device Backup Module sarà attivo su:

- **Admin API:** https://192.168.4.45:8001/api/v1/device-backup/...
- **Docs:** https://192.168.4.45:8001/docs
- **Agenti:** 192.168.4.45:8000 (porte agenti)

---

*Deploy Guide - Server 192.168.4.45*
*Last updated: 16 Dicembre 2025*
