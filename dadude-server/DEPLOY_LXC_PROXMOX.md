# 🚀 Deploy su Container LXC Proxmox

**Tipo:** LXC Container (non Docker!)
**IP Container:** 192.168.4.45
**Porta Admin (HTTPS):** 8001
**Porta Agenti:** 8000
**Proxmox Host:** 192.168.40.3
**Repository:** https://github.com/grandir66/Dadude.git

---

## 📋 Informazioni Container LXC

I container LXC (Linux Container) su Proxmox sono container di sistema, NON container Docker.
L'applicazione gira direttamente nel container LXC, non dentro Docker.

---

## 🚀 Procedura Deploy

### Step 1: Connetti Direttamente al Container LXC

**Opzione A: Da Proxmox Host**

```bash
# Connetti al Proxmox host
ssh root@192.168.40.3

# Entra nel container LXC (trova il CT ID con pct list)
pct list | grep 192.168.4.45
# Output esempio: 800  running

# Entra nel container
pct enter 800
```

**Opzione B: Direttamente via SSH (se configurato)**

```bash
# Connetti direttamente al container
ssh root@192.168.4.45
```

### Step 2: Backup Database

```bash
# Una volta dentro il container
cd /path/to/dadude  # Trova la directory dell'applicazione

# Backup database
cp ./data/dadude.db ./data/dadude.db.backup-$(date +%Y%m%d-%H%M%S)
ls -lh ./data/*.backup-*
```

### Step 3: Pull Modifiche da Git

```bash
# Verifica directory corrente
pwd
# Dovrebbe essere tipo: /opt/dadude o /root/dadude o simile

# Pull da Git
git fetch origin
git pull origin main

# Verifica commit
git log -1 --oneline
# Deve mostrare: 26643a9 docs: Add deployment readiness checklist
```

### Step 4: Verifica File Presenti

```bash
ls -l app/main_dual.py
ls -l app/routers/device_backup.py
ls -l app/services/backup_scheduler.py
ls -l app/models/backup_models.py
ls -l migrate_backup_tables.py
```

### Step 5: Installa Dipendenze

```bash
# Installa apscheduler (richiesto)
pip3 install apscheduler

# Opzionale: AI validation
pip3 install anthropic

# Verifica
pip3 list | grep apscheduler
```

### Step 6: Esegui Migrazione Database

```bash
python3 migrate_backup_tables.py --seed-templates
```

Output atteso:
```
============================================================
Device Backup Module - Database Migration
============================================================
Database URL: sqlite:///./data/dadude.db

--- Checking existing tables ---
Existing tables in database: 20
  - customers
  - networks
  - credentials
  ...

--- Creating backup tables ---
✓ Created table: device_backups
✓ Created table: backup_schedules
✓ Created table: backup_jobs
✓ Created table: backup_templates

--- Seeding default templates ---
✓ Created HP/Aruba default template
✓ Created MikroTik default template

============================================================
Migration completed successfully!
============================================================
```

### Step 7: Verifica Import Python

```bash
python3 -c "from app.routers import device_backup; print('✓ Router OK')"
python3 -c "from app.services.backup_scheduler import BackupScheduler; print('✓ Scheduler OK')"
```

### Step 8: Restart Applicazione

**Trova come l'applicazione è avviata:**

```bash
# Verifica se c'è systemd service
systemctl list-units | grep -i dadude

# Oppure verifica se c'è screen/tmux
screen -ls
tmux ls

# Oppure verifica processi
ps aux | grep -i uvicorn
ps aux | grep -i python
```

**Restart in base al metodo:**

```bash
# Se systemd service
systemctl restart dadude

# Se screen
screen -r dadude
# CTRL+C per fermare
# Riavvia con: uvicorn app.main:app --host 0.0.0.0 --port 8001
# CTRL+A, D per detach

# Se tmux
tmux attach -t dadude
# CTRL+C per fermare
# Riavvia e detach

# Se diretto
# Trova PID e kill
kill -HUP $(pidof python3)
```

### Step 9: Verifica Logs

```bash
# Verifica logs applicazione (dipende da configurazione)
tail -f /var/log/dadude.log
# oppure
journalctl -u dadude -f
# oppure
tail -f ./logs/dadude.log
```

Cerca questi messaggi:
- ✅ "Backup Scheduler started"
- ✅ "WebSocket Hub started"
- ✅ "DaDude - The Dude MikroTik Connector"

---

## ✅ Verifica Post-Deploy

### Test 1: Health Check

```bash
curl -k https://192.168.4.45:8001/health
```

### Test 2: Template Backup

```bash
curl -k https://192.168.4.45:8001/api/v1/device-backup/templates
```

### Test 3: Swagger Docs

Apri browser:
```
https://192.168.4.45:8001/docs
```

Cerca sezione "Device Backup"

### Test 4: Verifica Database

```bash
python3 -c "
from sqlalchemy import create_engine, inspect
engine = create_engine('sqlite:///./data/dadude.db')
inspector = inspect(engine)
backup_tables = [t for t in inspector.get_table_names() if 'backup' in t]
print('Tabelle backup:', backup_tables)
"
```

---

## 🔍 Trova Directory Applicazione

Se non sai dove si trova l'applicazione:

```bash
# Cerca file dadude
find / -name "dadude.db" 2>/dev/null
find / -name "main_dual.py" -path "*/app/main_dual.py" 2>/dev/null

# Verifica processi in esecuzione
ps aux | grep uvicorn
# Output mostrerà il path completo

# Verifica systemd service
systemctl cat dadude 2>/dev/null
# WorkingDirectory mostrerà il path
```

---

## 📝 Script Deploy Rapido per LXC

Crea questo script sul container:

```bash
cat > /root/deploy-backup-module.sh <<'EOF'
#!/bin/bash
set -e

echo "🚀 Deploy Device Backup Module"
echo "================================"

# Trova directory applicazione
APP_DIR=$(find /opt /root /home -name "dadude.db" -exec dirname {} \; 2>/dev/null | head -1 | xargs dirname)

if [ -z "$APP_DIR" ]; then
    echo "❌ Directory applicazione non trovata"
    exit 1
fi

echo "✓ Directory applicazione: $APP_DIR"
cd $APP_DIR

# Backup database
echo "📦 Backup database..."
cp ./data/dadude.db ./data/dadude.db.backup-$(date +%Y%m%d-%H%M%S)

# Git pull
echo "📥 Git pull..."
git pull origin main

# Installa dipendenze
echo "📦 Installazione dipendenze..."
pip3 install apscheduler -q

# Migrazione
echo "🗄️ Migrazione database..."
python3 migrate_backup_tables.py --seed-templates

# Verifica
echo "✅ Verifica import..."
python3 -c "from app.routers import device_backup; print('✓ Router OK')"

echo ""
echo "🎉 Deploy completato!"
echo "⚠️  IMPORTANTE: Riavvia l'applicazione manualmente"
echo ""
echo "Comandi restart possibili:"
echo "  systemctl restart dadude"
echo "  oppure controlla con: ps aux | grep uvicorn"
EOF

chmod +x /root/deploy-backup-module.sh
```

Poi esegui:
```bash
/root/deploy-backup-module.sh
```

---

## 🔄 Rollback

### Database

```bash
cd /path/to/dadude
ls -lh ./data/*.backup-*
cp ./data/dadude.db.backup-YYYYMMDD-HHMMSS ./data/dadude.db
# Restart applicazione
```

### Git

```bash
cd /path/to/dadude
git log --oneline -5
git checkout fe34461  # Commit prima integrazione
# Restart applicazione
```

---

## ✅ Checklist Deploy Completo

- [ ] Connesso al container LXC (pct enter 800 o ssh)
- [ ] Directory applicazione trovata
- [ ] Backup database creato
- [ ] Git pull completato (commit: 26643a9)
- [ ] File presenti verificati
- [ ] apscheduler installato
- [ ] Migrazione database eseguita
- [ ] Import Python verificato
- [ ] Applicazione riavviata
- [ ] Logs verificati (no errori)
- [ ] /health risponde
- [ ] /templates ritorna 2 template
- [ ] Swagger docs mostra "Device Backup"

---

## 🎯 Prossimi Step

1. **Configura Schedule Automatico**
   ```bash
   curl -k -X POST https://192.168.4.45:8001/api/v1/device-backup/schedule \
     -H "Content-Type: application/json" \
     -H "X-API-Key: YOUR_KEY" \
     -d '{
       "customer_id": "CUSTOMER_ID",
       "enabled": true,
       "schedule_type": "daily",
       "schedule_time": "03:00",
       "retention_days": 30
     }'
   ```

2. **Test Backup Manuale**
   - HP/Aruba switch
   - MikroTik router

3. **Verifica File Backup Creati**
   ```bash
   ls -lah ./data/backups/
   ```

---

*Deploy Guide - LXC Container Proxmox*
*Container IP: 192.168.4.45*
*Last updated: 16 Dicembre 2025*
