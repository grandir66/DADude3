#!/bin/bash
# Manual Deployment Commands
# Copy-paste these commands one by one

# ==============================================================================
# STEP 1: Connetti al server e trova il container
# ==============================================================================
ssh root@192.168.40.3
docker ps
# Prendi nota del CONTAINER_ID

# ==============================================================================
# STEP 2: Entra nel container
# ==============================================================================
CONTAINER_ID="<INSERISCI_QUI_IL_CONTAINER_ID>"
docker exec -it $CONTAINER_ID bash

# ==============================================================================
# STEP 3: Backup database (IMPORTANTE!)
# ==============================================================================
cp ./data/dadude.db ./data/dadude.db.backup-$(date +%Y%m%d-%H%M%S)
ls -lh ./data/*.backup-*

# ==============================================================================
# STEP 4: Pull modifiche da Git
# ==============================================================================
cd /app  # o il percorso appropriato
git fetch origin
git pull origin main
git log -1 --oneline  # Verifica commit: deve essere 26643a9

# ==============================================================================
# STEP 5: Verifica file presenti
# ==============================================================================
ls -l app/main.py
ls -l app/routers/device_backup.py
ls -l app/services/backup_scheduler.py
ls -l migrate_backup_tables.py

# ==============================================================================
# STEP 6: Installa dipendenze
# ==============================================================================
pip install apscheduler
# Opzionale per AI validation:
# pip install anthropic

# Verifica
pip list | grep apscheduler

# ==============================================================================
# STEP 7: Esegui migrazione database
# ==============================================================================
python3 migrate_backup_tables.py --seed-templates

# Output atteso:
# ✓ 4 tabelle create
# ✓ 2 template creati

# ==============================================================================
# STEP 8: Verifica import (opzionale ma consigliato)
# ==============================================================================
python3 -c "from app.routers import device_backup; print('✓ Router OK')"
python3 -c "from app.services.backup_scheduler import BackupScheduler; print('✓ Scheduler OK')"

# ==============================================================================
# STEP 9: Esci dal container
# ==============================================================================
exit

# ==============================================================================
# STEP 10: Restart container
# ==============================================================================
docker restart $CONTAINER_ID

# ==============================================================================
# STEP 11: Verifica logs
# ==============================================================================
docker logs -f $CONTAINER_ID --tail 100

# Cerca questi messaggi:
# ✓ "Backup Scheduler started"
# ✓ "WebSocket Hub started"
# ✓ "DaDude - The Dude MikroTik Connector"
# ✗ Nessun errore di import

# CTRL+C per uscire dai logs

# ==============================================================================
# STEP 12: Test API
# ==============================================================================
# Da un altro terminale o browser:
curl http://192.168.40.3:800/api/v1/device-backup/templates

# Oppure apri in browser:
# http://192.168.40.3:800/docs
# Cerca la sezione "Device Backup"

# ==============================================================================
# COMPLETATO! 🎉
# ==============================================================================
