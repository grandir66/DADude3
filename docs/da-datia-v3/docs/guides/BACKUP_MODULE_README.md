# 📦 Device Backup Module - Quick Start

**Modulo parallelo per DaDude** - Backup automatico configurazioni switch HP/Aruba e router MikroTik

---

## ✨ Cosa Fa

Questo modulo aggiunge a DaDude:

✅ **Backup automatici** di switch HP/Aruba e router MikroTik
✅ **Scheduling** backup notturni per cliente
✅ **Invio comandi** con backup pre-change
✅ **Validazione AI** comandi (opzionale)
✅ **Storico completo** con download
✅ **API REST** per integrazione UI

**IMPORTANTE**: Questo è un **modulo PARALLELO** - non modifica il codice esistente di DaDude!

---

## 🚀 Installation (5 minuti)

### 1. Install Dependencies
```bash
cd /Users/riccardo/Progetti/DATIA-inventtory/dadude
pip install apscheduler>=3.10.4
pip install anthropic>=0.18.0  # Opzionale per AI validation
```

### 2. Database Migration
```bash
python migrate_backup_tables.py --seed-templates
```

### 3. Environment Config
Aggiungi al `.env`:
```env
BACKUP_PATH=./backups
ANTHROPIC_API_KEY=sk-ant-...  # Opzionale
```

### 4. Register Router
In `app/main_dual.py`, aggiungi:
```python
from app.routers import device_backup
app.include_router(device_backup.router, prefix="/api/v1")

# Per backup schedulati:
from app.services.backup_scheduler import start_backup_scheduler
@app.on_event("startup")
async def startup():
    start_backup_scheduler()
```

### 5. Restart & Test
```bash
python -m app.run_dual
# Verifica: http://localhost:8000/docs
```

---

## 📡 Quick API Examples

### Backup Singolo Device
```bash
curl -X POST "http://localhost:8000/api/v1/device-backup/device" \
  -H "Content-Type: application/json" \
  -d '{
    "device_ip": "192.168.1.10",
    "customer_id": "cust001",
    "device_type": "hp_aruba",
    "backup_type": "config"
  }'
```

### Backup Tutti Device Cliente
```bash
curl -X POST "http://localhost:8000/api/v1/device-backup/customer" \
  -d '{"customer_id": "cust001", "backup_type": "config"}'
```

### Schedule Automatico
```bash
curl -X POST "http://localhost:8000/api/v1/device-backup/schedule" \
  -d '{
    "customer_id": "cust001",
    "schedule_type": "daily",
    "schedule_time": "03:00",
    "retention_days": 30
  }'
```

### Storico Backup
```bash
curl "http://localhost:8000/api/v1/device-backup/history/customer/cust001?days=30"
```

---

## 🎨 UI Integration Example

### Pulsante Backup Device

```html
<button onclick="backupDevice('device_id')">
  <i class="fas fa-save"></i> Backup
</button>

<script>
async function backupDevice(deviceId) {
  const response = await fetch('/api/v1/device-backup/device', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      device_assignment_id: deviceId,
      backup_type: 'config'
    })
  });
  const result = await response.json();
  alert(result.success ? 'Backup OK!' : 'Error: ' + result.error);
}
</script>
```

---

## 📁 Files Created (NO modifications to existing code)

```
dadude/
├── app/
│   ├── models/
│   │   └── backup_models.py              ← NEW
│   ├── services/
│   │   ├── hp_aruba_collector.py         ← NEW
│   │   ├── mikrotik_backup_collector.py  ← NEW
│   │   ├── device_backup_service.py      ← NEW
│   │   ├── command_execution_service.py  ← NEW
│   │   ├── ai_command_validator.py       ← NEW
│   │   └── backup_scheduler.py           ← NEW
│   └── routers/
│       └── device_backup.py               ← NEW
│
├── backups/                               ← NEW (auto-created)
├── migrate_backup_tables.py              ← NEW
├── DEVICE_BACKUP_MODULE.md               ← NEW (full docs)
├── INTEGRATION_GUIDE.md                  ← NEW (step-by-step)
└── BACKUP_MODULE_README.md               ← NEW (this file)
```

---

## 🗄️ Database Tables Created

- `device_backups` - Storico backup con metadata
- `backup_schedules` - Schedule automatici per cliente
- `backup_jobs` - Job batch in esecuzione
- `backup_templates` - Template vendor-specific

---

## 🤖 AI Validation (Optional)

Valida comandi prima dell'esecuzione:

```python
from app.services.ai_command_validator import AICommandValidator

validator = AICommandValidator()
result = validator.validate_commands(
    commands=["configure terminal", "vlan 100", "name TEST"],
    device_type="hp_aruba"
)

print(f"Valid: {result['valid']}")
print(f"Risk: {result['risk_level']}")
print(f"Errors: {result['errors']}")
```

Requires: `ANTHROPIC_API_KEY` in `.env`

---

## 📚 Documentation

- **Full Module Docs**: `DEVICE_BACKUP_MODULE.md`
- **Integration Guide**: `INTEGRATION_GUIDE.md`
- **API Reference**: `/docs` (Swagger UI)

---

## ✅ Features Overview

| Feature | HP/Aruba | MikroTik | Status |
|---------|----------|----------|--------|
| Config Backup | ✅ | ✅ | Ready |
| Binary Backup | - | ✅ | Ready |
| Auto Schedule | ✅ | ✅ | Ready |
| Command Exec | ✅ | ✅ | Ready |
| AI Validation | ✅ | ✅ | Optional |
| Pre-change Backup | ✅ | ✅ | Ready |
| Download History | ✅ | ✅ | Ready |
| Retention Policy | ✅ | ✅ | Ready |

---

## 🔒 Security

- Usa `EncryptionService` esistente per password
- Backup files con permessi restrittivi
- Audit trail completo in database
- AI validation: no credenziali inviate

---

## 🐛 Troubleshooting

**Backup fails?**
- Check credenziali SSH in database
- Verifica connettività rete
- Check logs: `./logs/`

**Scheduler not running?**
- Verifica `start_backup_scheduler()` in `main_dual.py`
- Check schedule `enabled=true`

**AI validation disabled?**
- Install: `pip install anthropic`
- Configure: `ANTHROPIC_API_KEY` in `.env`

---

## 🔮 Roadmap

- [ ] Diff tra backup
- [ ] Email notifications
- [ ] Cisco IOS support
- [ ] Config comparison tool
- [ ] Auto-rollback on errors

---

## 📞 Support

- **Full Docs**: `DEVICE_BACKUP_MODULE.md`
- **Integration**: `INTEGRATION_GUIDE.md`
- **Issues**: Check logs in `./logs/`

---

**Created for**: Domarc Srl
**Version**: 1.0.0
**Date**: Gennaio 2025
