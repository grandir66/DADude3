# Device Backup & Configuration Management Module

**Modulo parallelo per DaDude** - Backup automatico e gestione configurazioni dispositivi di rete

## 📋 Panoramica

Questo modulo estende DaDude con funzionalità avanzate di:
- **Backup automatico** configurazioni switch HP/Aruba e router MikroTik
- **Scheduling** backup periodici per cliente
- **Invio comandi** di configurazione con validazione
- **Validazione AI** comandi usando Claude (opzionale)
- **Storico backup** con retention policy
- **Rollback** automatico pre-change

### ✨ Caratteristiche Principali

- 🔄 **Backup automatici schedulati** - Configurabili per cliente
- 🔒 **Pre-change backup** - Backup automatico prima di modifiche
- 🤖 **Validazione AI** - Claude analizza comandi per errori e rischi
- 📊 **Storico completo** - Tracciamento tutti i backup con metadata
- 🗂️ **Storage strutturato** - Organizzazione gerarchica per cliente/device
- ⚡ **API REST** - Integrazione semplice con UI o altri sistemi
- 🔐 **Credenziali sicure** - Usa encryption service esistente

---

## 🏗️ Architettura

### Struttura File (SOLO NUOVI FILE - NON MODIFICA ESISTENTI)

```
dadude/
├── app/
│   ├── models/
│   │   └── backup_models.py              ← NUOVO
│   │
│   ├── services/
│   │   ├── hp_aruba_collector.py         ← NUOVO
│   │   ├── mikrotik_backup_collector.py  ← NUOVO
│   │   ├── device_backup_service.py      ← NUOVO
│   │   ├── command_execution_service.py  ← NUOVO
│   │   ├── ai_command_validator.py       ← NUOVO
│   │   └── backup_scheduler.py           ← NUOVO
│   │
│   └── routers/
│       └── device_backup.py               ← NUOVO
│
├── backups/                               ← NUOVO (storage)
│   ├── hp_aruba/
│   │   └── {customer_code}/
│   │       └── {device_name}/
│   │           └── {timestamp}.cfg
│   └── mikrotik/
│       └── {customer_code}/
│           └── {device_name}/
│               ├── {timestamp}.rsc
│               └── {timestamp}.backup
│
├── migrate_backup_tables.py              ← NUOVO
└── DEVICE_BACKUP_MODULE.md               ← NUOVO (questo file)
```

### Database Models (Nuove Tabelle)

**`device_backups`** - Storico backup
- Traccia ogni backup eseguito
- Metadata device (model, firmware, serial)
- Path file, checksum, dimensione
- Risultato esecuzione (success/error)

**`backup_schedules`** - Schedule automatici
- Configurazione per cliente
- Tipo schedule (daily/weekly/monthly/custom)
- Retention policy
- Statistiche esecuzione

**`backup_jobs`** - Job batch in esecuzione
- Traccia backup multipli (es: tutti device cliente)
- Progress tracking
- Risultati dettagliati

**`backup_templates`** - Template configurazione
- Comandi specifici per vendor/modello
- Parsing rules
- Template predefiniti (HP/Aruba, MikroTik)

---

## 🚀 Installazione

### 1. Dipendenze

Aggiungi al `requirements.txt` esistente:

```bash
paramiko>=3.4.0          # SSH (già presente)
apscheduler>=3.10.0      # Scheduler
anthropic>=0.18.0        # Claude AI (opzionale)
```

Installa:
```bash
pip install -r requirements.txt
```

### 2. Migrazione Database

Esegui migration per creare tabelle backup:

```bash
python migrate_backup_tables.py --seed-templates
```

Flags:
- `--force` - Ricrea tabelle (cancella dati esistenti!)
- `--seed-templates` - Crea template predefiniti HP/Aruba e MikroTik

### 3. Configurazione

Aggiungi al `.env`:

```env
# Backup Module
BACKUP_PATH=./backups
COMMANDS_LOG_PATH=./logs/commands

# AI Validation (opzionale)
ANTHROPIC_API_KEY=sk-ant-...
```

### 4. Registra Router API

Modifica `app/main_dual.py` per includere router backup:

```python
from app.routers import device_backup

# Aggiungi dopo router esistenti
app.include_router(device_backup.router, prefix="/api/v1")
```

### 5. Avvia Scheduler (Opzionale)

Aggiungi a `app/main_dual.py` per backup automatici:

```python
from app.services.backup_scheduler import start_backup_scheduler, stop_backup_scheduler

@app.on_event("startup")
async def startup_event():
    # ... codice esistente ...
    start_backup_scheduler()

@app.on_event("shutdown")
async def shutdown_event():
    # ... codice esistente ...
    stop_backup_scheduler()
```

---

## 📡 API Endpoints

### Backup Manuale

**Backup Singolo Device**
```http
POST /api/v1/device-backup/device
Content-Type: application/json

{
  "device_assignment_id": "abc123",
  "backup_type": "config"
}
```

Oppure per device non assegnato:
```json
{
  "device_ip": "192.168.1.10",
  "customer_id": "cust001",
  "device_type": "hp_aruba",
  "backup_type": "config"
}
```

**Backup Tutti Device Cliente**
```http
POST /api/v1/device-backup/customer
Content-Type: application/json

{
  "customer_id": "cust001",
  "backup_type": "config",
  "device_type_filter": ["hp_aruba", "mikrotik"]
}
```

### Storico Backup

**Device History**
```http
GET /api/v1/device-backup/history/device/{device_assignment_id}?limit=50
```

**Customer History**
```http
GET /api/v1/device-backup/history/customer/{customer_id}?days=30
```

**Download Backup**
```http
GET /api/v1/device-backup/download/{backup_id}
```

### Scheduling

**Crea/Aggiorna Schedule**
```http
POST /api/v1/device-backup/schedule
Content-Type: application/json

{
  "customer_id": "cust001",
  "enabled": true,
  "schedule_type": "daily",
  "schedule_time": "03:00",
  "backup_types": ["config"],
  "retention_days": 30
}
```

**Get Schedule**
```http
GET /api/v1/device-backup/schedule/{customer_id}
```

**Delete Schedule**
```http
DELETE /api/v1/device-backup/schedule/{customer_id}
```

### Job Status

**Get Job Progress**
```http
GET /api/v1/device-backup/job/{job_id}
```

Response:
```json
{
  "job_id": "job123",
  "status": "running",
  "progress_percent": 75,
  "devices_total": 10,
  "devices_success": 7,
  "devices_failed": 1
}
```

### Maintenance

**Cleanup Old Backups**
```http
POST /api/v1/device-backup/cleanup/{customer_id}?retention_days=30
```

---

## 💻 Usage Examples

### Python Client

```python
import requests

API = "http://localhost:8000/api/v1/device-backup"

# Backup singolo device
response = requests.post(f"{API}/device", json={
    "device_assignment_id": "dev123",
    "backup_type": "config"
})

result = response.json()
print(f"Backup: {result['success']}")
print(f"File: {result['file_path']}")

# Schedule automatico
requests.post(f"{API}/schedule", json={
    "customer_id": "cust001",
    "enabled": True,
    "schedule_type": "daily",
    "schedule_time": "03:00",
    "retention_days": 30
})

# Storico backups
history = requests.get(f"{API}/history/customer/cust001?days=7").json()
for backup in history['backups']:
    print(f"{backup['device_hostname']}: {backup['created_at']}")
```

### Uso Diretto Servizi

```python
from app.models.database import get_db
from app.services.device_backup_service import DeviceBackupService

db = next(get_db())
service = DeviceBackupService(db=db)

# Backup device
result = service.backup_device_by_ip(
    device_ip="192.168.1.10",
    customer_id="cust001",
    device_type="hp_aruba",
    backup_type="config"
)

print(f"Success: {result['success']}")
print(f"Config size: {len(result['config'])} bytes")
```

---

## 🤖 AI Validation (Opzionale)

### Setup

1. Ottieni API key Anthropic: https://console.anthropic.com
2. Configura in `.env`:
   ```env
   ANTHROPIC_API_KEY=sk-ant-...
   ```

### Usage

```python
from app.services.ai_command_validator import AICommandValidator

validator = AICommandValidator()

# Valida comandi
commands = [
    "configure terminal",
    "vlan 100",
    "name VLAN_UFFICI",
    "exit"
]

result = validator.validate_commands(
    commands=commands,
    device_type="hp_aruba",
    context="Configurazione VLAN uffici"
)

if result['valid']:
    print("✓ Comandi validi")
else:
    print(f"✗ Errori: {result['errors']}")

print(f"Risk level: {result['risk_level']}")
print(f"Warnings: {result['warnings']}")
print(f"Suggestions: {result['suggestions']}")
```

### Spiega Comando

```python
explanation = validator.explain_command(
    command="no spanning-tree",
    device_type="hp_aruba"
)

print(explanation['explanation'])
print(f"Reversible: {explanation['reversible']}")
```

---

## 🔧 Command Execution

### Invio Comandi da File

Crea file `commands.txt`:
```
configure terminal
vlan 100
name VLAN_UFFICI
tagged 1-24
exit
write memory
```

Esegui:
```python
from app.services.command_execution_service import CommandExecutionService

executor = CommandExecutionService()

result = executor.execute_commands_from_file(
    device_ip="192.168.1.10",
    device_type="hp_aruba",
    credentials={"username": "admin", "password": "pass"},
    commands_file="commands.txt",
    backup_before=True,  # Backup automatico
    validate_before=True  # Validazione AI
)

print(f"Executed: {result['commands_executed']}")
print(f"Success: {result['commands_success']}")
print(f"Failed: {result['commands_failed']}")
```

### Invio Comandi Inline

```python
commands = [
    "configure terminal",
    "interface 1-10",
    "enable",
    "exit",
    "write memory"
]

result = executor.execute_commands_on_device(
    device_ip="192.168.1.10",
    device_type="hp_aruba",
    credentials=credentials,
    commands=commands,
    backup_before=True
)
```

---

## 📊 Scheduler Details

### Schedule Types

**Daily**
```json
{
  "schedule_type": "daily",
  "schedule_time": "03:00"
}
```
Esegue ogni giorno alle 03:00

**Weekly**
```json
{
  "schedule_type": "weekly",
  "schedule_time": "03:00",
  "schedule_days": [0, 2, 4]  // Lunedì, Mercoledì, Venerdì
}
```

**Monthly**
```json
{
  "schedule_type": "monthly",
  "schedule_time": "03:00",
  "schedule_day_of_month": 1  // Primo del mese
}
```

**Custom Cron**
```json
{
  "schedule_type": "custom",
  "cron_expression": "0 3 * * 0"  // Domenica alle 03:00
}
```

### Retention Policy

```json
{
  "retention_days": 30,        // Cancella backup > 30 giorni
  "retention_count": 100,      // Mantieni max 100 backup
  "retention_strategy": "both" // Applica entrambi i criteri
}
```

---

## 🔐 Security

- **Credenziali**: Usa `EncryptionService` esistente per password
- **Backup Files**: Archiviati con permessi restrittivi
- **AI Validation**: Non invia credenziali o IP sensibili
- **Audit Trail**: Tutti i backup tracciati in DB con timestamp e utente

---

## 🐛 Troubleshooting

### Backup Fails

**Error: "No valid credentials found"**
- Verifica credenziali SSH nel database
- Check `Credential` table per cliente
- Usa credenziali globali se necessario

**Error: "Connection timeout"**
- Verifica connettività di rete
- Check firewall rules porta 22
- Aumenta timeout in config

### Scheduler Not Running

- Verifica `start_backup_scheduler()` chiamato in `main_dual.py`
- Check logs per errori scheduler
- Verifica schedule `enabled=true`

### AI Validation Disabled

- Installa `anthropic` package
- Configura `ANTHROPIC_API_KEY`
- Verifica quota API Anthropic

---

## 📈 Performance

- **Backup Speed**: ~10-30 sec per device (dipende da config size)
- **Concurrent Backups**: Gestiti da job queue
- **Storage**: ~10-50 KB per backup config testuale
- **Binary Backups MikroTik**: ~100-500 KB

---

## 🔮 Future Enhancements

- [ ] Diff configurazioni tra backup
- [ ] Notifiche email/webhook su errori
- [ ] Export backup formato Git
- [ ] Comparison tool configurazioni
- [ ] Rollback automatico su errori
- [ ] Support Cisco IOS
- [ ] Dashboard statistiche backup

---

## 📝 License

Uso interno - Domarc Srl

---

## 🤝 Support

Per supporto: [Domarc Srl](https://www.domarc.it)
